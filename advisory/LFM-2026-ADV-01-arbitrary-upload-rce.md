# Advisory LFM-2026-ADV-01 — Arbitrary file upload and RCE in `alexusmai/laravel-file-manager` with the default configuration

| Field | Value |
|---|---|
| Internal ID | LFM-2026-ADV-01 |
| Product | `alexusmai/laravel-file-manager` (Composer) |
| Reproduced version | 3.3.3 (latest published; the behavior has existed since 1.x) |
| CVE | None assigned to this specific variant. Related: CVE-2025-56399 (authenticated variant) |
| CWE | CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-1188 (Insecure Default Initialization) |
| Severity | Critical in the documented default deployment |
| CVSS 3.1 | 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (conditioned on the environment requirements) |
| Status | Reproduced in an isolated lab. No third-party system was contacted. |
| Date | 2026-11-14 |

## 1. Summary

The package's published configuration leaves the file manager reachable without
authentication (`middleware => ['web']`), without extension restrictions
(`allowFileTypes => []`) and with ACL disabled (`acl => false`). The default disk is
`public`, which in a standard Laravel deployment is exposed via
`php artisan storage:link`.

As a result, an unauthenticated attacker can obtain a CSRF token from the session
itself, upload a `.php` file with an arbitrary name and request
`/storage/<file>.php`, which the web server executes. The outcome is remote command
execution with the privileges of the web-server user.

Exploitation depends on the application configuration, not only on the version: if
the integrator adds `auth` middleware, enables ACL, restricts `allowFileTypes`, uses
a private disk or disables PHP execution in storage, the chain does not complete.
Those controls are the integrator's responsibility, but the values published by the
package are insecure for a default deployment.

## 2. Root cause

1. **Routes without authentication.** `config/file-manager.php` ships
   `'middleware' => ['web']`. Laravel's `web` group provides session and CSRF, but
   not authentication. `src/routes.php` applies that group to `GET initialize` and
   `POST upload`, among others.
2. **No extension list.** `config/file-manager.php` ships `'allowFileTypes' => []`,
   documented as "no restrictions". `FileManager::upload()` only checks the
   extension when the list is non-empty.
3. **Original filename preserved.** `FileManager::upload()` uses
   `getClientOriginalName()` and passes it to `putFileAs()`, so a name `x.php` is
   stored as `x.php`.
4. **Rename without re-validation.** `FileManager::rename()` moves the file without
   checking the new extension, enabling the "upload as image and rename to `.php`"
   variant.
5. **Public storage.** The default disk is `public` (`storage/app/public`) and
   Laravel's documentation says to link it with `storage:link`; Apache/nginx with
   the PHP handler executes the `.php` files under that path.

Code references (local copy in `../package-review` of the research tree, commit
`74bebe32`):

- `config/file-manager.php:85` — `allowFileTypes => []`
- `config/file-manager.php:98` — `middleware => ['web']`
- `config/file-manager.php:105` — `acl => false`
- `src/routes.php:25,37` — `initialize` and `upload`
- `src/FileManager.php:159-185` — optional check and `putFileAs` with original name
- `src/FileManager.php:274-277` — `rename` without validation

## 3. Exploitation requirements

- A reachable instance with the package installed and routes registered.
- A configuration without `auth` (or other access control) on the package middleware
  group, or an application that does not enforce global authentication.
- `allowFileTypes` empty (default) or permitting an executable extension;
  alternatively, a reachable `rename`.
- A URL-reachable disk (`storage:link`) on a server that executes PHP at that
  location.
- The attacker can obtain a CSRF token from the session; `GET /file-manager/initialize`
  itself issues the `XSRF-TOKEN` cookie, so CSRF does not prevent the
  unauthenticated chain.

## 4. Lab reproduction

Lab: `lab/` (Docker, PHP 8.3 + Apache + Laravel 12 + package 3.3.3, published
configuration unchanged, `storage:link`).

```bash
cd lab && docker compose build && docker compose up -d
python3 poc/lfm_upload_rce_poc.py --base-url http://127.0.0.1:18080 --cmd 'id; whoami; hostname'
```

Observed result:

```
[+] initialize OK : acl=False disks=['public']
[*] upload        : HTTP 200 {"result":{"status":"success","message":"uploaded"}}
[*] execute       : GET /storage/lfm_poc_763b67e0.php -> HTTP 200
[+] RCE CONFIRMED
[+] command output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
fef3d04c4a7f
```

Additional evidence: the link `public/storage -> /app/storage/app/public`, the
stored file owned by `www-data`, response header `X-Powered-By: PHP/8.3.36` and a
body containing the command output. The Apache logs show
`GET /file-manager/initialize`, `POST /file-manager/upload` and
`GET /storage/<file>.php`.

## 5. Impact

- Execution of arbitrary commands as the web-server user.
- Read and write access to files reachable by that user, including configuration and
  secrets (`APP_KEY`, database credentials).
- Persistence via web shell, scheduled tasks or lateral movement depending on the
  environment.
- Possible full compromise of the host and connected systems.

## 6. Detection

- `POST` to `/<prefix>/upload` without an authenticated session, especially with
  `files[]` and `.php` names.
- Appearance of `.php` files in `storage/app/public` or any web-served disk.
- `GET` requests to `/storage/*.php` with command parameters.
- Use of `POST /<prefix>/rename` followed by access to a `.php`.
- `GET /<prefix>/initialize` responses with `"acl":false` from non-administrative
  addresses.
- In application logs: the package's `FilesUploading`/`FilesUploaded` events with
  suspicious names.

## 7. Remediation

**Immediate**

1. Add authentication and authorization to the package group:
   `'middleware' => ['web','auth','admin']` or equivalent, and verify with
   `php artisan route:list -v`.
2. Restrict extensions: `allowFileTypes => ['jpg','jpeg','png','gif','pdf']`, and
   validate server-side with `mimes`/`extensions` rules.
3. Enable ACL (`acl => true`) with a whitelist strategy where applicable.
4. Move uploads to a private disk (`storage/app/private`) and serve them through an
   authorized controller.
5. Prevent PHP execution in storage:

```apache
<Directory /var/www/html/public/storage>
    php_admin_flag engine off
    <FilesMatch "\.(php|phtml|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

```nginx
location ^~ /storage/ {
    location ~ \.php$ { return 403; }
}
```

6. Find and remove unexpected `.php` files in `storage/app/public` and the public
   directory; rotate `APP_KEY` and credentials if there are signs of compromise.

**Structural**

- Do not publish the file manager without authentication middleware; consider the
  package for administrative use only.
- Validate the real type (magic bytes), generate random names and do not allow
  renaming to executable extensions.
- Serve uploaded files from a separate domain/host without script execution.
- Add WAF rules for `POST` to `*/file-manager/upload` and for access to `*.php`
  under `/storage/`.

## 8. Timeline

- 2020-07-11/19 — Public issues #185 and #187 document the extension change and the
  `web`-middleware risk.
- 2025-10-28 — CVE-2025-56399 (authenticated upload/rename variant).
- 2026-05-12 — Release 3.3.3 ships the same defaults.
- 2026-11-14 — Local unauthenticated reproduction, PoC and this advisory.

## 9. References

- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/config/file-manager.php
- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/src/routes.php
- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/src/FileManager.php
- https://github.com/alexusmai/laravel-file-manager/issues/185
- https://github.com/alexusmai/laravel-file-manager/issues/187
- https://nvd.nist.gov/vuln/detail/CVE-2025-56399
- https://laravel.com/docs/12.x/filesystem#the-public-disk
- https://laravel.com/docs/12.x/middleware#laravels-default-middleware-groups

## 10. Limitations and disclaimer

- This document describes a reproduction in a local lab. No interaction took place
  with the domains seen in the source video.
- No CVE is assigned to this variant. The CVSS score assumes the default deployment
  described; in configurations with authentication or a private disk the impact and
  the score drop (for example 8.8 with low privileges for the authenticated
  CVE-2025-56399 variant).
- The vendor considers deployment security the integrator's responsibility (response
  in issue #187). This advisory does not contradict that position: it documents that
  the published values lead to an insecure deployment if they are not changed.

## 11. Verified negative controls

In the same lab, restoring the configuration after each test:

| Change | Result |
|---|---|
| `'middleware' => ['web','auth']` | `GET /file-manager/initialize` stops returning 200 (HTTP 500 in the lab because there is no `login` route; in a real app it redirects to login) |
| `'allowFileTypes' => ['jpg','jpeg','png','gif']` | `POST /file-manager/upload` returns `{"status":"warning","message":"notAllUploaded"}` and the `.php` is not stored; the PoC ends without execution |
