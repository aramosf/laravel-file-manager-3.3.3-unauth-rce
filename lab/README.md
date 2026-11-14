# Local lab — alexusmai/laravel-file-manager 3.3.3

Isolated environment to reproduce the arbitrary PHP upload and execution described
in `../advisory/LFM-2026-ADV-01-arbitrary-upload-rce.md`.

- Laravel 12 + PHP 8.3 + Apache.
- Package installed at the exact version 3.3.3.
- Published configuration unchanged: `middleware => ['web']`, `allowFileTypes => []`,
  `acl => false`, `public` disk.
- `php artisan storage:link` executed.
- Published only on `127.0.0.1:18080` so it is never exposed to the network.

Usage:

```bash
docker compose build
docker compose up -d
python3 ../poc/lfm_upload_rce_poc.py --base-url http://127.0.0.1:18080 --cmd 'id; whoami'
docker compose down
```

The container must not be exposed beyond loopback. Do not use this lab against
third-party systems.
