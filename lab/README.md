# Laboratorio local — alexusmai/laravel-file-manager 3.3.3

Entorno aislado para reproducir la subida arbitraria de PHP y la ejecución descritas
en `advisory/LFM-2026-ADV-01-arbitrary-upload-rce.md`.

- Laravel 12 + PHP 8.3 + Apache.
- Paquete instalado en la versión exacta 3.3.3.
- Configuración publicada sin cambios: `middleware => ['web']`, `allowFileTypes => []`,
  `acl => false`, disco `public`.
- `php artisan storage:link` ejecutado.
- Publicado solo en `127.0.0.1:18080` para no exponerlo a la red.

Uso:

```bash
docker compose build
docker compose up -d
python3 ../poc/lfm_upload_rce_poc.py --base-url http://127.0.0.1:18080 --cmd 'id; whoami'
docker compose down
```

El contenedor no debe exponerse fuera de loopback. No usar este laboratorio contra
sistemas de terceros.
