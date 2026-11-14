# Advisory LFM-2026-ADV-01 — Subida arbitraria de archivos y RCE en `alexusmai/laravel-file-manager` con configuración predeterminada

| Campo | Valor |
|---|---|
| ID interno | LFM-2026-ADV-01 |
| Producto | `alexusmai/laravel-file-manager` (Composer) |
| Versión reproducida | 3.3.3 (última publicada; el comportamiento existe desde 1.x) |
| CVE | Ninguno asignado a esta variante concreta. Relacionado: CVE-2025-56399 (variante autenticada) |
| CWE | CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-1188 (Insecure Default Initialization) |
| Severidad | Crítica en el despliegue predeterminado documentado |
| CVSS 3.1 | 9.8 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (condicionado a los requisitos de entorno) |
| Estado | Reproducido en laboratorio aislado. No se ha contactado ningún sistema de terceros. |
| Fecha | 2026-11-14 |

## 1. Resumen

La configuración publicada del paquete deja el gestor de archivos accesible sin autenticación (`middleware => ['web']`), sin restricción de extensiones (`allowFileTypes => []`) y con ACL desactivada (`acl => false`). El disco predeterminado es `public`, que en un despliegue Laravel estándar se expone mediante `php artisan storage:link`.

Como consecuencia, un atacante no autenticado puede obtener un token CSRF de la propia sesión, subir un archivo `.php` con el nombre que elija y solicitar `/storage/<archivo>.php`, que el servidor web ejecuta. El resultado es ejecución remota de comandos con los privilegios del usuario del servidor web.

La explotación depende de la configuración de la aplicación, no solo de la versión: si el integrador añade middleware `auth`, habilita ACL, restringe `allowFileTypes`, usa un disco privado o desactiva la ejecución de PHP en el almacenamiento, la cadena no se completa. Esos controles son responsabilidad del integrador, pero los valores publicados por el paquete son inseguros para un despliegue por defecto.

## 2. Causa raíz

1. **Rutas sin autenticación.** `config/file-manager.php` publica `'middleware' => ['web']`. El grupo `web` de Laravel aporta sesión y CSRF, pero no autenticación. `src/routes.php` aplica ese grupo a `GET initialize` y `POST upload` entre otras rutas.
2. **Sin lista de extensiones.** `config/file-manager.php` publica `'allowFileTypes' => []`, documentado como «sin restricciones». `FileManager::upload()` solo comprueba la extensión si la lista no está vacía.
3. **Nombre original conservado.** `FileManager::upload()` usa `getClientOriginalName()` y lo pasa a `putFileAs()`, por lo que un nombre `x.php` se guarda como `x.php`.
4. **Renombrado sin revalidación.** `FileManager::rename()` mueve el archivo sin comprobar la nueva extensión, lo que permite la variante subir como imagen y renombrar a `.php`.
5. **Almacenamiento público.** El disco predeterminado es `public` (`storage/app/public`) y la documentación de Laravel indica enlazarlo con `storage:link`; Apache/nginx con el handler de PHP ejecuta los `.php` bajo esa ruta.

Referencias de código (copia local en `package-review/`, commit `74bebe32`):

- `config/file-manager.php:85` — `allowFileTypes => []`
- `config/file-manager.php:98` — `middleware => ['web']`
- `config/file-manager.php:105` — `acl => false`
- `src/routes.php:25,37` — `initialize` y `upload`
- `src/FileManager.php:159-185` — comprobación opcional y `putFileAs` con nombre original
- `src/FileManager.php:274-277` — `rename` sin validación

## 3. Requisitos para la explotación

- Instancia alcanzable con el paquete instalado y rutas registradas.
- Configuración sin `auth` (u otro control de acceso) en el grupo de middleware del paquete, o una aplicación que no aplique autenticación global.
- `allowFileTypes` vacío (predeterminado) o que permita una extensión ejecutable; alternativamente, `rename` accesible.
- Disco accesible por URL (`storage:link`) y servidor que ejecute PHP en esa ubicación.
- El atacante puede obtener un token CSRF de la sesión; el propio `GET /file-manager/initialize` emite la cookie `XSRF-TOKEN`, por lo que el CSRF no impide la cadena sin autenticación.

## 4. Reproducción en laboratorio

Laboratorio: `lab/` (Docker, PHP 8.3 + Apache + Laravel 12 + paquete 3.3.3, configuración publicada sin cambios, `storage:link`).

```bash
cd lab && docker compose build && docker compose up -d
python3 poc/lfm_upload_rce_poc.py --base-url http://127.0.0.1:18080 --cmd 'id; whoami; hostname'
```

Resultado observado (`evidence/poc-run.txt`):

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

Evidencia adicional (`evidence/lab-verify.txt`): enlace `public/storage -> /app/storage/app/public`, archivo almacenado propiedad de `www-data`, respuesta `X-Powered-By: PHP/8.3.36` y cuerpo con la salida del comando. Los registros de Apache muestran `GET /file-manager/initialize`, `POST /file-manager/upload` y `GET /storage/<archivo>.php`.

## 5. Impacto

- Ejecución de comandos arbitrarios como el usuario del servidor web.
- Lectura y escritura de archivos accesibles a ese usuario, incluida configuración y secretos (`APP_KEY`, credenciales de base de datos).
- Persistencia mediante webshell, tareas o movimiento lateral según el entorno.
- Posible compromiso total del host y de sistemas conectados.

## 6. Detección

- `POST` a `/<prefijo>/upload` sin sesión autenticada, especialmente con `files[]` y nombres `.php`.
- Aparición de archivos `.php` en `storage/app/public` o en cualquier disco servido por web.
- Peticiones `GET` a `/storage/*.php` con parámetros de comando.
- Uso de `POST /<prefijo>/rename` seguido de acceso a `.php`.
- Respuestas `GET /<prefijo>/initialize` con `"acl":false` desde direcciones no administrativas.
- En logs de aplicación: eventos `FilesUploading`/`FilesUploaded` del paquete con nombres sospechosos.

## 7. Remediación

**Inmediata**

1. Añadir autenticación y autorización al grupo del paquete: `'middleware' => ['web','auth','admin']` o equivalente, y verificar con `php artisan route:list -v`.
2. Restringir extensiones: `allowFileTypes => ['jpg','jpeg','png','gif','pdf']`, y validar también en el servidor con reglas `mimes`/`extensions`.
3. Activar ACL (`acl => true`) con estrategia `whitelist` cuando aplique.
4. Mover las subidas a un disco privado (`storage/app/private`) y servirlas mediante controlador autorizado.
5. Impedir la ejecución de PHP en el almacenamiento:

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

6. Buscar y eliminar archivos `.php` no previstos en `storage/app/public` y en el directorio público; rotar `APP_KEY` y credenciales si hay indicios de compromiso.

**Estructural**

- No publicar el gestor sin middleware de autenticación; considerar el paquete solo para administración.
- Validar tipo real (magic bytes), generar nombres aleatorios y no permitir renombrar a extensiones ejecutables.
- Servir archivos subidos desde un dominio/host separado sin ejecución de scripts.
- Añadir reglas WAF para `POST` a `*/file-manager/upload` y para acceso a `*.php` bajo `/storage/`.

## 8. Cronología

- 2020-07-11/19 — Issues públicas #185 y #187 documentan el cambio de extensión y el riesgo del middleware `web`.
- 2025-10-28 — CVE-2025-56399 (variante autenticada de subida/renombrado).
- 2026-05-12 — Publicación de 3.3.3 con los mismos valores predeterminados.
- 2026-11-14 — Reproducción local no autenticada, PoC y este advisory.

## 9. Referencias

- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/config/file-manager.php
- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/src/routes.php
- https://github.com/alexusmai/laravel-file-manager/blob/3.3.3/src/FileManager.php
- https://github.com/alexusmai/laravel-file-manager/issues/185
- https://github.com/alexusmai/laravel-file-manager/issues/187
- https://nvd.nist.gov/vuln/detail/CVE-2025-56399
- https://laravel.com/docs/12.x/filesystem#the-public-disk
- https://laravel.com/docs/12.x/middleware#laravels-default-middleware-groups

## 10. Limitaciones y descargo

- Este documento describe una reproducción en un laboratorio local. No se ha interactuado con los dominios que aparecen en el vídeo.
- No se ha asignado CVE a esta variante. La puntuación CVSS asume el despliegue predeterminado descrito; en configuraciones con autenticación o disco privado el impacto y la puntuación bajan (por ejemplo, 8.8 con privilegios bajos para la variante autenticada de CVE-2025-56399).
- El fabricante considera que la seguridad del despliegue corresponde al integrador (respuesta en la issue #187). Este advisory no contradice esa postura: documenta que los valores publicados conducen a un despliegue inseguro si no se modifican.

## 11. Controles negativos verificados

En el mismo laboratorio, y restaurando la configuración después de cada prueba:

| Cambio | Resultado |
|---|---|
| `'middleware' => ['web','auth']` | `GET /file-manager/initialize` deja de responder 200 (HTTP 500 en el laboratorio por no existir ruta `login`; en una aplicación real redirige al login) |
| `'allowFileTypes' => ['jpg','jpeg','png','gif']` | `POST /file-manager/upload` responde `{"status":"warning","message":"notAllUploaded"}` y no se guarda el `.php`; la PoC termina sin ejecución |

Evidencia: `evidence/negative-controls.txt`.
