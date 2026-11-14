# laravel-file-manager 3.3.3 — configuración por defecto insegura (CWE-434 / CWE-1188)

Advisory, prueba de concepto de laboratorio y material de detección/remediación para
el paquete Composer `alexusmai/laravel-file-manager` cuando se despliega con la
configuración que publica el propio paquete.

> Todo el trabajo de este repositorio es **pasivo** (análisis) o contra un
> **laboratorio Docker local y aislado** (`127.0.0.1:18080`). No se ha interactuado
> con ningún sistema de terceros. Material destinado a defensa, detección y
> divulgación responsable.

- **ID interno:** LFM-2026-ADV-01
- **Producto:** `alexusmai/laravel-file-manager` 3.3.3 (comportamiento presente desde 1.x)
- **CVE:** sin asignar a esta variante no autenticada. Relacionado: CVE-2025-56399 (variante autenticada).
- **CWE:** CWE-434 (subida sin restricción de tipo), CWE-1188 (inicialización insegura por defecto).
- **Severidad:** crítica en el despliegue predeterminado documentado.

## Resumen

La configuración publicada del paquete deja el gestor de archivos accesible sin
autenticación (`middleware => ['web']`), sin restricción de extensiones
(`allowFileTypes => []`) y con ACL desactivada (`acl => false`), sobre el disco
`public`. En un despliegue Laravel estándar con `php artisan storage:link` y un
servidor que ejecuta PHP bajo `/storage`, esos valores encadenan una subida
arbitraria que termina en ejecución de comandos como el usuario del servidor web.

La explotación **depende de la configuración, no solo de la versión**: añadir
middleware `auth`, habilitar ACL, restringir `allowFileTypes`, usar un disco privado
o impedir la ejecución de PHP en el almacenamiento rompe la cadena. Esos controles
son responsabilidad del integrador, pero los valores que publica el paquete son
inseguros por defecto.

El análisis completo (causa raíz con referencias de código, requisitos, impacto,
cronología y controles negativos) está en
[`advisory/LFM-2026-ADV-01-arbitrary-upload-rce.md`](advisory/LFM-2026-ADV-01-arbitrary-upload-rce.md).

## Demostración (laboratorio local)

![Demostración de la PoC contra el laboratorio local](demo/lfm-rce-demo.gif)

Grabación real de la PoC contra el laboratorio `lab/` en `127.0.0.1:18080`:
reconocimiento de `GET /file-manager/initialize` (`acl=false`, disco `public`),
ejecución de la PoC y salida de `id; whoami; hostname` como `www-data`. El guion
reproducible está en [`demo/lfm-rce-demo.tape`](demo/lfm-rce-demo.tape) (requiere
[`vhs`](https://github.com/charmbracelet/vhs) y el laboratorio levantado).

## Causa raíz (referencias de código)

Copia revisada en el commit `74bebe32` del paquete:

| Fichero | Valor | Efecto |
|---|---|---|
| `config/file-manager.php:85` | `allowFileTypes => []` | sin lista de extensiones permitidas |
| `config/file-manager.php:98` | `middleware => ['web']` | sesión y CSRF, pero **sin** autenticación |
| `config/file-manager.php:105` | `acl => false` | sin control de acceso por ruta |
| `src/FileManager.php:159-185` | comprobación opcional + `putFileAs` con nombre original | conserva el nombre subido |
| `src/FileManager.php:274-277` | `rename` sin revalidar extensión | variante «subir como imagen y renombrar» |

El grupo de middleware `web` emite la cookie `XSRF-TOKEN` en el propio
`initialize`, por lo que el CSRF no detiene a un cliente no autenticado.

## Contenido del repositorio

| Ruta | Descripción |
|---|---|
| `advisory/` | Advisory técnico completo (LFM-2026-ADV-01). |
| `poc/lfm_upload_rce_poc.py` | PoC en Python stdlib. Objetivo por defecto `127.0.0.1:18080`; solo para laboratorio propio o autorizado. |
| `lab/` | Laboratorio Docker reproducible (Laravel 12 + PHP 8.3 + Apache + paquete 3.3.3, configuración publicada sin cambios). |
| `demo/` | GIF de la demostración y su guion VHS. |

## Reproducción en laboratorio

```bash
# Laboratorio aislado (solo loopback)
cd lab && docker compose build && docker compose up -d && cd ..

# PoC contra el laboratorio local
python3 poc/lfm_upload_rce_poc.py --base-url http://127.0.0.1:18080 --cmd 'id; whoami; hostname'

# Parar y limpiar
cd lab && docker compose down
```

El laboratorio se publica únicamente en `127.0.0.1:18080`; no debe exponerse fuera
de loopback ni usarse contra sistemas de terceros.

## Detección

- `POST` a `*/file-manager/upload` sin sesión autenticada, con `files[]` y nombres `.php`.
- Aparición de ficheros `.php` en `storage/app/public` o en cualquier disco servido por web.
- `GET` a `/storage/*.php` con parámetros de comando.
- `POST */file-manager/rename` seguido de acceso a un `.php`.
- Respuestas de `initialize` con `"acl":false` desde direcciones no administrativas.

## Remediación

1. Añadir autenticación/autorización al grupo del paquete: `['web','auth','admin']` o equivalente.
2. Restringir extensiones (`allowFileTypes => ['jpg','jpeg','png','gif','pdf']`) y validar en servidor.
3. Activar ACL (`acl => true`) con estrategia whitelist cuando aplique.
4. Mover las subidas a un disco privado y servirlas mediante controlador autorizado.
5. Impedir la ejecución de PHP bajo `/storage` en Apache/nginx (ejemplos en el advisory).

Detalle ampliado y controles negativos verificados en el advisory.

## Divulgación y alcance

El fabricante considera que la seguridad del despliegue corresponde al integrador
(issues públicas #185 y #187). Este material no contradice esa postura: documenta que
los valores **publicados** conducen a un despliegue inseguro si no se modifican, y
aporta detección y remediación. Reproducción en laboratorio local; sin interacción
con sistemas de terceros.

## Licencia

Material de investigación de seguridad. Uso exclusivo en sistemas propios o con
autorización explícita por escrito.
