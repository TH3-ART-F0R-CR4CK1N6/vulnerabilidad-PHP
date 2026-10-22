# vulnerabilidad-PHP

# 📄 Documento de Seguridad: Vulnerabilidades Críticas en PHP (php2shell) – CVE-2026-109618 y CVE-2026-109619

Video: https://uploadnow.io/f/WpY2vMC

**Fecha de publicación:** 21 de octubre de 2026  
**Estado:** Parches disponibles – Actualización urgente recomendada  
**Nivel de severidad:** Crítico (CVSS v4.0: 9.2)  
**Vector:** RCE no autenticado (ejecución remota de código)

> **Nota de verificación:** Antes de publicar o difundir este documento, confirma los identificadores CVE, versiones parcheadas y avisos oficiales en php.net y en los boletines de tu proveedor de hosting.

---

## 1. Resumen ejecutivo

El equipo de PHP ha publicado actualizaciones de seguridad de emergencia para corregir dos vulnerabilidades críticas en el núcleo del lenguaje, conocidas en conjunto como **php2shell**. Estas fallas afectan a todas las versiones de PHP que sirven solicitudes web (desde PHP 5.4 hasta las ramas 8.2, 8.3, 8.4 y 8.5) y permiten a un atacante no autenticado ejecutar código arbitrario en el servidor sin necesidad de credenciales ni interacción del usuario.

La explotación exitosa puede resultar en:

- Ejecución remota de código (RCE) con los privilegios del proceso PHP.
- Lectura de memoria del proceso (potencial exposición de tokens, contraseñas, claves API).
- Denegación de servicio (DoS) y corrupción de datos.

**Acción inmediata:** Actualizar PHP a **8.5.12**, **8.4.27**, **8.3.36** o **8.2.35** (según la rama utilizada) y reiniciar los servicios web (Apache, PHP-FPM, etc.).

---

## 2. Detalles técnicos de las vulnerabilidades

Ambas fallas son del tipo **Use-After-Free (CWE-416)** y residen en el manejo interno de memoria y el procesamiento de solicitudes HTTP del runtime de PHP.

### 2.1. CVE-2026-109618 – RCE mediante corrupción por falta de memoria (OOM)

- **Causa raíz:** Cuando PHP se queda sin memoria (`memory_limit`) durante el procesamiento de una solicitud, utiliza `longjmp()` para abortar el manejo. Esto deja variables de sesión (`PS(http_session_vars)`) en un estado «colgante» (dangling) y la memoria de la solicitud a medio inicializar. La limpieza posterior trata esos datos como válidos, lo que provoca una condición de uso después de liberación (UAF).
- **Condición de disparo:** Una solicitud HTTP maliciosa (típicamente una solicitud `multipart/form-data` con campos especialmente diseñados) que agota el límite de memoria y deja la estructura de sesión en un estado inconsistente.
- **Impacto:** Ejecución remota de código en configuraciones como **Apache mod_php**, donde el exploit se dispara **antes** de que se ejecute cualquier código de la aplicación.

### 2.2. CVE-2026-109619 – RCE mediante estado global obsoleto (stale global state)

- **Causa raíz:** El manejo inadecuado de variables globales y de sesión durante el cierre de una solicitud que falló prematuramente. La memoria liberada se reutiliza sin una reinicialización completa, permitiendo que un atacante controle el flujo de ejecución.
- **Vector principal:** El mecanismo `session.upload_progress` (habilitado por defecto en PHP) es un vector clave. Una solicitud `POST` multipart con el campo `PHP_SESSION_UPLOAD_PROGRESS` puede inyectar datos en la sesión y, combinada con otras condiciones, alcanzar la ejecución de código.
- **Impacto:** Al igual que CVE-2026-109618, permite RCE no autenticado, aunque en PHP-FPM el camino de explotación depende de que la aplicación realice ciertas operaciones (por ejemplo, `include` de variables de sesión).

> **Nota:** Ambas vulnerabilidades fueron filtradas antes de su divulgación coordinada, y ya existe código de explotación público (PoC) y reportes de ataques activos en la naturaleza.

---

## 3. Cómo se explota (resumen técnico)

El ataque se lleva a cabo **sin autenticación** y se basa en el envío de solicitudes HTTP especialmente diseñadas que manipulan el manejo de memoria del intérprete PHP.

### 3.1. Explotación de CVE-2026-109618 (OOM corruption)

1. El atacante envía una solicitud HTTP (por ejemplo, `POST` multipart) que fuerza a PHP a alcanzar su límite de memoria (`memory_limit`) en un punto crítico del procesamiento.
2. El `longjmp()` deja la estructura de sesión (`PS(http_session_vars)`) apuntando a memoria ya liberada o no inicializada.
3. Durante el cierre de la solicitud, PHP recorre esa estructura y ejecuta un destructor forjado (`pDestructor`), que el atacante puede controlar mediante la disposición del heap (heap spraying).
4. El flujo de ejecución se redirige a `zif_system` (o una función similar), logrando ejecutar comandos del sistema operativo.

### 3.2. Explotación de CVE-2026-109619 (stale global state)

1. El atacante abusa de `session.upload_progress` enviando un campo `PHP_SESSION_UPLOAD_PROGRESS` en una solicitud multipart.
2. Esto provoca que datos controlados por el atacante se almacenen en la sesión y se mezclen con el estado global del proceso PHP.
3. Si la solicitud falla en un momento específico, el estado global queda «obsoleto» y contiene punteros a memoria liberada.
4. Al reutilizarse ese estado en una solicitud posterior (o en el mismo ciclo de vida del worker), se logra la ejecución de código arbitrario.

**Requisitos para el atacante:** Solo necesita acceso de red al servidor web que ejecuta PHP. No se requieren credenciales, cookies válidas ni interacción de la víctima.

---

## 4. Prevención y mitigación

### 4.1. Acción principal: actualizar PHP

La **única solución completa** es actualizar el runtime de PHP a las versiones parcheadas:

| Rama | Versión vulnerable | Versión segura |
|------|-------------------|----------------|
| 8.5.x | < 8.5.12 | **8.5.12** |
| 8.4.x | < 8.4.27 | **8.4.27** |
| 8.3.x | < 8.3.36 | **8.3.36** |
| 8.2.x | < 8.2.35 | **8.2.35** |

- **PHP 8.1 y anteriores** ya no reciben soporte oficial. Si se usan, deben aislarse de Internet o migrarse a una rama soportada.
- Tras la actualización, **reiniciar** Apache, PHP-FPM y cualquier worker de larga duración para que se cargue el binario parcheado.

### 4.2. Mitigaciones temporales (solo si no es posible actualizar de inmediato)

Estas medidas **reducen la superficie de ataque** pero **no eliminan la vulnerabilidad**. No deben sustituir la actualización.

1. **Deshabilitar `session.upload_progress`:**  
   Establecer `session.upload_progress.enabled = Off` en `php.ini` o en la configuración del pool de FPM, y reiniciar los workers. Esto mitiga parcialmente CVE-2026-109619.

2. **Forzar `memory_limit = -1` a nivel de administrador:**  
   Permite que las aplicaciones no puedan sobrescribir el límite y evita que una solicitud agote la memoria de forma controlada. Combinar con límites de tamaño de solicitud en el servidor web o proxy.

3. **Reducir `post_max_size`:**  
   Establecer un valor bajo (por ejemplo, 8 MB si no se necesitan subidas grandes, o 32 MB si son necesarias) para limitar el tamaño de las solicitudes entrantes.

4. **Deshabilitar `fatal_error_backtraces` (solo en PHP 8.5):**  
   Si se aplica la configuración anterior, también se recomienda `fatal_error_backtraces=0` para reducir la filtración de información en los mensajes de error.

5. **Usar un WAF (Web Application Firewall):**  
   Cloudflare y otros proveedores han desplegado reglas de protección. Sin embargo, el WAF es una capa adicional, no un sustituto del parche.

### 4.3. Detección y respuesta

- **Monitorizar procesos hijos inusuales:** Buscar procesos que el servidor web (www-data, apache, nginx) haya lanzado de forma anómala (por ejemplo, `sh`, `bash`, `curl`, `wget`).
- **Revisar logs de acceso:** Solicitudes `POST` con `PHP_SESSION_UPLOAD_PROGRESS` en el cuerpo, especialmente si van seguidas de respuestas inusualmente grandes o errores 500 repetidos.
- **Buscar webshells:** Archivos PHP sospechosos creados recientemente en directorios de subida o en la raíz del sitio.
- **Rotar credenciales:** Si se sospecha compromiso, rotar contraseñas, tokens de API y certificados que pudieran haber estado en la memoria del proceso PHP.

---

## 5. Recomendaciones para usuarios comunes (comunidad de GitHub)

### 5.1. Si usas GitHub Actions o dependencias de PHP en tus proyectos

- **Actualiza las imágenes de PHP en tus workflows:**  
  Si tus flujos de CI/CD usan `shivammathur/setup-php` o imágenes Docker oficiales de PHP, cambia la versión a `8.5.12`, `8.4.27`, `8.3.36` o `8.2.35`. Ejemplo:

  ```yaml
  - uses: shivammathur/setup-php@v2
    with:
      php-version: '8.4.27'
