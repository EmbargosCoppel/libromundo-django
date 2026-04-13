# Librería Libromundo

Aplicación web de librería en línea desarrollada con Django, enfocada en seguridad y buenas prácticas.

## Descripción

Libromundo es una plataforma para comprar y leer libros en línea. Incluye autenticación de usuarios, catálogo de libros, carrito de compras y lector online.

## Características

- **Autenticación Segura**: Login, registro con validadores de contraseña compleja.
- **Catálogo**: Visualización de libros disponibles.
- **Carrito de Compras**: Gestión de compras.
- **Lector Online**: Acceso a libros digitales.
- **Seguridad**: Logs de seguridad, CSP, HSTS, RBAC.
- **Logs**: Registro de eventos en JSON para análisis.

## Requerimientos Funcionales

- Registro y login de usuarios.
- Visualización de catálogo de libros.
- Agregar libros al carrito.
- Procesar compras.
- Acceso restringido por roles (staff, superuser).

## Requerimientos de Seguridad

- Autenticación robusta con validadores personalizados.
- Protección contra ataques comunes (CSRF, XSS vía CSP).
- Logs detallados de eventos de seguridad.
- Encriptación de contraseñas.
- RBAC para acceso a paneles administrativos.

## Instalación

1. Clona el repositorio.
2. Crea un entorno virtual: `python -m venv env`
3. Activa el entorno: `.\env\Scripts\Activate.ps1` (Windows)
4. Instala dependencias: `pip install -r requirements.txt`
5. Ejecuta migraciones: `python manage.py migrate`
6. Crea un superusuario: `python manage.py createsuperuser`
7. Ejecuta el servidor: `python manage.py runserver`

## Uso

- Accede a `http://127.0.0.1:8000`
- Regístrate o inicia sesión.
- Explora el catálogo y agrega libros al carrito.

## S-SDLC (Ciclo de Vida de Seguridad en Desarrollo de Software)

### 1. Análisis
- Identificación de activos: Datos de usuarios, libros, transacciones.
- Amenazas: Ataques de inyección, XSS, CSRF, accesos no autorizados.
- Requerimientos: Autenticación, logs, validaciones.

### 2. Diseño
- Arquitectura: MVC con Django.
- Controles: Middleware de seguridad, CSP, validadores.
- Técnicas: Encriptación, RBAC, logs estructurados.

### 3. Implementación
- Código seguro: Uso de ORM, sanitización de inputs.
- Estándares: PEP8, comentarios en inglés.

### 4. Pruebas
- Unitarias: Modelos y vistas.
- Seguridad: Validadores, acceso restringido.

### 5. Despliegue
- Configuración: DEBUG=False en producción, HTTPS.
- Monitoreo: Logs para detección de anomalías.

### 6. Mantenimiento
- Actualizaciones: Parches de seguridad.
- Auditorías: Revisión periódica de logs.

## Pruebas de Seguridad

### Resultados
- **SAST**: No implementado (recomendado: Bandit).
- **DAST**: No implementado (recomendado: OWASP ZAP).
- **IAST**: No implementado.
- **RASP**: No implementado.

### Fallas Detectadas
- Posible XSS en templates si no se escapan datos.
- SQL Injection mitigado por ORM, pero validar inputs.

### Recomendaciones
- Implementar herramientas automatizadas.
- Realizar pentesting.
- Monitorear logs con SIEM.

## Logs

Los logs se almacenan en `logs/libromundo_security.json` en formato JSON.

Para análisis básico:
```python
import json
with open('logs/libromundo_security.json') as f:
    logs = [json.loads(line) for line in f]
# Analizar eventos
```

Recomendado: Usar ELK Stack para análisis avanzado.

## Contribución

- Sigue estándares de codificación.
- Agrega tests para nuevas funcionalidades.
- Documenta cambios de seguridad.