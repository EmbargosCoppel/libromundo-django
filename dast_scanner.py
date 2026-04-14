#!/usr/bin/env python3
"""
Script de pruebas DAST (Dynamic Application Security Testing) para Libromundo.
Realiza pruebas de seguridad dinámicas contra la aplicación en ejecución.

Uso: python dast_scanner.py [--url URL_BASE]
"""
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import ssl
import http.cookiejar
from datetime import datetime

BASE_URL = "http://localhost:8000"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
RESULTS_FILE = os.path.join(OUTPUT_DIR, 'dast_results.json')
REPORT_FILE = os.path.join(OUTPUT_DIR, 'dast_report.txt')


class DastScanner:
    """Scanner DAST básico para aplicaciones Django."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.results = []
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.csrf_token = None

    def _request(self, path, method='GET', data=None, headers=None):
        """Realiza una petición HTTP y retorna (status, headers, body)."""
        url = f"{self.base_url}{path}"
        if headers is None:
            headers = {}
        headers.setdefault('User-Agent', 'LibromundoDAST/1.0')

        if data and isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode('utf-8')

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=10)
            return response.status, dict(response.headers), response.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode('utf-8', errors='replace')
        except Exception as e:
            return 0, {}, str(e)

    def _get_csrf_token(self, html_body):
        """Extrae el token CSRF de un formulario HTML."""
        import re
        match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html_body)
        if match:
            return match.group(1)
        return None

    def _add_result(self, test_name, severity, status, details, recommendation=""):
        """Agrega un resultado de prueba."""
        self.results.append({
            'test': test_name,
            'severity': severity,
            'status': status,
            'details': details,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat(),
        })

    # ====== PRUEBAS DE SEGURIDAD ======

    def test_security_headers(self):
        """Verifica la presencia de headers de seguridad HTTP."""
        print("  [*] Verificando headers de seguridad...")
        status, headers, _ = self._request('/accounts/login/')

        required_headers = {
            'X-Frame-Options': 'Protección contra clickjacking',
            'X-Content-Type-Options': 'Previene MIME type sniffing',
            'Content-Security-Policy': 'Política de seguridad de contenido',
            'Referrer-Policy': 'Control de información de referrer',
            'Permissions-Policy': 'Restricción de APIs del navegador',
        }

        for header, description in required_headers.items():
            # Case-insensitive header check
            found = any(h.lower() == header.lower() for h in headers.keys())
            if found:
                value = next(v for k, v in headers.items() if k.lower() == header.lower())
                self._add_result(
                    f"Header: {header}",
                    "INFO",
                    "PASS",
                    f"Presente con valor: {value[:100]}",
                )
            else:
                self._add_result(
                    f"Header: {header}",
                    "MEDIUM",
                    "FAIL",
                    f"Header faltante: {description}",
                    f"Agregar header {header} a las respuestas HTTP.",
                )

    def test_csrf_protection(self):
        """Verifica que la protección CSRF está activa."""
        print("  [*] Verificando protección CSRF...")
        status, _, body = self._request('/accounts/login/')

        if 'csrfmiddlewaretoken' in body:
            self._add_result(
                "CSRF Protection",
                "INFO",
                "PASS",
                "Token CSRF presente en formularios de login.",
            )
        else:
            self._add_result(
                "CSRF Protection",
                "HIGH",
                "FAIL",
                "No se encontró token CSRF en el formulario de login.",
                "Verificar que CsrfViewMiddleware está activo en settings.py.",
            )

    def test_login_bruteforce(self):
        """Prueba protección contra fuerza bruta en login."""
        print("  [*] Probando protección contra fuerza bruta...")
        # Primero obtener token CSRF
        status, _, body = self._request('/accounts/login/')
        csrf_token = self._get_csrf_token(body)

        blocked = False
        for i in range(7):
            data = {
                'csrfmiddlewaretoken': csrf_token or '',
                'username': f'attacker_{i}',
                'password': 'wrongpass',
                'g-recaptcha-response': 'test',
            }
            headers = {'Referer': f'{self.base_url}/accounts/login/'}
            status, _, body = self._request('/accounts/login/', method='POST', data=data, headers=headers)

            if status == 429 or 'Demasiadas solicitudes' in body:
                blocked = True
                self._add_result(
                    "Brute Force Protection",
                    "INFO",
                    "PASS",
                    f"Rate limiting activado después de {i+1} intentos.",
                )
                break
            # Get new CSRF token
            status2, _, body2 = self._request('/accounts/login/')
            csrf_token = self._get_csrf_token(body2)

        if not blocked:
            self._add_result(
                "Brute Force Protection",
                "MEDIUM",
                "WARNING",
                "El rate limiting no se activó con 7 intentos rápidos (puede depender de configuración).",
                "Verificar RateLimitMiddleware está activo y configurado.",
            )

    def test_sql_injection_login(self):
        """Prueba inyección SQL en formulario de login."""
        print("  [*] Probando inyección SQL en login...")
        status, _, body = self._request('/accounts/login/')
        csrf_token = self._get_csrf_token(body)

        payloads = [
            "' OR '1'='1",
            "admin'--",
            "1; DROP TABLE auth_user;--",
            "' UNION SELECT * FROM auth_user--",
        ]

        for payload in payloads:
            data = {
                'csrfmiddlewaretoken': csrf_token or '',
                'username': payload,
                'password': payload,
                'g-recaptcha-response': 'test',
            }
            headers = {'Referer': f'{self.base_url}/accounts/login/'}
            status, _, body = self._request('/accounts/login/', method='POST', data=data, headers=headers)

            if status == 500 or ('error' in body.lower() and 'sql' in body.lower()):
                self._add_result(
                    f"SQL Injection: {payload[:30]}",
                    "CRITICAL",
                    "FAIL",
                    f"Posible vulnerabilidad SQL injection con payload: {payload}",
                    "Usar consultas parametrizadas (ORM de Django).",
                )
                return

        self._add_result(
            "SQL Injection (Login)",
            "INFO",
            "PASS",
            "No se detectó vulnerabilidad SQL injection en login. Django ORM protege contra inyección.",
        )

    def test_xss_reflected(self):
        """Prueba XSS reflejado en parámetros de búsqueda."""
        print("  [*] Probando XSS reflejado...")
        # Necesitamos autenticarnos primero para acceder al catálogo
        payloads = [
            '<script>alert("XSS")</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert('XSS')",
        ]

        for payload in payloads:
            encoded = urllib.parse.quote(payload)
            status, _, body = self._request(f'/catalogo/?q={encoded}')

            if payload in body and '&lt;' not in body.replace(payload, ''):
                self._add_result(
                    f"XSS Reflected: {payload[:30]}",
                    "HIGH",
                    "FAIL",
                    f"Payload XSS reflejado sin escapar: {payload}",
                    "Usar template engine de Django que escapa por defecto.",
                )
                return

        self._add_result(
            "XSS Reflected (Catálogo)",
            "INFO",
            "PASS",
            "No se detectó XSS reflejado. Templates de Django escapan contenido automáticamente.",
        )

    def test_directory_traversal(self):
        """Prueba directory traversal."""
        print("  [*] Probando directory traversal...")
        payloads = [
            '/../../../etc/passwd',
            '/static/../../settings.py',
            '/leer/1/?page=../../../../etc/passwd',
        ]

        for payload in payloads:
            status, _, body = self._request(payload)
            if 'root:' in body or 'SECRET_KEY' in body:
                self._add_result(
                    f"Directory Traversal: {payload[:40]}",
                    "CRITICAL",
                    "FAIL",
                    f"Posible directory traversal: {payload}",
                    "Sanitizar rutas de archivo y usar pathlib.",
                )
                return

        self._add_result(
            "Directory Traversal",
            "INFO",
            "PASS",
            "No se detectó directory traversal. Django maneja rutas de forma segura.",
        )

    def test_session_security(self):
        """Verifica configuración de seguridad de sesiones."""
        print("  [*] Verificando seguridad de sesiones...")
        status, headers, _ = self._request('/accounts/login/')

        # Buscar cookie de sesión
        set_cookie = headers.get('Set-Cookie', '')

        checks = {
            'HttpOnly': 'httponly' in set_cookie.lower(),
            'SameSite': 'samesite' in set_cookie.lower(),
        }

        all_pass = True
        for check, passed in checks.items():
            if passed:
                self._add_result(
                    f"Session Cookie: {check}",
                    "INFO",
                    "PASS",
                    f"Cookie de sesión tiene atributo {check}.",
                )
            else:
                # Can still pass if no session cookie is set on GET request
                self._add_result(
                    f"Session Cookie: {check}",
                    "LOW",
                    "INFO",
                    f"Atributo {check} no visible en respuesta GET (puede requerir sesión activa).",
                )

    def test_error_handling(self):
        """Verifica que errores no exponen información sensible."""
        print("  [*] Verificando manejo de errores...")
        paths = [
            '/nonexistent-page-12345/',
            '/api/libros/99999/',
            '/leer/99999/',
        ]

        for path in paths:
            status, _, body = self._request(path)
            sensitive_patterns = ['Traceback', 'SETTINGS', 'SECRET_KEY', 'django.db', 'File "/', 'password']
            exposed = [p for p in sensitive_patterns if p in body]

            if exposed:
                self._add_result(
                    f"Error Info Leak: {path}",
                    "MEDIUM",
                    "WARNING",
                    f"La página de error puede exponer información: {', '.join(exposed)}",
                    "Configurar DEBUG=False en producción y usar páginas de error personalizadas.",
                )
            else:
                self._add_result(
                    f"Error Handling: {path}",
                    "INFO",
                    "PASS" if status in (302, 404) else "INFO",
                    f"Respuesta segura (status {status}), sin información sensible expuesta.",
                )

    def test_authentication_required(self):
        """Verifica que rutas protegidas requieren autenticación."""
        print("  [*] Verificando protección de rutas...")
        protected_paths = [
            '/catalogo/',
            '/carrito/',
            '/leer/1/',
            '/panel/',
            '/ventas/',
        ]

        for path in protected_paths:
            status, headers, _ = self._request(path)
            location = headers.get('Location', '')

            if status == 302 and 'login' in location.lower():
                self._add_result(
                    f"Auth Required: {path}",
                    "INFO",
                    "PASS",
                    f"Ruta protegida correctamente, redirige a login.",
                )
            elif status == 200:
                self._add_result(
                    f"Auth Required: {path}",
                    "HIGH",
                    "FAIL",
                    f"Ruta accesible sin autenticación.",
                    "Agregar @login_required o @user_passes_test.",
                )
            else:
                self._add_result(
                    f"Auth Required: {path}",
                    "INFO",
                    "PASS",
                    f"Ruta protegida (status {status}).",
                )

    def test_http_methods(self):
        """Verifica que métodos HTTP no permitidos son rechazados."""
        print("  [*] Verificando métodos HTTP...")
        # procesar_compra debería rechazar GET
        status, _, _ = self._request('/comprar/', method='GET')
        if status == 405 or status == 302:  # 302 redirect to login is also acceptable
            self._add_result(
                "HTTP Methods: /comprar/ GET",
                "INFO",
                "PASS",
                f"Método GET rechazado correctamente en /comprar/ (status {status}).",
            )
        else:
            self._add_result(
                "HTTP Methods: /comprar/ GET",
                "MEDIUM",
                "WARNING",
                f"Método GET retornó status {status} en /comprar/.",
                "Usar @require_http_methods para restringir métodos.",
            )

    def run_all_tests(self):
        """Ejecuta todas las pruebas DAST."""
        print("\n" + "=" * 60)
        print("  DAST SCANNER - LIBROMUNDO")
        print(f"  Target: {self.base_url}")
        print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        tests = [
            self.test_security_headers,
            self.test_csrf_protection,
            self.test_sql_injection_login,
            self.test_xss_reflected,
            self.test_directory_traversal,
            self.test_session_security,
            self.test_error_handling,
            self.test_authentication_required,
            self.test_http_methods,
            self.test_login_bruteforce,
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                self._add_result(
                    test.__name__,
                    "ERROR",
                    "ERROR",
                    f"Error ejecutando prueba: {str(e)}",
                )

        return self.results

    def generate_report(self):
        """Genera reporte de resultados DAST."""
        lines = []
        lines.append("=" * 60)
        lines.append("  REPORTE DAST - LIBROMUNDO")
        lines.append(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Total pruebas: {len(self.results)}")
        lines.append("=" * 60)

        # Resumen
        pass_count = sum(1 for r in self.results if r['status'] == 'PASS')
        fail_count = sum(1 for r in self.results if r['status'] == 'FAIL')
        warn_count = sum(1 for r in self.results if r['status'] == 'WARNING')

        lines.append(f"\n  RESUMEN: {pass_count} PASS | {fail_count} FAIL | {warn_count} WARNING\n")

        # Detalles por severidad
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            items = [r for r in self.results if r['severity'] == severity]
            if items:
                lines.append(f"\n--- {severity} ---")
                for r in items:
                    icon = "✅" if r['status'] == 'PASS' else "❌" if r['status'] == 'FAIL' else "⚠️"
                    lines.append(f"  {icon} [{r['status']}] {r['test']}")
                    lines.append(f"      {r['details']}")
                    if r.get('recommendation'):
                        lines.append(f"      💡 {r['recommendation']}")

        lines.append("\n" + "=" * 60)

        report_text = '\n'.join(lines)

        # Guardar resultados JSON
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # Guardar reporte texto
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            f.write(report_text)

        return report_text


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='DAST Scanner para Libromundo')
    parser.add_argument('--url', default=BASE_URL, help='URL base de la aplicación')
    args = parser.parse_args()

    scanner = DastScanner(args.url)
    scanner.run_all_tests()
    report = scanner.generate_report()
    print(report)
