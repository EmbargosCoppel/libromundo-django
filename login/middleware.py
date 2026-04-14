"""
Middleware de seguridad para Libromundo.
Implementa logging de todas las peticiones HTTP y protección contra ataques comunes.
"""
import time
import logging
from django.http import HttpResponse
from django.conf import settings

security_logger = logging.getLogger('libromundo_security')


class SecurityLoggingMiddleware:
    """
    Middleware que registra todas las peticiones HTTP con información de seguridad.
    Captura: método, ruta, IP, usuario, código de respuesta, tiempo de respuesta.
    Cumple con el requisito de logging exhaustivo para auditoría (OWASP Logging Cheat Sheet).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()

        # Obtener IP del cliente
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.META.get('REMOTE_ADDR', 'unknown')

        # Procesar la petición
        response = self.get_response(request)

        # Calcular tiempo de respuesta
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Determinar usuario
        user = 'anonimo'
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user.username

        # Registrar la petición
        log_data = {
            'ip': client_ip,
            'user': user,
            'event_type': 'HTTP_REQUEST',
        }

        log_message = (
            f"{request.method} {request.path} "
            f"status={response.status_code} "
            f"duration={duration_ms}ms "
            f"user={user} ip={client_ip}"
        )

        # Clasificar por código de respuesta
        if response.status_code >= 500:
            security_logger.error(log_message, extra=log_data)
        elif response.status_code >= 400:
            security_logger.warning(log_message, extra=log_data)
        else:
            # Solo loguear peticiones no-estáticas en nivel INFO
            if not request.path.startswith('/static/'):
                security_logger.info(log_message, extra=log_data)

        return response


class RateLimitMiddleware:
    """
    Middleware básico de rate limiting para protección contra fuerza bruta.
    Limita intentos de login por IP usando cache en memoria.
    Implementa protección OWASP contra ataques de fuerza bruta (A07:2021).
    """

    # Cache simple en memoria para rate limiting
    _request_counts = {}
    _last_cleanup = 0
    MAX_REQUESTS_PER_MINUTE = 30  # Límite general
    MAX_LOGIN_ATTEMPTS_PER_MINUTE = 5  # Límite para login
    CLEANUP_INTERVAL = 300  # Limpiar keys inactivos cada 5 minutos

    def __init__(self, get_response):
        self.get_response = get_response

    def _cleanup_stale_keys(self, current_time):
        """Elimina keys sin timestamps recientes para evitar crecimiento ilimitado de memoria."""
        if current_time - self._last_cleanup < self.CLEANUP_INTERVAL:
            return
        RateLimitMiddleware._last_cleanup = current_time
        stale_keys = [
            key for key, timestamps in self._request_counts.items()
            if not timestamps or all(current_time - t >= 60 for t in timestamps)
        ]
        for key in stale_keys:
            del self._request_counts[key]

    def __call__(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.META.get('REMOTE_ADDR', 'unknown')

        current_time = time.time()
        is_login = request.path == '/accounts/login/' and request.method == 'POST'

        # Limpieza periódica de keys inactivos
        self._cleanup_stale_keys(current_time)

        # Limpiar entradas antiguas (más de 60 segundos)
        key = f"{client_ip}:{'login' if is_login else 'general'}"
        if key in self._request_counts:
            self._request_counts[key] = [
                t for t in self._request_counts[key]
                if current_time - t < 60
            ]
        else:
            self._request_counts[key] = []

        # Verificar límite
        limit = self.MAX_LOGIN_ATTEMPTS_PER_MINUTE if is_login else self.MAX_REQUESTS_PER_MINUTE
        if len(self._request_counts[key]) >= limit:
            security_logger.warning(
                f"Rate limit excedido para IP {client_ip} en {'login' if is_login else 'general'}",
                extra={
                    'ip': client_ip,
                    'user': 'sistema',
                    'event_type': 'RATE_LIMIT',
                }
            )
            return HttpResponse(
                '<h1>429 - Demasiadas solicitudes</h1>'
                '<p>Has excedido el límite de solicitudes. Intenta de nuevo en un minuto.</p>',
                status=429
            )

        # Registrar esta petición
        self._request_counts[key].append(current_time)

        return self.get_response(request)


class SecurityHeadersMiddleware:
    """
    Middleware que añade headers de seguridad adicionales a todas las respuestas.
    Implementa recomendaciones OWASP para headers HTTP de seguridad.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Prevenir MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'

        # Política de referrer
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy (antes Feature-Policy)
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

        # Cache control para páginas con datos sensibles
        if hasattr(request, 'user') and request.user.is_authenticated:
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response['Pragma'] = 'no-cache'

        return response
