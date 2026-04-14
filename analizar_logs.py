#!/usr/bin/env python3
"""
Herramienta de análisis de logs de seguridad para Libromundo.
Analiza el archivo JSON de logs y genera estadísticas de seguridad.

Uso: python analizar_logs.py [--archivo RUTA] [--output RUTA]
"""
import json
import sys
import os
from collections import Counter, defaultdict
from datetime import datetime

# Ruta por defecto del archivo de logs
DEFAULT_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'libromundo_security.json')
DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'analisis_seguridad.txt')


def cargar_logs(ruta_archivo):
    """Carga y parsea los logs JSON línea por línea."""
    logs = []
    with open(ruta_archivo, 'r', encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()
            if linea:
                try:
                    logs.append(json.loads(linea))
                except json.JSONDecodeError:
                    continue
    return logs


def analizar_eventos(logs):
    """Clasifica y cuenta eventos por tipo."""
    event_counts = Counter()
    for log in logs:
        event_type = log.get('event_type', 'UNKNOWN')
        event_counts[event_type] += 1
    return event_counts


def analizar_intentos_fallidos(logs):
    """Identifica patrones de intentos de autenticación fallidos."""
    intentos_por_ip = defaultdict(list)
    intentos_por_usuario = defaultdict(list)

    for log in logs:
        event_type = log.get('event_type', '')
        if event_type in ('AUTH_FAIL', 'CAPTCHA_FAIL', 'REGISTRATION_FAIL'):
            ip = log.get('ip', 'unknown')
            user = log.get('user', 'unknown')
            timestamp = log.get('asctime', '')
            intentos_por_ip[ip].append({
                'user': user, 'time': timestamp, 'type': event_type
            })
            intentos_por_usuario[user].append({
                'ip': ip, 'time': timestamp, 'type': event_type
            })

    return intentos_por_ip, intentos_por_usuario


def detectar_fuerza_bruta(intentos_por_ip, umbral=3):
    """Detecta posibles ataques de fuerza bruta por IP."""
    alertas = []
    for ip, intentos in intentos_por_ip.items():
        if len(intentos) >= umbral:
            usuarios_atacados = set(i['user'] for i in intentos)
            alertas.append({
                'ip': ip,
                'total_intentos': len(intentos),
                'usuarios_atacados': list(usuarios_atacados),
                'primer_intento': intentos[0]['time'],
                'ultimo_intento': intentos[-1]['time'],
            })
    return alertas


def analizar_accesos_sensibles(logs):
    """Analiza accesos a recursos sensibles (admin, ventas, etc.)."""
    accesos = []
    for log in logs:
        event_type = log.get('event_type', '')
        if event_type in ('ADMIN_ACCESS', 'SENSITIVE_ACCESS', 'ACCESS_DENIED'):
            accesos.append({
                'user': log.get('user', 'unknown'),
                'ip': log.get('ip', 'unknown'),
                'event': event_type,
                'time': log.get('asctime', ''),
                'message': log.get('message', ''),
            })
    return accesos


def analizar_errores(logs):
    """Identifica errores de base de datos y sistema."""
    errores = []
    for log in logs:
        if log.get('levelname') == 'ERROR' or log.get('event_type') == 'DATABASE_ERROR':
            errores.append({
                'message': log.get('message', ''),
                'time': log.get('asctime', ''),
                'event_type': log.get('event_type', ''),
            })
    return errores


def generar_reporte(logs, output_path):
    """Genera un reporte completo de análisis de seguridad."""
    event_counts = analizar_eventos(logs)
    intentos_ip, intentos_user = analizar_intentos_fallidos(logs)
    alertas_fuerza_bruta = detectar_fuerza_bruta(intentos_ip)
    accesos_sensibles = analizar_accesos_sensibles(logs)
    errores = analizar_errores(logs)

    reporte = []
    reporte.append("=" * 70)
    reporte.append("  REPORTE DE ANÁLISIS DE LOGS DE SEGURIDAD - LIBROMUNDO")
    reporte.append(f"  Fecha de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    reporte.append(f"  Total de registros analizados: {len(logs)}")
    reporte.append("=" * 70)

    # 1. Resumen de eventos
    reporte.append("\n1. RESUMEN DE EVENTOS POR TIPO")
    reporte.append("-" * 40)
    for event, count in event_counts.most_common():
        nivel = "🔴 CRÍTICO" if event in ('DATABASE_ERROR', 'RATE_LIMIT') else \
                "🟡 ADVERTENCIA" if event in ('AUTH_FAIL', 'CAPTCHA_FAIL', 'ACCESS_DENIED', 'REGISTRATION_FAIL') else \
                "🟢 INFO"
        reporte.append(f"  {nivel} | {event}: {count} eventos")

    # 2. Intentos fallidos por IP
    reporte.append("\n2. INTENTOS FALLIDOS POR IP")
    reporte.append("-" * 40)
    if intentos_ip:
        for ip, intentos in sorted(intentos_ip.items(), key=lambda x: len(x[1]), reverse=True):
            reporte.append(f"  IP: {ip} → {len(intentos)} intentos fallidos")
            for intento in intentos[:5]:  # Mostrar máximo 5
                reporte.append(f"    - Usuario: {intento['user']} | Tipo: {intento['type']} | Hora: {intento['time']}")
    else:
        reporte.append("  Sin intentos fallidos registrados.")

    # 3. Intentos fallidos por usuario
    reporte.append("\n3. INTENTOS FALLIDOS POR USUARIO")
    reporte.append("-" * 40)
    if intentos_user:
        for user, intentos in sorted(intentos_user.items(), key=lambda x: len(x[1]), reverse=True):
            reporte.append(f"  Usuario: {user} → {len(intentos)} intentos fallidos")
    else:
        reporte.append("  Sin intentos fallidos registrados.")

    # 4. Alertas de fuerza bruta
    reporte.append("\n4. ALERTAS DE POSIBLE FUERZA BRUTA (≥3 intentos por IP)")
    reporte.append("-" * 40)
    if alertas_fuerza_bruta:
        for alerta in alertas_fuerza_bruta:
            reporte.append(f"  🔴 ALERTA: IP {alerta['ip']}")
            reporte.append(f"     Total intentos: {alerta['total_intentos']}")
            reporte.append(f"     Usuarios atacados: {', '.join(alerta['usuarios_atacados'])}")
            reporte.append(f"     Periodo: {alerta['primer_intento']} → {alerta['ultimo_intento']}")
    else:
        reporte.append("  Sin alertas de fuerza bruta detectadas.")

    # 5. Accesos a recursos sensibles
    reporte.append("\n5. ACCESOS A RECURSOS SENSIBLES")
    reporte.append("-" * 40)
    if accesos_sensibles:
        for acceso in accesos_sensibles:
            emoji = "🔴" if acceso['event'] == 'ACCESS_DENIED' else "🟢"
            reporte.append(f"  {emoji} {acceso['event']} | Usuario: {acceso['user']} | IP: {acceso['ip']}")
            reporte.append(f"     {acceso['message']}")
    else:
        reporte.append("  Sin accesos a recursos sensibles registrados.")

    # 6. Errores del sistema
    reporte.append("\n6. ERRORES DEL SISTEMA")
    reporte.append("-" * 40)
    if errores:
        for error in errores:
            reporte.append(f"  🔴 [{error['time']}] {error['event_type']}: {error['message']}")
    else:
        reporte.append("  Sin errores del sistema registrados.")

    # 7. Métricas de seguridad
    total_auth = event_counts.get('AUTH_SUCCESS', 0) + event_counts.get('AUTH_FAIL', 0)
    tasa_fallo = (event_counts.get('AUTH_FAIL', 0) / total_auth * 100) if total_auth > 0 else 0

    reporte.append("\n7. MÉTRICAS DE SEGURIDAD")
    reporte.append("-" * 40)
    reporte.append(f"  Total autenticaciones exitosas: {event_counts.get('AUTH_SUCCESS', 0)}")
    reporte.append(f"  Total autenticaciones fallidas: {event_counts.get('AUTH_FAIL', 0)}")
    reporte.append(f"  Tasa de fallo de autenticación: {tasa_fallo:.1f}%")
    reporte.append(f"  Captchas fallidos: {event_counts.get('CAPTCHA_FAIL', 0)}")
    reporte.append(f"  Accesos denegados: {event_counts.get('ACCESS_DENIED', 0)}")
    reporte.append(f"  Errores de base de datos: {event_counts.get('DATABASE_ERROR', 0)}")
    reporte.append(f"  Rate limits activados: {event_counts.get('RATE_LIMIT', 0)}")

    # 8. Recomendaciones
    reporte.append("\n8. RECOMENDACIONES DE SEGURIDAD")
    reporte.append("-" * 40)
    if tasa_fallo > 30:
        reporte.append("  ⚠️  Tasa de fallo de autenticación alta (>30%). Considerar bloqueo temporal de cuentas.")
    if alertas_fuerza_bruta:
        reporte.append("  ⚠️  Ataques de fuerza bruta detectados. Revisar IPs y considerar bloqueo.")
    if event_counts.get('DATABASE_ERROR', 0) > 0:
        reporte.append("  ⚠️  Errores de base de datos detectados. Revisar integridad y conexiones.")
    if not accesos_sensibles:
        reporte.append("  ✅ Sin accesos sospechosos a recursos sensibles.")
    reporte.append("  📌 Revisar periódicamente los logs para detectar anomalías.")
    reporte.append("  📌 Implementar alertas automáticas para eventos críticos.")
    reporte.append("  📌 Rotar logs periódicamente para gestión de almacenamiento.")

    reporte.append("\n" + "=" * 70)
    reporte.append("  FIN DEL REPORTE")
    reporte.append("=" * 70)

    reporte_texto = '\n'.join(reporte)

    # Escribir a archivo
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(reporte_texto)

    return reporte_texto


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Análisis de logs de seguridad de Libromundo')
    parser.add_argument('--archivo', default=DEFAULT_LOG_FILE, help='Ruta al archivo de logs JSON')
    parser.add_argument('--output', default=DEFAULT_OUTPUT, help='Ruta de salida del reporte')
    args = parser.parse_args()

    if not os.path.exists(args.archivo):
        print(f"Error: No se encontró el archivo de logs: {args.archivo}")
        sys.exit(1)

    print(f"Cargando logs de: {args.archivo}")
    logs = cargar_logs(args.archivo)
    print(f"Total de registros: {len(logs)}")

    print(f"Generando reporte en: {args.output}")
    reporte = generar_reporte(logs, args.output)
    print(reporte)
