# Usa una imagen de Python que ya viene con todo listo
FROM python:3.11-bullseye

# Evita archivos basura
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# Instalamos las librerías directamente sin pasar por apt-get update
# Esto evita el error 403 de los repositorios de Debian
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]