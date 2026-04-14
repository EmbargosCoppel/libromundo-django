from django.shortcuts import render, redirect, get_object_or_404
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_http_methods
from django.db import DatabaseError 
from rest_framework import generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from .forms import RegistroForm, LoginForm
from .models import Libro, Carrito, ItemCarrito, Categoria, Resena
from .serializers import LibroSerializer, CarritoSerializer, ResenaSerializer
import logging

# Logger de seguridad
security_logger = logging.getLogger('libromundo_security')

def get_client_ip(request):
    """Obtiene la IP real del cliente para análisis (Punto 4.2)"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            usuario = form.cleaned_data.get('username')
            clave = form.cleaned_data.get('password')
            client_ip = get_client_ip(request)
            try:
                user = authenticate(request, username=usuario, password=clave)
                if user is not None:
                    login(request, user)
                    security_logger.info(f"Inicio de sesión exitoso: {usuario}", extra={
                        'ip': client_ip, 'user': usuario, 'event_type': 'AUTH_SUCCESS'
                    })
                    return redirect('home')
                else:
                    security_logger.warning(f"Intento de login fallido: {usuario}", extra={
                        'ip': client_ip, 'user': usuario if usuario else 'anonimo', 'event_type': 'AUTH_FAIL'
                    })
                    messages.error(request, "Usuario o contraseña incorrectos.")
            except DatabaseError as e:
                security_logger.error(f"Error crítico: SQLException detectada - {str(e)}", extra={
                    'ip': client_ip, 'user': 'sistema', 'event_type': 'DATABASE_ERROR'
                })
                messages.error(request, "Error técnico de conexión.")
        else:
            messages.error(request, "CAPTCHA inválido o datos incorrectos.")
    else:
        form = LoginForm()
    return render(request, 'registration/login.html', {'form': form})

def registro(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form = RegistroForm(request.POST)
        client_ip = get_client_ip(request)
        try:
            if form.is_valid():
                user = form.save()
                username = form.cleaned_data.get('username')
                # Enviar email de bienvenida
                send_mail(
                    'Bienvenido a Libromundo',
                    f'Hola {username}, tu cuenta ha sido creada exitosamente. ¡Disfruta leyendo!',
                    'noreply@libromundo.com',
                    [user.email],
                    fail_silently=True,
                )
                security_logger.info(f"Nuevo usuario registrado: {username}", extra={
                    'ip': client_ip, 'user': username, 'event_type': 'DATA_MOD'
                })
                messages.success(request, f'¡Cuenta creada para {username}!')
                return redirect('login')
            else:
                user_tried = request.POST.get('username', 'desconocido')
                security_logger.warning(f"Intento de registro fallido: {user_tried}", extra={
                    'ip': client_ip, 'user': user_tried, 'event_type': 'REGISTRATION_FAIL'
                })
        except DatabaseError as e:
            security_logger.error(f"Fallo en registro: SQLException - {str(e)}", extra={
                'ip': client_ip, 'user': 'sistema', 'event_type': 'DATABASE_ERROR'
            })
    else:
        form = RegistroForm()
    return render(request, 'registration/registro.html', {'form': form})

def logout_view(request):
    user = request.user.username if request.user.is_authenticated else "anonimo"
    client_ip = get_client_ip(request)
    security_logger.info(f"Cierre de sesión: {user}", extra={
        'ip': client_ip, 'user': user, 'event_type': 'LOGOUT'
    })
    logout(request)
    return redirect('login')


@login_required 
def home(request):
    libros_novedades = Libro.objects.all()[:3]  # Mostrar los primeros 3 libros
    return render(request, 'home.html', {'libros': libros_novedades})

@login_required
def catalogo(request):
    security_logger.info(f"Usuario {request.user.username} accedió al catálogo", extra={
        'ip': get_client_ip(request), 'user': request.user.username, 'event_type': 'CATALOG_VIEW'
    })
    query = request.GET.get('q', '')
    categoria_id = request.GET.get('categoria')
    
    libros = Libro.objects.all()
    
    if query:
        libros = libros.filter(
            Q(titulo__icontains=query) | 
            Q(autor__icontains=query) | 
            Q(descripcion__icontains=query)
        )
    
    if categoria_id:
        libros = libros.filter(categoria_id=categoria_id)
    
    categorias = Categoria.objects.all()
    
    # Paginación
    paginator = Paginator(libros, 9)  # 9 libros por página
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'catalogo.html', {
        'page_obj': page_obj, 
        'categorias': categorias, 
        'query': query,
        'categoria_id': categoria_id
    })

@login_required
def agregar_al_carrito(request, libro_id):
    libro = get_object_or_404(Libro, id=libro_id)
    carrito, created = Carrito.objects.get_or_create(usuario=request.user)
    item, created = ItemCarrito.objects.get_or_create(carrito=carrito, libro=libro, defaults={'cantidad': 1})
    if not created:
        item.cantidad += 1
        item.save()
    messages.success(request, f"'{libro.titulo}' agregado al carrito.")
    return redirect('catalogo')

@login_required
def eliminar_item_carrito(request, item_id):
    item = get_object_or_404(ItemCarrito, id=item_id, carrito__usuario=request.user)
    item.delete()
    messages.info(request, f"'{item.libro.titulo}' eliminado del carrito.")
    return redirect('carrito')

@login_required
def ver_carrito(request):
    carrito, created = Carrito.objects.get_or_create(usuario=request.user)
    items = ItemCarrito.objects.filter(carrito=carrito).select_related('libro')
    total = sum(item.libro.precio * item.cantidad for item in items)
    return render(request, 'carrito.html', {'items': items, 'total': total})

@login_required
def agregar_resena(request, libro_id):
    libro = get_object_or_404(Libro, id=libro_id)
    if request.method == 'POST':
        calificacion = request.POST.get('calificacion')
        comentario = request.POST.get('comentario')
        resena, created = Resena.objects.update_or_create(
            usuario=request.user,
            libro=libro,
            defaults={'calificacion': calificacion, 'comentario': comentario}
        )
        messages.success(request, "Reseña guardada exitosamente.")
        return redirect('lector', libro_id=libro_id)
    return redirect('lector', libro_id=libro_id)

@login_required
def ver_resenas(request, libro_id):
    libro = get_object_or_404(Libro, id=libro_id)
    resenas = Resena.objects.filter(libro=libro).select_related('usuario')
    return render(request, 'resenas.html', {'libro': libro, 'resenas': resenas})

@login_required
def lector(request, libro_id):
    """Simula el lector de libros online con logs de acceso"""
    libro = get_object_or_404(Libro, id=libro_id)
    security_logger.info(f"Acceso a lectura online: Libro '{libro.titulo}' (ID {libro_id})", extra={
        'ip': get_client_ip(request), 'user': request.user.username, 'event_type': 'ONLINE_READ'
    })
    page_num = int(request.GET.get('page', 1))
    paginas = libro.paginas if libro.paginas else [libro.descripcion]  # Si no hay páginas, usar descripción como una página
    total_pages = len(paginas)
    if page_num < 1:
        page_num = 1
    elif page_num > total_pages:
        page_num = total_pages
    current_page = paginas[page_num - 1] if paginas else "Contenido no disponible"
    return render(request, 'lector.html', {
        'libro': libro,
        'current_page': current_page,
        'page_num': page_num,
        'total_pages': total_pages,
        'has_prev': page_num > 1,
        'has_next': page_num < total_pages
    })

# --- ADMINISTRACIÓN Y SEGURIDAD ---

@user_passes_test(lambda u: u.is_superuser, login_url='/accounts/access-denied/')
def reporte_ventas(request):
    security_logger.info("Consulta autorizada a Ventas", extra={
        'ip': get_client_ip(request), 'user': request.user.username, 'event_type': 'SENSITIVE_ACCESS'
    })
    return render(request, 'ventas.html')

@login_required
@require_http_methods(["POST"]) 
def procesar_compra(request):
    carrito = Carrito.objects.filter(usuario=request.user).first()
    if carrito:
        items = ItemCarrito.objects.filter(carrito=carrito)
        if not items.exists():
            messages.warning(request, "Tu carrito está vacío.")
            return redirect('carrito')
        security_logger.info("Transacción comercial - DATA_MOD", extra={
            'ip': get_client_ip(request), 'user': request.user.username, 'event_type': 'DATA_MOD'
        })
        send_mail(
            'Compra realizada en Libromundo',
            f'Hola {request.user.username}, tu compra ha sido procesada exitosamente.',
            'noreply@libromundo.com',
            [request.user.email],
            fail_silently=True,
        )
        items.delete()  # Vaciar el carrito
        messages.success(request, "Compra realizada con éxito.")
    else:
        messages.warning(request, "No tienes un carrito activo.")
    return redirect('home')

@user_passes_test(lambda u: u.is_staff, login_url='/accounts/access-denied/')
def panel_administrador(request): 
    security_logger.info("Acceso exitoso al Panel Administrativo", extra={
        'ip': get_client_ip(request), 'user': request.user.username, 'event_type': 'ADMIN_ACCESS'
    })
    return render(request, 'admin_panel.html')

def access_denied(request):
    client_ip = get_client_ip(request)
    user = request.user.username if request.user.is_authenticated else 'anonimo'
    security_logger.warning(f"ACCESO DENEGADO para: {user}", extra={
        'ip': client_ip, 'user': user, 'event_type': 'ACCESS_DENIED'
    })
    return render(request, 'registration/access_denied.html', status=403)

# --- API REST ---
class LibroListAPI(generics.ListAPIView):
    queryset = Libro.objects.all()
    serializer_class = LibroSerializer
    permission_classes = [permissions.IsAuthenticated]

class LibroDetailAPI(generics.RetrieveAPIView):
    queryset = Libro.objects.all()
    serializer_class = LibroSerializer
    permission_classes = [permissions.IsAuthenticated]

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def carrito_api(request):
    carrito, created = Carrito.objects.get_or_create(usuario=request.user)
    serializer = CarritoSerializer(carrito)
    return Response(serializer.data)

class ResenaListAPI(generics.ListCreateAPIView):
    serializer_class = ResenaSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        libro_id = self.kwargs['libro_id']
        return Resena.objects.filter(libro_id=libro_id)
    
    def perform_create(self, serializer):
        libro_id = self.kwargs['libro_id']
        serializer.save(usuario=self.request.user, libro_id=libro_id)