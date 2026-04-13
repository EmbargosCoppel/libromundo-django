from django.contrib import admin
from django.urls import path, include
from login import views

urlpatterns = [
    # 1. Administración
    path('admin/', admin.site.urls),

    # 2. Autenticación con Logs (Tus vistas personalizadas)
    path('accounts/login/', views.login_view, name='login'),
    path('accounts/logout/', views.logout_view, name='logout'),
    path('accounts/access-denied/', views.access_denied, name='access_denied'),
    path('accounts/', include('django.contrib.auth.urls')),

    # 3. Aplicación Libromundo
    path('registration/registro/', views.registro, name='registro'),
    path('', views.home, name='home'),
    
    # --- AQUÍ ESTABA EL ERROR: AGREGAMOS LAS RUTAS FALTANTES ---
    path('catalogo/', views.catalogo, name='catalogo'),
    path('carrito/', views.ver_carrito, name='carrito'),
    path('leer/<int:libro_id>/', views.lector, name='lector'),
    path('resenas/<int:libro_id>/', views.ver_resenas, name='ver_resenas'),
    path('resenas/agregar/<int:libro_id>/', views.agregar_resena, name='agregar_resena'),
    # ----------------------------------------------------------

    # 4. Protección por Roles (RBAC)
    path('panel/', views.panel_administrador, name='panel_admin'),
    path('reportes/', views.reporte_ventas, name='reportes'),
    path('ventas/', views.reporte_ventas, name='ventas'),
    path('carrito/agregar/<int:libro_id>/', views.agregar_al_carrito, name='agregar_al_carrito'),
    path('carrito/eliminar/<int:item_id>/', views.eliminar_item_carrito, name='eliminar_item_carrito'),
    path('comprar/', views.procesar_compra, name='comprar'),
    # API REST
    path('api/libros/', views.LibroListAPI.as_view(), name='api_libros'),
    path('api/libros/<int:pk>/', views.LibroDetailAPI.as_view(), name='api_libro_detail'),
    path('api/carrito/', views.carrito_api, name='api_carrito'),
    path('api/resenas/<int:libro_id>/', views.ResenaListAPI.as_view(), name='api_resenas'),
]