from django.contrib import admin
from .models import Libro, Categoria, Carrito, ItemCarrito, Resena

admin.site.register(Categoria)
admin.site.register(Libro)
admin.site.register(Carrito)
admin.site.register(ItemCarrito)
admin.site.register(Resena)
