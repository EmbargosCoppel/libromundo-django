from django.db import models
from django.contrib.auth.models import User


class Categoria(models.Model):
    nombre = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField(blank=True)

    def __str__(self):
        return self.nombre

class Libro(models.Model):
    titulo = models.CharField(max_length=200)
    autor = models.CharField(max_length=100)
    descripcion = models.TextField(blank=True)
    precio = models.DecimalField(max_digits=10, decimal_places=2)
    archivo = models.FileField(upload_to='libros/', blank=True)  # Para archivos PDF o similares
    categoria = models.ForeignKey(Categoria, on_delete=models.CASCADE, related_name='libros', null=True, blank=True)
    paginas = models.JSONField(default=list, blank=True)  # Lista de strings, cada uno una página

    def __str__(self):
        return self.titulo

class Carrito(models.Model):
    usuario = models.OneToOneField(User, on_delete=models.CASCADE)
    libros = models.ManyToManyField(Libro, through='ItemCarrito')

    def __str__(self):
        return f"Carrito de {self.usuario.username}"

class ItemCarrito(models.Model):
    carrito = models.ForeignKey(Carrito, on_delete=models.CASCADE)
    libro = models.ForeignKey(Libro, on_delete=models.CASCADE)
    cantidad = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.cantidad} x {self.libro.titulo}"

class Resena(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    libro = models.ForeignKey(Libro, on_delete=models.CASCADE, related_name='resenas')
    calificacion = models.PositiveIntegerField(choices=[(i, i) for i in range(1, 6)])  # 1-5 estrellas
    comentario = models.TextField(blank=True)
    fecha = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('usuario', 'libro')  # Una reseña por usuario por libro

    def __str__(self):
        return f"Reseña de {self.usuario.username} para {self.libro.titulo}"
