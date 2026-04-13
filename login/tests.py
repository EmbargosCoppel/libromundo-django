from django.test import TestCase
from django.contrib.auth.models import User
from .models import Libro, Carrito, ItemCarrito

class LibreriaTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.libro = Libro.objects.create(titulo='Test Book', autor='Test Author', precio=10.00)

    def test_libro_creation(self):
        self.assertEqual(self.libro.titulo, 'Test Book')

    def test_carrito_creation(self):
        carrito = Carrito.objects.create(usuario=self.user)
        self.assertEqual(carrito.usuario.username, 'testuser')

    def test_item_carrito(self):
        carrito = Carrito.objects.create(usuario=self.user)
        item = ItemCarrito.objects.create(carrito=carrito, libro=self.libro, cantidad=2)
        self.assertEqual(item.cantidad, 2)
