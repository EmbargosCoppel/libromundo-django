from rest_framework import serializers
from .models import Libro, Categoria, Carrito, ItemCarrito, Resena

class CategoriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Categoria
        fields = '__all__'

class LibroSerializer(serializers.ModelSerializer):
    categoria = CategoriaSerializer(read_only=True)
    
    class Meta:
        model = Libro
        fields = ['id', 'titulo', 'autor', 'descripcion', 'precio', 'categoria', 'paginas']

class ResenaSerializer(serializers.ModelSerializer):
    usuario = serializers.StringRelatedField()
    
    class Meta:
        model = Resena
        fields = ['id', 'usuario', 'calificacion', 'comentario', 'fecha']

class ItemCarritoSerializer(serializers.ModelSerializer):
    libro = LibroSerializer(read_only=True)
    
    class Meta:
        model = ItemCarrito
        fields = ['id', 'libro', 'cantidad']

class CarritoSerializer(serializers.ModelSerializer):
    items = ItemCarritoSerializer(many=True, read_only=True, source='itemcarrito_set')
    
    class Meta:
        model = Carrito
        fields = ['id', 'usuario', 'items']