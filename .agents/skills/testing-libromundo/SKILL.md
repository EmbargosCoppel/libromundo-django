# Testing Libromundo Django App

## Overview
Libromundo is a Django 6.x digital bookstore with login, registration, catalog, cart, and purchase flows. Uses Bootstrap 5.3, SweetAlert2, and django-recaptcha.

## Devin Secrets Needed
None required for local testing — the app uses reCAPTCHA test keys by default.

## Local Setup
```bash
cd /home/ubuntu/repos/libromundo-django
pip install django python-json-logger django-recaptcha djangorestframework django-csp
DJANGO_DEBUG=True python manage.py migrate
DJANGO_DEBUG=True python manage.py createsuperuser --username admin --email admin@test.com --noinput
# Then set password via shell:
DJANGO_DEBUG=True python manage.py shell -c "
from django.contrib.auth.models import User
u = User.objects.get(username='admin')
u.set_password('TestPass123!')
u.save()
"
# Create test data:
DJANGO_DEBUG=True python manage.py shell -c "
from login.models import Categoria, Libro
cat, _ = Categoria.objects.get_or_create(nombre='Ficción', defaults={'descripcion': 'Libros de ficción'})
Libro.objects.get_or_create(titulo='El Quijote', defaults={'autor': 'Miguel de Cervantes', 'descripcion': 'Novela clásica', 'precio': 199.99, 'categoria': cat})
"
DJANGO_DEBUG=True python manage.py runserver 0.0.0.0:8000
```

## Key URLs
| Route | Purpose |
|---|---|
| `/accounts/login/` | Login page with reCAPTCHA |
| `/accounts/logout/` | Logout (redirects to login) |
| `/registration/registro/` | Registration page (must be logged out) |
| `/catalogo/` | Book catalog with search/filter |
| `/carrito/` | Shopping cart |
| `/carrito/agregar/<libro_id>/` | Add book to cart (GET, redirects to catalogo) |
| `/comprar/` | Process purchase (POST only, empties cart) |
| `/` | Home / admin panel |

## Testing Tips

### SweetAlert Popups
- SweetAlert popups fire on `DOMContentLoaded` and may auto-dismiss before screenshots
- To verify they rendered, check the page source for `Swal.fire` calls via browser console
- You can re-trigger them manually: `Swal.fire({title: 'Test', text: 'msg', icon: 'error'})`
- Django messages (success, error, warning) trigger SweetAlert via the `{% if messages %}` block in templates

### reCAPTCHA
- Uses test keys by default (`RECAPTCHA_PUBLIC_KEY`/`RECAPTCHA_PRIVATE_KEY` in settings.py)
- Test reCAPTCHA auto-passes after clicking the checkbox
- CSP must allow `frame-src`, `script-src`, and `img-src` for Google reCAPTCHA domains

### Registration Page
- Only accessible when logged out — redirects to home if authenticated
- Log out first via `/accounts/logout/` before testing registration

### Cart & Purchase Flow
- "Agregar al Carrito" in catalog is a plain link (`<a>` tag), not a button
- Adding to cart redirects back to `/catalogo/` with a success message
- "Finalizar Compra" in cart is a POST form button
- After purchase, `items.delete()` empties the cart and redirects to home
- Verify cart is empty by navigating to `/carrito/` — should show "Tu carrito está vacío"

### Browser Navigation
- Chrome may autocomplete URLs when typing in address bar (e.g., `/carrito/` might autocomplete to `/carrito/agregar/1/`)
- Use `google-chrome "http://localhost:8000/path/"` shell command for reliable navigation to new tabs
- Multiple tabs may accumulate during testing — keep track of which tab you're on

### Form Validation
- HTML5 `required` attribute prevents empty form submission client-side
- To test server-side validation, fill required fields but trigger other errors (e.g., skip captcha, use mismatched passwords)
- Inline errors appear as `<div class="text-danger small mt-1">` below fields
- `non_field_errors` appear as `<div class="alert alert-danger">` above the form

### Admin Home Page
- Admin/superuser home page shows "PANEL DE CONTROL: LIBROMUNDO" with links to reports and user management
- Regular users may see a different home view
