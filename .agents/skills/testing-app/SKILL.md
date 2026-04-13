# Testing libromundo-django

## Local Dev Setup

1. Install dependencies (skip mysqlclient — SQLite works for testing):
   ```bash
   pip install django python-json-logger django-recaptcha djangorestframework django-csp
   ```
2. Create logs directory and run migrations:
   ```bash
   mkdir -p logs
   DJANGO_DEBUG=True python manage.py makemigrations
   DJANGO_DEBUG=True python manage.py migrate
   ```
3. Create test users and data:
   ```bash
   DJANGO_DEBUG=True python manage.py shell -c "
   from django.contrib.auth.models import User
   if not User.objects.filter(username='admin').exists():
       User.objects.create_superuser('admin', 'admin@test.com', 'Admin!9x#Z')
   if not User.objects.filter(username='testuser').exists():
       u = User.objects.create_user('testuser', 'test@test.com', 'Test!9x#Z')
       u.is_staff = True
       u.save()
   from login.models import Categoria, Libro
   cat, _ = Categoria.objects.get_or_create(nombre='Ficción', defaults={'descripcion': 'Libros de ficción'})
   Libro.objects.get_or_create(titulo='Test Book', defaults={'autor': 'Author', 'descripcion': 'Desc', 'precio': 25.00, 'categoria': cat, 'paginas': ['Page 1']})
   "
   ```
4. Start dev server:
   ```bash
   DJANGO_DEBUG=True python manage.py runserver 0.0.0.0:8000
   ```

## Known Issue: reCAPTCHA + CSP Conflict

The login form uses django-recaptcha, but the CSP policy in `settings.py` does not allow scripts from `google.com/recaptcha`. This means:
- The reCAPTCHA widget **will not render** on the login page
- Users **cannot log in** via the normal login form (`/accounts/login/`)
- **Workaround**: Log in via Django admin at `/admin/login/?next=<target_url>`
  - Example: `/admin/login/?next=/catalogo/` — logs in and redirects to the catalog page
  - The admin login does not require reCAPTCHA
  - The session cookie from admin login is valid for the entire site
- Only staff/superuser accounts can use this workaround (set `is_staff=True` on test users)

If this CSP issue is fixed in the future (by adding `https://www.google.com/recaptcha/` to CSP allowed script sources), the normal login form should work.

## Key URLs

| Page | URL | Notes |
|------|-----|-------|
| Login | `/accounts/login/` | reCAPTCHA may block — use admin login |
| Admin login | `/admin/login/?next=/` | Bypass for reCAPTCHA issue |
| Home | `/` | Shows admin panel for staff users |
| Catalog | `/catalogo/` | Lists all books with add-to-cart buttons |
| Cart | `/carrito/` | Shows items in cart |
| Book reader | `/leer/<book_id>/` | Online book reader |
| Reviews | `/resenas/<book_id>/` | View and add reviews |
| Logout | `/accounts/logout/` | POST-only (GET returns 405) |

## Testing Security Fixes

### POST Enforcement
- **Add-to-cart**: On `/catalogo/`, the "Agregar al Carrito" button should be a `<button type="submit">` inside a `<form method="post">`, not an `<a>` link
- **Cart deletion**: On `/carrito/`, the "Eliminar" button should be inside a `<form method="post">`
- **Logout**: GET to `/accounts/logout/` should return 405 Method Not Allowed
- Verify via browser address bar: navigating directly to GET URLs of POST-only endpoints should show 405

### Review Validation
- Navigate to `/resenas/<book_id>/`, fill in calificacion (1-5) and comentario, submit
- Valid input should save and redirect to `/leer/<book_id>/`
- The review should appear on `/resenas/<book_id>/` with correct stars and text

### XSS Fix
- Check `templates/registration/login.html` line 79 for `|escapejs` (not `|safe`)
- `grep 'escapejs\|safe' templates/registration/login.html` should show `escapejs`

## Test Credentials

| User | Password | Role |
|------|----------|------|
| admin | Admin!9x#Z | Superuser |
| testuser | Test!9x#Z | Staff (regular user with admin login access) |

## Devin Secrets Needed

No external secrets are required for local testing. The app runs fully with SQLite and Django's built-in test reCAPTCHA keys.

For production-like testing, you would need:
- `DJANGO_SECRET_KEY` — Django secret key
- `DB_PASSWORD` — MySQL database password
- `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD` — Email credentials
- `RECAPTCHA_PUBLIC_KEY` / `RECAPTCHA_PRIVATE_KEY` — Google reCAPTCHA keys
