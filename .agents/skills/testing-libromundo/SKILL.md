# Testing Libromundo Django App

## Local Dev Setup

```bash
cd /home/ubuntu/repos/libromundo-django
pip install django python-json-logger django-recaptcha djangorestframework django-csp
mkdir -p logs
DJANGO_DEBUG=True python manage.py migrate
DJANGO_DEBUG=True python manage.py runserver 0.0.0.0:8000
```

The app uses SQLite locally (no MySQL needed). The `DJANGO_DEBUG=True` env var is required.

## Creating a Test User

```bash
DJANGO_DEBUG=True python manage.py shell -c "
from django.contrib.auth.models import User
if not User.objects.filter(username='testuser').exists():
    User.objects.create_user('testuser', 'test@test.com', 'TestPass123!')
    print('User created')
else:
    print('User exists')
"
```

## Key URLs

| URL | Auth Required | Description |
|-----|---------------|-------------|
| `/accounts/login/` | No | Login page |
| `/accounts/logout/` | No | Logout (redirects to login) |
| `/registration/registro/` | No | Registration page |
| `/` | Yes | Home page |
| `/catalogo/` | Yes | Book catalog |
| `/carrito/` | Yes | Shopping cart |
| `/leer/<id>/` | Yes | Book reader |
| `/panel/` | Staff only | Admin panel |
| `/admin/` | Superuser | Django admin |

## reCAPTCHA Testing

- The app uses Google reCAPTCHA v2 with **test keys** that always pass validation:
  - Site key: `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`
  - Secret key: `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`

### Known Quirk: reCAPTCHA Auto-Render on Login Page

The `LoginForm.__init__` applies `class="form-control"` to ALL fields including the captcha div. This overrides the `g-recaptcha` class that Google's API needs for auto-rendering. As a workaround during testing, you may need to manually render the widget:

```javascript
// Run in browser console if widget doesn't auto-render
grecaptcha.render('id_captcha', {sitekey: '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'});
```

The registration page (`RegistroForm`) does NOT have this issue — reCAPTCHA auto-renders correctly there.

## CSP (Content Security Policy)

The app uses `django-csp` middleware. The CSP config is in `Libreria/settings.py` under `CONTENT_SECURITY_POLICY`. For reCAPTCHA to work, CSP must allow:
- `script-src`: `https://www.google.com`, `https://www.gstatic.com`
- `frame-src`: `https://www.google.com`

If the reCAPTCHA widget fails to load, check the browser console for CSP violation errors.

## Testing the `?next=` Login Redirect

1. Log out (click "Cerrar Sesión Auditada" or visit `/accounts/logout/`)
2. Navigate to a protected route like `/catalogo/`
3. You'll be redirected to `/accounts/login/?next=/catalogo/`
4. Log in — you should be redirected to `/catalogo/` (not `/`)
5. Verify the hidden `<input name="next">` field exists in the login form HTML

## Chrome Setup for GUI Testing

Chrome may not be running. Start it with:

```bash
/opt/.devin/chrome/chrome/linux-133.0.6943.126/chrome-linux64/chrome \
  --no-first-run --no-default-browser-check \
  --disable-background-timer-throttling \
  --remote-debugging-port=29229 \
  --user-data-dir=/tmp/chrome-test \
  http://localhost:8000/accounts/login/ &
```

Then maximize: `wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz`

## Devin Secrets Needed

No secrets are required for local testing. The app uses test reCAPTCHA keys and SQLite by default.
