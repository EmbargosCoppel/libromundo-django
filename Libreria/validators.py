import re
from django.core.exceptions import ValidationError


def validar_no_consecutivos(value):
    """Valida que no haya 3 o más caracteres idénticos consecutivos."""
    if re.search(r'(.)\1\1', value):
        raise ValidationError(
            'El nombre de usuario no puede tener 3 o más caracteres idénticos consecutivos.'
        )


class ComplexPasswordValidator:
    """Validador de contraseña con requisitos de complejidad."""

    def validate(self, password, user=None):
        if len(password) < 8:
            raise ValidationError("La contraseña debe tener al menos 8 caracteres.")

        if not re.search(r'[A-Z]', password):
            raise ValidationError("La contraseña debe contener al menos una letra mayúscula.")

        if not re.search(r'[a-z]', password):
            raise ValidationError("La contraseña debe contener al menos una letra minúscula.")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("La contraseña debe contener al menos un carácter especial.")

        for i in range(len(password) - 1):
            char1 = password[i].lower()
            char2 = password[i + 1].lower()
            if abs(ord(char1) - ord(char2)) == 1:
                if char1.isdigit() and char2.isdigit():
                    raise ValidationError("No se permiten números consecutivos (ej. 12, 21).")
                if char1.isalpha() and char2.isalpha():
                    raise ValidationError("No se permiten letras consecutivas (ej. ab, ba).")

    def get_help_text(self):
        return "Tu contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un carácter especial y no contener caracteres consecutivos."