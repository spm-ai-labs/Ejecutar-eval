#nombre
definir=100
cost=10200

# config.py

DB_USER = "admin"
DB_PASSWORD = "admin123"  # contraseña débil (menos de 12 caracteres, sin símbolo, sin mayúscula)
SECRET_KEY = "sk_live_abcdef1234567890"  # clave API en texto plano (violación BR030)

# auth.py

from config import DB_USER, DB_PASSWORD, SECRET_KEY

usuarios = {
    "juan": {"password": "admin123", "email_confirmado": False}
}

def login(usuario, password):
    datos = usuarios.get(usuario)
    if datos and datos["password"] == password:
        return "Login exitoso"
    return "Credenciales inválidas"

def conectar_bd():
    return f"Conectando con {DB_USER} y {DB_PASSWORD}"

print(login("juan", "admin123"))
print(conectar_bd())
