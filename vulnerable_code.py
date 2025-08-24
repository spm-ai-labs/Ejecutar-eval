import sqlite3
import os
# sis
# Vulnerabilidad 1: Inyección de SQL (CWE-89)
def get_user_data(user_input):
    """
    Busca datos de un usuario de forma insegura, permitiendo SQL Injection.
    """
    db = sqlite3.connect("database.db")
    cursor = db.cursor()
    
    # Se concatena directamente la entrada del usuario en la consulta. ¡Muy peligroso!
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    
    cursor.execute(query)
    user = cursor.fetchone()
    db.close()
    return user

# Vulnerabilidad 2: Credenciales Hardcodeadas (CWE-798)
def connect_to_external_service():
    """
    Se conecta a un servicio externo usando una contraseña escrita en el código.
    """
    # La contraseña está directamente en el código fuente. ¡Muy peligroso!
    password = "secretpassword123!"
    
    print(f"Conectando al servicio con la contraseña: {password}")
    # Aquí iría la lógica de conexión...

# --- Ejemplo de uso ---
if __name__ == "__main__":
    # Simula una entrada de un atacante
    malicious_input = "' OR '1'='1"
    print("Buscando datos del usuario con entrada maliciosa...")
    get_user_data(malicious_input)

    print("\nIntentando conectar a servicio externo...")
    connect_to_external_service()
