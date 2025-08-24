import os
import re
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# --- Base de datos Falsa para simular usuarios y datos ---
# En una app real, esto vendría de una base de datos.
USERS = {
    '101': {'id': '101', 'name': 'Alice', 'is_admin': False},
    '102': {'id': '102', 'name': 'Bob', 'is_admin': False}
}
INVOICES = {
    'inv_001': {'id': 'inv_001', 'user_id': '101', 'amount': 150.00, 'details': 'Invoice for Alice'},
    'inv_002': {'id': 'inv_002', 'user_id': '102', 'amount': 300.50, 'details': 'Invoice for Bob'},
    'inv_003': {'id': 'inv_003', 'user_id': '101', 'amount': 50.25, 'details': 'Another invoice for Alice'}
}

# Simulación de un usuario autenticado (en una app real, esto vendría de una sesión)
def get_current_user():
    user_id = request.headers.get('X-User-ID') # El atacante puede controlar esta cabecera
    return USERS.get(user_id)

# --- Vulnerabilidad 1: Referencia Insegura y Directa a Objetos (IDOR) (CWE-639) ---
@app.route('/api/invoices/<invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    """
    Devuelve los detalles de una factura específica.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    invoice = INVOICES.get(invoice_id)
    if not invoice:
        abort(404)

    # LA VULNERABILIDAD:
    # Se comprueba que el usuario está autenticado, pero NO se comprueba
    # si la factura que solicita (`invoice_id`) le pertenece a ESE usuario.
    # Alice (user_id 101) podría solicitar /api/invoices/inv_002 y ver la factura de Bob.
    
    return jsonify(invoice)

# --- Vulnerabilidad 2: Asignación Masiva de Atributos (Mass Assignment) (CWE-915) ---
@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    """
    Actualiza el perfil de un usuario con los datos enviados en un JSON.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    data_to_update = request.get_json()

    # LA VULNERABILIDAD:
    # El código actualiza CIEGAMENTE todos los campos del usuario con los datos del JSON.
    # Un atacante podría enviar: {"name": "Mallory", "is_admin": true}
    # y esta función le otorgaría privilegios de administrador.
    for key, value in data_to_update.items():
        current_user[key] = value
        
    return jsonify({"status": "success", "user": current_user})

# --- Vulnerabilidad 3: Path Traversal (CWE-22) ---
@app.route('/avatars/<path:filename>', methods=['GET'])
def get_user_avatar(filename):
    """
    Devuelve la imagen de un avatar de usuario.
    """
    # Directorio base donde se guardan los avatares
    AVATAR_DIR = "/var/www/app/avatars"

    # LA VULNERABILIDAD:
    # No se valida ni sanea el `filename`. Un atacante podría solicitar
    # /avatars/../../../../etc/passwd para leer archivos sensibles del sistema.
    # La herramienta debe detectar que `filename` viene de la URL y se usa en una ruta de archivo.
    safe_path = os.path.realpath(os.path.join(AVATAR_DIR, filename))

    # Una validación adicional que una herramienta podría no entender.
    if not safe_path.startswith(os.path.realpath(AVATAR_DIR)):
         abort(400) # Aunque hay una validación, el patrón inseguro existe antes.

    with open(safe_path, 'r') as f:
        return f.read()

# --- Vulnerabilidad 4: Expresión Regular Ineficiente (Denegación de Servicio - ReDoS) (CWE-1333) ---
@app.route('/username/validate', methods=['POST'])
def validate_username():
    """
    Valida si un nombre de usuario cumple con un patrón específico.
    """
    username = request.get_json().get('username')

    # LA VULNERABILIDAD:
    # Este patrón de Regex es vulnerable a "Catastrophic Backtracking".
    # Un input como "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX" puede hacer que la evaluación
    # del regex tarde un tiempo exponencialmente largo, congelando el servidor.
    vulnerable_regex = re.compile(r'^(a+)+$')

    if vulnerable_regex.match(username):
        return jsonify({"status": "valid"})
    else:
        return jsonify({"status": "invalid"})

if __name__ == "__main__":
    # Se quita debug=True para no reportar esa vulnerabilidad de nuevo.
    app.run()
