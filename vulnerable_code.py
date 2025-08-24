import os
import random
import requests
from flask import Flask, request, jsonify, redirect, render_template_string

app = Flask(__name__)

# --- Base de datos Falsa para simular comentarios ---
COMMENTS = []

# --- Vulnerabilidad 1: Cross-Site Scripting (XSS) Almacenado (CWE-79) ---
# Esta es la 2ª vulnerabilidad más común según el informe de Snyk.
@app.route('/comments', methods=['GET'])
def view_comments():
    """
    Muestra los comentarios. Es el RECEPTOR (Sink) de la vulnerabilidad.
    """
    html = "<h1>Comentarios</h1><ul>"
    for comment in COMMENTS:
        # LA VULNERABILIDAD (SINK):
        # El comentario se renderiza directamente en el HTML sin ser escapado.
        # Si un comentario contiene <script>, se ejecutará en el navegador de la víctima.
        html += f"<li><b>{comment['author']}:</b> {comment['text']}</li>"
    html += "</ul>"
    # Se utiliza render_template_string para simular un motor de plantillas inseguro.
    return render_template_string(html)

@app.route('/comments/new', methods=['POST'])
def post_comment():
    """
    Guarda un nuevo comentario. Es la FUENTE (Source) de la vulnerabilidad.
    """
    author = request.form.get('author')
    text = request.form.get('text')

    # LA VULNERABILIDAD (SOURCE):
    # No se sanea ni valida el texto del comentario antes de guardarlo.
    # Un atacante puede enviar: {"text": "<script>alert('XSS')</script>"}
    COMMENTS.append({'author': author, 'text': text})
    
    return redirect('/comments')

# --- Vulnerabilidad 2: Redirección Abierta (Open Redirect) (CWE-601) ---
# Esta es la 6ª vulnerabilidad en la lista de Snyk.
@app.route('/redirect', methods=['GET'])
def handle_redirect():
    """
    Redirige al usuario a una URL especificada en los parámetros.
    """
    # FUENTE (Source): La URL de destino es controlada por el usuario.
    target_url = request.args.get('target')

    if target_url:
        # RECEPTOR (Sink): La aplicación redirige al usuario a la URL sin validarla.
        # Un atacante puede crear un enlace a:
        # /redirect?target=http://sitio-malicioso.com
        # y usarlo en una campaña de phishing.
        return redirect(target_url)
    
    return "No target specified."

# --- Vulnerabilidad 3: Uso de Valores Criptográficamente Débiles (CWE-330/CWE-338) ---
# Relacionado con "Cryptographic Issues" (nº 5 en la lista de Snyk).
@app.route('/password-reset/request', methods=['POST'])
def generate_password_reset_token():
    """
    Genera un token "seguro" para el reseteo de contraseña.
    """
    user_id = request.form.get('user_id')

    # LA VULNERABILIDAD:
    # `random` no es criptográficamente seguro. Sus valores son predecibles.
    # Un atacante podría predecir el token de reseteo de otro usuario.
    # La herramienta debe saber que `random` no debe usarse para fines de seguridad.
    token = ''.join(str(random.randint(0, 9)) for _ in range(6))
    
    print(f"Token de reseteo para {user_id}: {token}")
    return jsonify({"status": "success", "message": "Si el usuario existe, se ha enviado un token."})

# --- Vulnerabilidad 4: Transmisión de Datos Sensibles en Texto Plano (CWE-319) ---
# Relacionado con "Cryptographic Issues" (nº 5) y malas prácticas generales.
@app.route('/auth/login', methods=['POST'])
def login():
    """
    Autentica a un usuario contra un servicio externo.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    # LA VULNERABILIDAD:
    # Las credenciales se envían a un servicio de autenticación
    # a través de HTTP, no HTTPS.
    # Una herramienta de análisis debe detectar el uso de 'http://' en un contexto sensible.
    auth_service_url = 'http://auth.internal-service.com/validate'
    
    try:
        requests.post(auth_service_url, json={'user': username, 'pass': password})
        return "Login attempt processed."
    except requests.exceptions.RequestException as e:
        return f"Error connecting to auth service: {e}", 500

if __name__ == "__main__":
    app.run()
