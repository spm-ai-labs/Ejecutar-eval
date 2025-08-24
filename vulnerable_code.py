import base64
import pickle
import subprocess
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# --- Vulnerabilidad 1: Deserialización Insegura (CWE-502) ---
# Un atacante puede crear un objeto malicioso que, al ser deserializado,
# ejecuta código arbitrario en el servidor.
@app.route('/profile/update', methods=['POST'])
def process_user_profile():
    """
    Recibe datos de perfil serializados y codificados en Base64, los decodifica
    y los deserializa para actualizar el perfil de un usuario.
    """
    try:
        # FUENTE (Source): Datos controlados por el usuario desde un formulario.
        profile_data_b64 = request.form['profile_data']
        
        # El flujo pasa por una decodificación, un paso intermedio.
        serialized_profile = base64.b64decode(profile_data_b64)
        
        # RECEPTOR (Sink): Se deserializan los datos sin validar si son seguros.
        # La función pickle.loads es extremadamente peligrosa con datos no confiables.
        profile_object = pickle.loads(serialized_profile)

        # ... aquí iría la lógica para actualizar el perfil con profile_object ...
        return jsonify({"status": "success", "message": f"Perfil para {profile_object.get('name')} actualizado."})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# --- Vulnerabilidad 2: Inyección de Comandos del Sistema Operativo (CWE-78) ---
# El atacante puede inyectar comandos del sistema que se ejecutan en el servidor.
@app.route('/diagnostics/report', methods=['POST'])
def run_diagnostic():
    """
    Ejecuta un comando para listar los detalles de un archivo de reporte específico.
    """
    try:
        # FUENTE (Source): El nombre del archivo viene de un JSON enviado por el usuario.
        data = request.get_json()
        filename = data['filename']
        
        # RECEPTOR (Sink): El nombre del archivo se inserta en un comando del sistema.
        # El uso de `shell=True` con entrada del usuario es la causa de la vulnerabilidad.
        # Un atacante podría enviar: {"filename": "report.txt; rm -rf /"}
        command = f"ls -l reports/{filename}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        return jsonify({"status": "success", "output": result.stdout})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# --- Vulnerabilidad 3: Carga Insegura de YAML (similar a Deserialización) (CWE-502) ---
# La función `yaml.load` sin el `Loader` especificado es insegura y puede ejecutar código.
@app.route('/config/load', methods=['POST'])
def load_config():
    """
    Carga una configuración en formato YAML proporcionada por el usuario.
    """
    try:
        # FUENTE (Source): Contenido YAML directamente desde el cuerpo de la petición.
        yaml_content = request.data
        
        # RECEPTOR (Sink): `yaml.load` es peligroso y puede instanciar cualquier
        # objeto de Python, llevando a la ejecución de código.
        # La forma segura es usar `yaml.safe_load()`.
        config = yaml.load(yaml_content)

        return jsonify({"status": "success", "config_loaded": config})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


if __name__ == "__main__":
    # Nota: Se ejecuta en modo debug solo para desarrollo. No usar en producción.
    app.run(debug=True)
