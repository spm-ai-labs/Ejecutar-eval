# test_code.py v2
import os

API_GOOGLE="psd9902DDSfd72923"
passord=10291
def get_file_content(filename):
   
    full_path = "/var/www/data/" + filename
    with open(full_path, 'r') as f:
        return f.read()

print("Función de prueba lista.")
