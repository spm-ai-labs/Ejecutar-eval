# test_code.py
import os
clave_api="dsd33rfkksdwwfefE"
def suma(a,b):
   return a+b
def get_file_content(filename):
   
    full_path = "/var/www/data/" + filename
    with open(full_path, 'r') as f:
        return f.read()

print("Función de prueba lista.")
