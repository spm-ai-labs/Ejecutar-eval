import pdfplumber
import pandas as pd
import re
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

def categorize_rubro(detail):
    detail = detail.upper()
    if any(word in detail for word in ["OPESSA", "YPF", "LUBRICENTRO", "SHELL"]):
        return "COMBUSTIBLE"
    elif any(word in detail for word in ["MARKET MARTINEZ", "CARREFOUR", "JUMBO", "RAFFA", "MERCADO", "LOS AMIGOS"]):
        return "SUPERMERCADO"
    elif any(word in detail for word in ["SANCOR COOP", "MERPAGO*SANCORCOOPERA"]):
        return "SEGUROS"
    elif any(word in detail for word in ["WWW.AYSA.COM.AR", "NATURGY", "EDENORDIGITAL", "PERSONAL FLOW", "CLARO"]):
        return "SERVICIOS"
    elif any(word in detail for word in ["DLO*RAPPI", "RAPPI"]):
        return "PEDIDO RAPPI"
    elif any(word in detail for word in ["GOOGLE *GSUITE", "APPLE.COM/BILL", "OPENAI *CHATGPT"]):
        return "SUSCRIPCIONES"
    elif any(word in detail for word in ["IMPUESTO", "DB.IMPUESTO", "IIBB ", "IVA", "DB.RG"]):
        return "IMPUESTOS"
    elif any(word in detail for word in ["INTERESES FINANCIACION"]):
        return "INTERESES"
    else:
        return "OTROS"

def extract_visa_data(pdf_path):
    data = []
    current_card = "8757"  # Inicializamos con la primera tarjeta
    start_processing = False

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            lines = text.split('\n')

            for line in lines:
                if "SU PAGO EN PESOS" in line:
                    start_processing = True
                    continue

                if not start_processing:
                    continue

                if "TOTAL TARJETA XXXX XXXX XXXX 8757" in line:
                    current_card = "7168"  # Cambiamos a la segunda tarjeta
                    continue

                if "TOTAL TARJETA XXXX XXXX XXXX 7168" in line:
                    current_card = ""  # Dejamos vacío para las líneas siguientes
                    continue

                if "ó PLAN V EN" in line:
                    break  # Terminamos de procesar aquí

                # Usamos una expresión regular para identificar líneas de transacción válidas
                if re.match(r'\d{2}/\d{2}/\d{2}', line):
                    parts = line.split()
                    date = parts[0]
                    comprobante = parts[-2] if '*' in parts[-2] else ''

                    # Manejo del formato de importe
                    amount = parts[-1].replace('.', '').replace(',', '.')
                    pesos = amount if 'USD' not in line else ''
                    dollars = amount if 'USD' in line else ''

                    detail = " ".join(parts[1:-2]) if comprobante else " ".join(parts[1:-1])

                    rubro = categorize_rubro(detail)

                    data.append([
                        date,
                        detail,
                        comprobante,
                        pesos,
                        dollars,
                        rubro,  # Agregamos el rubro categorizado
                        current_card
                    ])

    return pd.DataFrame(data, columns=["Fecha", "Detalle de Transac", "Comprobante", "PESOS", "DOLARES", "Rubro", "Tarjeta_Nro"])

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if file_path:
        try:
            df = extract_visa_data(file_path)
            # Guardar en Excel
            output_file = "resumen_visa.xlsx"
            df.to_excel(output_file, index=False)
            messagebox.showinfo("Éxito", f"Los datos han sido extraídos y guardados en {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Ha ocurrido un error: {str(e)}")

# Crear la ventana principal
root = tk.Tk()
root.title("Extracto Visa a Excel")

# Configurar tamaño de la ventana
root.geometry('400x200')

# Añadir etiqueta
label = tk.Label(root, text="Seleccione el archivo PDF de su resumen Visa:")
label.pack(pady=20)

# Añadir botón para examinar archivos
browse_button = tk.Button(root, text="Examinar", command=browse_file, width=15)
browse_button.pack(pady=10)

# Ejecutar la aplicación
root.mainloop()
