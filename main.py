import tkinter as tk
from tkinter import simpledialog, messagebox
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import firebase_admin
from firebase_admin import credentials, firestore

# Inicializar Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate("seguridad-a415a-firebase-adminsdk-fbsvc-0c2629f6fa.json")
    firebase_admin.initialize_app(cred)
db = firestore.client()

# Función para generar clave
def generar_clave(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

salt = b'salt1234'
clave = generar_clave("puchicanas", salt)
f = Fernet(clave)

# Función para enviar mensaje
def enviar_mensaje():
    mensaje = simpledialog.askstring("Enviar mensaje", "Escribe tu mensaje:")
    if mensaje:
        mensaje_cifrado = f.encrypt(mensaje.encode()).decode()
        db.collection("mensajes").add({"contenido": mensaje_cifrado})
        messagebox.showinfo("Éxito", "Mensaje enviado correctamente.")

# Función para ver mensajes
def ver_mensajes():
    mensajes = []
    docs = db.collection("mensajes").stream()
    for doc in docs:
        data = doc.to_dict()
        cifrado = data.get("contenido")
        try:
            descifrado = f.decrypt(cifrado.encode()).decode()
            mensajes.append(f"- {descifrado}")
        except:
            mensajes.append(f"- [Error al descifrar mensaje ID {doc.id}]")
    if mensajes:
        messagebox.showinfo("Mensajes almacenados", "\n".join(mensajes))
    else:
        messagebox.showinfo("Mensajes almacenados", "No hay mensajes.")

# Crear la interfaz
root = tk.Tk()
root.title("Mensajes Cifrados")

tk.Label(root, text="Menú de Mensajes Cifrados", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="Enviar Mensaje", width=30, command=enviar_mensaje).pack(pady=5)
tk.Button(root, text="Ver Mensajes", width=30, command=ver_mensajes).pack(pady=5)

root.mainloop()
