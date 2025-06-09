import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

import firebase_admin
from firebase_admin import credentials, firestore   

if not firebase_admin._apps:
    cred = credentials.Certificate("seguridad-a415a-firebase-adminsdk-fbsvc-0c2629f6fa.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

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
mensaje = "Vuelve gatita"
mensaje_cifrado = f.encrypt(mensaje.encode()).decode()

# Guardar en Firebase Firestore
db.collection("mensajes").add({
    "contenido": mensaje_cifrado
})

print("Mensaje enviado (cifrado):", mensaje_cifrado)

docs = db.collection("mensajes").stream()

for doc in docs:
    data = doc.to_dict()
    mensaje_cifrado = data.get("contenido")
    if mensaje_cifrado:
        try:
            mensaje_descifrado = f.decrypt(mensaje_cifrado.encode()).decode()
            print(f"Mensaje descifrado (ID {doc.id}): {mensaje_descifrado}")
        except Exception as e:
            print(f"Error descifrando mensaje ID {doc.id}: {e}")
    else:
        print(f"No hay campo 'contenido' en el doc ID {doc.id}")