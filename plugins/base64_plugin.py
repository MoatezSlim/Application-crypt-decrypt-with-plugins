# plugins/base64_plugin.py
import base64
from tkinter import messagebox
import os

def encrypt_fn(data):
    return None, base64.b64encode(data)

def decrypt_fn(data, _):
    return base64.b64decode(data)

def register(api):
    def encrypt_file():
        if api.app.current_file:
            try:
                with open(api.app.current_file, "rb") as f:
                    data = f.read()
                _, encrypted_data = encrypt_fn(data)
                output_path = api.app.current_file + ".b64"
                with open(output_path, "wb") as f:
                    f.write(encrypted_data)
                api.log("✅ Fichier chiffré avec Base64")
                messagebox.showinfo("Succès", f"Chiffrement terminé : {os.path.basename(output_path)}")
            except Exception as e:
                api.log(f"❌ Erreur: {str(e)}")
                messagebox.showerror("Erreur", str(e))
    
    def decrypt_file():
        if api.app.current_file:
            try:
                with open(api.app.current_file, "rb") as f:
                    data = f.read()
                decrypted_data = decrypt_fn(data, None)
                output_path = api.app.current_file.replace(".b64", ".decoded")
                with open(output_path, "wb") as f:
                    f.write(decrypted_data)
                api.log("✅ Fichier déchiffré avec Base64")
                messagebox.showinfo("Succès", f"Déchiffrement terminé : {os.path.basename(output_path)}")
            except Exception as e:
                api.log(f"❌ Erreur: {str(e)}")
                messagebox.showerror("Erreur", str(e))

    api.register_algorithm("Base64", encrypt_fn, decrypt_fn)
    api.add_menu_item("🔐 Base64 Chiffrer", encrypt_file)
    api.add_menu_item("🔓 Base64 Déchiffrer", decrypt_file)
    api.log("Plugin Base64 chargé avec succès")
