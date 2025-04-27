# plugins/file_hasher_plugin.py
import hashlib
import os
from tkinter import messagebox

def register(api):
    def hash_file():
        filepath = api.app.current_file
        if not filepath or not os.path.exists(filepath):
            api.log("❌ Aucun fichier sélectionné ou le fichier n'existe pas.")
            messagebox.showerror("Erreur", "Aucun fichier valide sélectionné.")
            return

        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            api.log(f"✅ SHA-256: {digest}")
            messagebox.showinfo("Hash réussi", f"SHA-256:\n{digest}")
        except Exception as e:
            api.log(f"❌ Erreur de hachage : {str(e)}")
            messagebox.showerror("Erreur", f"Hachage échoué : {str(e)}")

    api.add_menu_item("🔍 Hacher le fichier", hash_file)
    api.log("Plugin de hachage SHA-256 chargé")
