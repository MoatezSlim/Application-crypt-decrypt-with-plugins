# plugins/zip_compression_plugin.py
import zipfile
import os
from tkinter import messagebox

def register(api):
    def compress_file():
        filepath = api.app.current_file
        if not filepath or not os.path.exists(filepath):
            api.log("❌ Aucun fichier sélectionné.")
            messagebox.showerror("Erreur", "Aucun fichier valide sélectionné.")
            return
        
        try:
            zip_path = filepath + ".zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(filepath, arcname=os.path.basename(filepath))
            api.log(f"✅ Fichier compressé : {zip_path}")
            messagebox.showinfo("Compression réussie", f"Créé : {os.path.basename(zip_path)}")
        except Exception as e:
            api.log(f"❌ Erreur compression : {str(e)}")
            messagebox.showerror("Erreur", str(e))
    
    def decompress_file():
        filepath = api.app.current_file
        if not filepath or not zipfile.is_zipfile(filepath):
            api.log("❌ Le fichier sélectionné n'est pas un fichier ZIP.")
            messagebox.showerror("Erreur", "Le fichier sélectionné n'est pas un fichier ZIP valide.")
            return

        try:
            output_dir = os.path.splitext(filepath)[0] + "_extracted"
            os.makedirs(output_dir, exist_ok=True)

            with zipfile.ZipFile(filepath, 'r') as zipf:
                zipf.extractall(output_dir)
            api.log(f"✅ Fichier extrait dans : {output_dir}")
            messagebox.showinfo("Extraction réussie", f"Extrait vers : {output_dir}")
        except Exception as e:
            api.log(f"❌ Erreur extraction : {str(e)}")
            messagebox.showerror("Erreur", str(e))

    api.add_menu_item("🗜️ Compresser (ZIP)", compress_file)
    api.add_menu_item("📂 Extraire ZIP", decompress_file)
    api.log("Plugin de compression ZIP chargé")
