import customtkinter as ctk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import os
import threading
import time
from datetime import datetime
import plugin_api
from PIL import Image

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")

class Stats:
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.operations = {
            'encrypt': {'count': 0, 'total_size': 0},
            'decrypt': {'count': 0, 'total_size': 0}
        }
        self.last_operation = None
        self.start_time = datetime.now()
    
    def add_operation(self, op_type, file_size):
        self.operations[op_type]['count'] += 1
        self.operations[op_type]['total_size'] += file_size
        self.last_operation = datetime.now()

class ModernCryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("SecureCrypt Pro")
        self.geometry("1200x800")
        
        # Configuration
        self.font_family = "Segoe UI"
        self.main_font = ctk.CTkFont(family=self.font_family, size=14)
        self.header_font = ctk.CTkFont(family=self.font_family, size=18, weight="bold")
        
        # Initialisation
        self.stats = Stats()
        self.current_file = None
        self.running_operation = False
        self.crypto_algorithms = {
            'AES-256': (self.aes_encrypt, self.aes_decrypt),
            'RSA-4096': (self.rsa_encrypt, self.rsa_decrypt)
        }
        self.plugin_manager = plugin_api.PluginManager(self)
        
        # Interface
        self.configure_layout()
        self.create_sidebar()
        self.create_main_content()
        self.create_keys_folder()
        self.generate_rsa_keys_if_needed()
    
    def configure_layout(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.main_frame = ctk.CTkFrame(self, corner_radius=0)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
    
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.main_frame, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=5, pady=5)
        
        ctk.CTkLabel(self.sidebar, text="SecureCrypt", font=self.header_font).pack(pady=20)
        
        buttons = [
            ("📁 Ouvrir", self.open_file),
            ("🔒 Chiffrer", self.encrypt_file),
            ("🔓 Déchiffrer", self.decrypt_file),
            ("📈 Statistiques", self.show_stats),
            ("🧩 Charger Plugin", self.load_plugin),
            ("🔄 Réinitialiser", self.reset_stats)
        ]
        
        for text, cmd in buttons:
            self.add_sidebar_button(text, cmd)
        
        self.theme_switch = ctk.CTkSwitch(
            self.sidebar,
            text="Mode Sombre", 
            command=self.toggle_theme,
            font=self.main_font
        )
        self.theme_switch.pack(pady=20)
    
    def add_sidebar_button(self, text, command):
        """Ajoute un bouton dans la sidebar"""
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            command=command,
            anchor="w",
            font=self.main_font,
            hover_color="#2B579A"
        )
        btn.pack(fill="x", pady=2)
    
    def create_main_content(self):
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(expand=True, fill="both", padx=5, pady=5)
        
        if hasattr(self.tabview, '_segmented_button'):
            self.tabview._segmented_button.configure(font=self.main_font)
        
        encrypt_tab = self.tabview.add("🔐 Chiffrement")
        self.setup_encryption_tab(encrypt_tab)
        
        log_tab = self.tabview.add("📜 Journal")
        self.setup_logs_tab(log_tab)
    
    def setup_encryption_tab(self, parent):
        self.file_entry = ctk.CTkEntry(
            parent, 
            placeholder_text="Sélectionnez un fichier...",
            font=self.main_font
        )
        self.file_entry.pack(pady=15, padx=20, fill="x")
        
        self.algo_var = ctk.StringVar(value="AES-256")
        algo_frame = ctk.CTkFrame(parent)
        algo_frame.pack(pady=10, fill="x", padx=20)
        
        for algo in self.crypto_algorithms.keys():
            ctk.CTkRadioButton(
                algo_frame, 
                text=algo, 
                variable=self.algo_var, 
                value=algo,
                font=self.main_font
            ).pack(side="left", padx=10)
        
        self.progress = ctk.CTkProgressBar(parent)
        self.progress.pack(pady=15, fill="x", padx=20)
    
    def setup_logs_tab(self, parent):
        self.log_text = ctk.CTkTextbox(
            parent, 
            wrap="word", 
            font=self.main_font,
            activate_scrollbars=True
        )
        self.log_text.pack(expand=True, fill="both", padx=10, pady=10)
    
    def create_keys_folder(self):
        if not os.path.exists('keys'):
            os.makedirs('keys')
    
    def generate_rsa_keys_if_needed(self):
        priv_path = "keys/rsa_private.pem"
        pub_path = "keys/rsa_public.pem"
        
        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            key = RSA.generate(4096)
            with open(priv_path, "wb") as f:
                f.write(key.export_key())
            with open(pub_path, "wb") as f:
                f.write(key.publickey().export_key())
    
    def toggle_theme(self):
        current = ctk.get_appearance_mode()
        new_mode = "Dark" if current == "Light" else "Light"
        ctk.set_appearance_mode(new_mode)
    
    def generate_cover_image(self):
        """Génère une image de couverture par défaut"""
        try:
            img = Image.new('RGB', (512, 512), color=(0, 0, 0))
            img.save('cover.jpg')
            self.log("✅ Image de couverture générée : cover.jpg")
            messagebox.showinfo("Succès", "Image créée avec succès")
        except Exception as e:
            self.log(f"❌ Erreur génération image : {str(e)}")
            messagebox.showerror("Erreur", f"Échec : {str(e)}")
    
    def open_file(self):
        self.current_file = filedialog.askopenfilename()
        if self.current_file:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, self.current_file)
            self.log(f"Fichier sélectionné : {os.path.basename(self.current_file)}")
    
    def encrypt_file(self):
        if self.current_file and not self.running_operation:
            threading.Thread(target=self.perform_encryption).start()
    
    def decrypt_file(self):
        if self.current_file and not self.running_operation:
            threading.Thread(target=self.perform_decryption).start()
    
    def aes_encrypt(self, data):
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return key, cipher.nonce + tag + ciphertext
    
    def aes_decrypt(self, data, key):
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    
    def rsa_encrypt(self, data):
        with open("keys/rsa_public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(public_key)
        return None, cipher.encrypt(data)
    
    def rsa_decrypt(self, data, _):
        with open("keys/rsa_private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(data)
    
    def perform_encryption(self):
        try:
            self.running_operation = True
            file_size = os.path.getsize(self.current_file)
            self.stats.add_operation('encrypt', file_size)
            
            with open(self.current_file, "rb") as f:
                data = f.read()
            
            algo = self.algo_var.get()
            if algo in self.crypto_algorithms:
                encrypt_fn, _ = self.crypto_algorithms[algo]
                key, encrypted_data = encrypt_fn(data)
                
                output_path = self.current_file + ".enc"
                with open(output_path, "wb") as f:
                    f.write(encrypted_data)
                
                if key:
                    self.save_key(key, "aes.key")
                
                self.log(f"✅ {algo} - Chiffrement réussi")
                messagebox.showinfo("Succès", "Chiffrement terminé")
        
        except Exception as e:
            self.log(f"❌ Erreur : {str(e)}")
            messagebox.showerror("Erreur", str(e))
        
        finally:
            self.running_operation = False
    
    def perform_decryption(self):
        try:
            self.running_operation = True
            file_size = os.path.getsize(self.current_file)
            self.stats.add_operation('decrypt', file_size)
            
            with open(self.current_file, "rb") as f:
                encrypted_data = f.read()
            
            algo = self.algo_var.get()
            if algo in self.crypto_algorithms:
                _, decrypt_fn = self.crypto_algorithms[algo]
                key = self.load_key("aes.key") if algo == "AES-256" else None
                decrypted_data = decrypt_fn(encrypted_data, key)
                
                output_path = self.current_file[:-4]
                with open(output_path, "wb") as f:
                    f.write(decrypted_data)
                
                self.log(f"✅ {algo} - Déchiffrement réussi")
                messagebox.showinfo("Succès", "Déchiffrement terminé")
        
        except Exception as e:
            self.log(f"❌ Erreur : {str(e)}")
            messagebox.showerror("Erreur", str(e))
        
        finally:
            self.running_operation = False
    
    def show_stats(self):
        stats_window = ctk.CTkToplevel(self)
        stats_window.title("Statistiques")
        stats_window.geometry("500x400")
        
        stats_frame = ctk.CTkFrame(stats_window)
        stats_frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        stats_data = [
            ("Chiffrements", self.stats.operations['encrypt']['count']),
            ("Déchiffrements", self.stats.operations['decrypt']['count']),
            ("Données chiffrées (MB)", round(self.stats.operations['encrypt']['total_size'] / 1e6, 2)),
            ("Données déchiffrées (MB)", round(self.stats.operations['decrypt']['total_size'] / 1e6, 2)),
            ("Dernière opération", self.stats.last_operation.strftime("%d/%m/%Y %H:%M") if self.stats.last_operation else "Aucune"),
            ("Temps écoulé", str(datetime.now() - self.stats.start_time).split('.')[0])
        ]
        
        for label, value in stats_data:
            row = ctk.CTkFrame(stats_frame)
            row.pack(fill="x", pady=5)
            
            ctk.CTkLabel(row, text=label, font=self.main_font).pack(side="left")
            ctk.CTkLabel(row, text=str(value), font=self.main_font).pack(side="right")
    
    def reset_stats(self):
        self.stats.reset()
        self.log("📊 Statistiques réinitialisées")
    
    def load_plugin(self):
        plugin_path = filedialog.askopenfilename(filetypes=[("Plugins Python", "*.py")])
        if plugin_path:
            threading.Thread(
                target=self.plugin_manager.load_plugin,
                args=(plugin_path,),
                daemon=True
            ).start()
    
    def save_key(self, key, filename):
        with open(f"keys/{filename}", 'wb') as f:
            f.write(key)
        self.log(f"🔑 Clé sauvegardée : keys/{filename}")
    
    def load_key(self, filename):
        with open(f"keys/{filename}", 'rb') as f:
            return f.read()
    
    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]")
        self.log_text.insert("end", f"{timestamp} {message}\n")
        self.log_text.see("end")

if __name__ == "__main__":
    if not os.path.exists('keys'):
        os.makedirs('keys')
    app = ModernCryptoApp()
    app.mainloop()