import importlib.util
import os
import hashlib
import inspect
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import logging
import customtkinter as ctk

class SecurityError(Exception):
    pass

class PluginAPI:
    def __init__(self, app):
        self.app = app
        self.lock = Lock()
        self.logger = logging.getLogger('PluginAPI')
    
    def add_menu_item(self, text, command):
        with self.lock:
            btn = ctk.CTkButton(self.app.sidebar, text=text, command=command, anchor="w", font=self.app.main_font)
            btn.pack(fill="x", pady=2)
    
    def register_algorithm(self, name, encrypt_fn, decrypt_fn):
        with self.lock:
            self.app.crypto_algorithms[name] = (encrypt_fn, decrypt_fn)
            self.app.log(f"Algorithme {name} chargé")

    def log(self, message, level='info'):
        self.app.log(f"[Plugin] {message}")

class PluginManager:
    def __init__(self, app):
        self.app = app
        self.api = PluginAPI(app)
    
    def load_plugin(self, plugin_path):
        try:
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            plugin_module.register(self.api)
        except Exception as e:
            self.api.log(f"Erreur : {str(e)}", 'error')

if __name__ == "__main__":
    pass