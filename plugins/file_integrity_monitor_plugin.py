import hashlib
import os
import time
from tkinter import messagebox
from tkinter import simpledialog
import threading

class FileIntegrityMonitor:
    def __init__(self):
        self.files_to_monitor = {}
        self.check_interval = 10  # Time in seconds between checks

    def add_file(self, file_path):
        """Add a file to the monitoring list with its initial hash"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_hash = self.hash_file(file_path)
        self.files_to_monitor[file_path] = file_hash
        return file_hash

    def hash_file(self, file_path):
        """Hash a file using SHA-256"""
        hash_func = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def check_integrity(self):
        """Check the integrity of all monitored files"""
        for file_path, original_hash in list(self.files_to_monitor.items()):
            if not os.path.exists(file_path):
                messagebox.showwarning("File Missing", f"The file {file_path} has been deleted.")
                self.files_to_monitor.pop(file_path)
                continue

            current_hash = self.hash_file(file_path)
            if current_hash != original_hash:
                self.handle_file_change(file_path)
                # Update the file hash after handling the change
                self.files_to_monitor[file_path] = current_hash

    def handle_file_change(self, file_path):
        """Handle file modification: Alert user and optionally re-encrypt"""
        messagebox.showwarning("File Integrity Alert", f"File '{file_path}' has been modified!")

        # Ask user if they want to re-encrypt the file
        response = messagebox.askyesno("Re-encrypt?", f"Do you want to re-encrypt the modified file '{file_path}'?")
        if response:
            self.re_encrypt_file(file_path)

    def re_encrypt_file(self, file_path):
        """Re-encrypt the modified file using AES encryption (could be customized as per the app's existing logic)"""
        password = simpledialog.askstring("Encryption Password", f"Enter the password to re-encrypt {file_path}:")
        if password:
            # Use your existing encryption function or create one that works with the app's encryption logic
            try:
                # For demonstration purposes, this can be any encryption function you'd like to use.
                self.encrypt_file(file_path, password)
                messagebox.showinfo("Re-encryption", f"File {file_path} has been re-encrypted successfully.")
            except Exception as e:
                messagebox.showerror("Re-encryption Error", f"Failed to re-encrypt {file_path}: {str(e)}")

    def encrypt_file(self, file_path, password):
        """Encrypt the file using a simple AES encryption (placeholder for actual implementation)"""
        # You would replace this with your AES encryption logic.
        pass

def register(api):
    """Register the File Integrity Monitoring plugin with the main app"""
    def start_monitoring():
        # Run the monitoring function in a separate thread so the app doesn't freeze
        monitoring_thread = threading.Thread(target=monitor_files, daemon=True)
        monitoring_thread.start()

    def monitor_files():
        """Monitor files in a separate thread"""
        monitor = FileIntegrityMonitor()
        
        # Add files to monitor (this can be dynamically added via a menu item or dialog)
        try:
            file_path = api.app.current_file  # Get the selected file
            monitor.add_file(file_path)
        except FileNotFoundError as e:
            messagebox.showerror("Error", str(e))

        # Run the integrity check at regular intervals
        while True:
            monitor.check_integrity()
            time.sleep(monitor.check_interval)

    api.add_menu_item("🔒 Démarrer la surveillance de l'intégrité des fichiers", start_monitoring)
    api.log("Plugin de surveillance de l'intégrité des fichiers chargé")
