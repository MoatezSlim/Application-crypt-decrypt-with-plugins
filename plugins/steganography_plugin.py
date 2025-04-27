# plugins/steganography_plugin.py
from PIL import Image
from tkinter import messagebox, simpledialog
import os

def encode_message_in_image(image_path, message, output_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    binary_msg = ''.join([format(ord(c), '08b') for c in message]) + '00000000'
    pixels = img.load()

    width, height = img.size
    idx = 0

    for y in range(height):
        for x in range(width):
            if idx >= len(binary_msg):
                img.save(output_path)
                return
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary_msg[idx])
            idx += 1
            if idx < len(binary_msg):
                g = (g & ~1) | int(binary_msg[idx])
                idx += 1
            if idx < len(binary_msg):
                b = (b & ~1) | int(binary_msg[idx])
                idx += 1
            pixels[x, y] = (r, g, b)
    img.save(output_path)

def decode_message_from_image(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    bits = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    msg = ''.join(chars)
    return msg.split('\x00', 1)[0]

def register(api):
    def hide_message():
        filepath = api.app.current_file
        if not filepath or not filepath.lower().endswith(".png"):
            messagebox.showerror("Erreur", "Veuillez sélectionner une image PNG.")
            return
        
        msg = simpledialog.askstring("Message secret", "Entrez le message à cacher :")
        if not msg:
            return
        
        try:
            output_path = filepath.replace(".png", "_hidden.png")
            encode_message_in_image(filepath, msg, output_path)
            api.log(f"✅ Message caché dans : {output_path}")
            messagebox.showinfo("Succès", f"Message caché dans : {output_path}")
        except Exception as e:
            api.log(f"❌ Erreur Steganography : {str(e)}")
            messagebox.showerror("Erreur", str(e))

    def reveal_message():
        filepath = api.app.current_file
        if not filepath or not filepath.lower().endswith(".png"):
            messagebox.showerror("Erreur", "Veuillez sélectionner une image PNG.")
            return
        
        try:
            secret = decode_message_from_image(filepath)
            api.log(f"✅ Message révélé : {secret}")
            messagebox.showinfo("Message secret", secret)
        except Exception as e:
            api.log(f"❌ Erreur extraction : {str(e)}")
            messagebox.showerror("Erreur", str(e))

    api.add_menu_item("🖼️ Cacher un message", hide_message)
    api.add_menu_item("🔍 Révéler le message", reveal_message)
    api.log("Plugin de stéganographie chargé avec succès")
