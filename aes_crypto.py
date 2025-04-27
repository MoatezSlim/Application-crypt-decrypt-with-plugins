from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def generer_cle_aes():
    """Génère une clé AES-256 aléatoire"""
    return get_random_bytes(32)

def chiffrer_aes(fichier_entree, fichier_sortie, cle):
    """Chiffre un fichier avec AES-CBC"""
    try:
        iv = get_random_bytes(16)
        cipher = AES.new(cle, AES.MODE_CBC, iv)
        
        with open(fichier_entree, 'rb') as f_in:
            donnees = f_in.read()
        
        # Padding PKCS7
        pad = AES.block_size - (len(donnees) % AES.block_size)
        donnees += bytes([pad]) * pad
        
        with open(fichier_sortie, 'wb') as f_out:
            f_out.write(iv + cipher.encrypt(donnees))
        
        return True
    except Exception as e:
        raise Exception(f"Erreur chiffrement AES: {str(e)}")

def dechiffrer_aes(fichier_entree, fichier_sortie, cle):
    """Déchiffre un fichier AES"""
    try:
        with open(fichier_entree, 'rb') as f_in:
            iv = f_in.read(16)
            donnees_chiffrees = f_in.read()
        
        cipher = AES.new(cle, AES.MODE_CBC, iv)
        donnees = cipher.decrypt(donnees_chiffrees)
        
        # Suppression du padding
        pad = donnees[-1]
        donnees = donnees[:-pad]
        
        with open(fichier_sortie, 'wb') as f_out:
            f_out.write(donnees)
        
        return True
    except Exception as e:
        raise Exception(f"Erreur déchiffrement AES: {str(e)}")