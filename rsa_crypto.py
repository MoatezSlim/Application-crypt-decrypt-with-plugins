from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def generer_paires_cles():
    """Génère des clés RSA 2048 bits"""
    try:
        cle = RSA.generate(2048)
        privee = cle.export_key()
        publique = cle.publickey().export_key()
        return privee, publique
    except Exception as e:
        raise Exception(f"Erreur génération clés RSA: {str(e)}")

def chiffrer_rsa(fichier_entree, fichier_sortie, cle_publique):
    """Chiffre un fichier avec RSA"""
    try:
        cipher = PKCS1_OAEP.new(RSA.import_key(cle_publique))
        
        with open(fichier_entree, 'rb') as f_in, open(fichier_sortie, 'wb') as f_out:
            while chunk := f_in.read(190):  # Taille max pour RSA 2048
                f_out.write(cipher.encrypt(chunk))
        return True
    except Exception as e:
        raise Exception(f"Erreur chiffrement RSA: {str(e)}")

def dechiffrer_rsa(fichier_entree, fichier_sortie, cle_privee):
    """Déchiffre un fichier RSA"""
    try:
        cipher = PKCS1_OAEP.new(RSA.import_key(cle_privee))
        
        with open(fichier_entree, 'rb') as f_in, open(fichier_sortie, 'wb') as f_out:
            while chunk := f_in.read(256):  # Taille bloc chiffré
                f_out.write(cipher.decrypt(chunk))
        return True
    except Exception as e:
        raise Exception(f"Erreur déchiffrement RSA: {str(e)}")