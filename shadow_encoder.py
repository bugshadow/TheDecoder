#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadow Encoder - Outil de test pour Le Décodeur
===============================================
Permet de cacher des messages dans une image pour tester les méthodes de détection.
"""

import os
import cv2
import numpy as np
from PIL import Image
import piexif
from stegano import lsb
from pathlib import Path
from colorama import init, Fore, Style

# Initialiser colorama
init(autoreset=True)

def encode_image(input_path, output_path, message, hidden_text_ocr="SECRET_OCR_123"):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- SHADOW ENCODER : GÉNÉRATION DE L'IMAGE DE TEST ---")
    
    input_path = Path(input_path)
    output_path = Path(output_path)
    
    if not input_path.exists():
        print(f"{Fore.RED}[!] Fichier d'entrée introuvable : {input_path}")
        return

    # 1. MÉTHODE OCR : Inscrire du texte sur l'image (subtil)
    print(f"{Fore.YELLOW}[+] Ajout de texte OCR...")
    img = cv2.imread(str(input_path))
    font = cv2.FONT_HERSHEY_SIMPLEX
    # Texte un peu transparent ou discret (couleur proche du fond ou petite taille)
    cv2.putText(img, hidden_text_ocr, (10, 30), font, 1, (200, 200, 200), 2, cv2.LINE_AA)
    cv2.imwrite("temp_ocr.png", img)

    # 2. MÉTHODE LSB : Cacher le message dans les pixels
    print(f"{Fore.YELLOW}[+] Encodage LSB (Stéganographie)...")
    secret_img = lsb.hide("temp_ocr.png", message)
    secret_img.save(str(output_path))
    os.remove("temp_ocr.png")

    # 3. MÉTHODE EXIF : Ajouter des métadonnées suspectes
    print(f"{Fore.YELLOW}[+] Ajout de métadonnées EXIF...")
    try:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
        exif_dict["Exif"][piexif.ExifIFD.UserComment] = f"HiddenExif:{message}".encode('utf-8')
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = "Nothing to see here...".encode('utf-8')
        exif_bytes = piexif.dump(exif_dict)
        piexif.insert(exif_bytes, str(output_path))
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur EXIF (Possible si l'image n'est pas JPEG/TIFF) : {e}")

    # 4. MÉTHODE STRINGS & SIGNATURES : Append en fin de fichier
    print(f"{Fore.YELLOW}[+] Ajout de chaînes ASCII et signatures binaires en fin de fichier...")
    with open(output_path, 'ab') as f:
        # Signature ZIP fictive pour tester detect_signatures
        f.write(b'\x50\x4B\x03\x04') 
        # Chaîne ASCII suspecte pour tester analyze_strings
        f.write(f"\nFLAG{{TEST_STENO_SUCCESS}}\n".encode('utf-8'))
        f.write(f"password=supersecret123\n".encode('utf-8'))
        f.write(f"TRAILING_DATA:{message}\n".encode('utf-8'))

    print(f"\n{Fore.GREEN}{Style.BRIGHT}[SUCCESS] Image de test générée : {output_path}")
    print(f"{Fore.CYAN}Méthodes incluses : OCR, LSB, EXIF, STRINGS, SIGNATURES")

if __name__ == "__main__":
    INPUT = "test.png"
    OUTPUT = "test_encoded.png"
    MSG = "Ceci est un message secret pour LE DECODEUR"
    
    encode_image(INPUT, OUTPUT, MSG)
