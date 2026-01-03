import cv2
import pytesseract
import easyocr
from stegano import lsb
from PIL import Image
import os

# Configuration Tesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Vérifier que l'image source existe
if not os.path.exists("test.jpg"):
    print("Erreur : test.jpg n'existe pas!")
    exit()

# Convertir en PNG pour la stéganographie (recommandé)
try:
    img_pil = Image.open("test.jpg")
    img_pil.save("test.png")
    print("✓ Image convertie en PNG")
except Exception as e:
    print(f"Erreur conversion : {e}")
    exit()

# Cacher le message
try:
    secret = "Message cache : TEST FORENSIC"
    lsb.hide("test.png", secret).save("test_steno.png")
    print("✓ Message caché avec succès")
except Exception as e:
    print(f"Erreur lors du cachage : {e}")
    exit()

# Charger l'image stéganographiée
image_path = "test_steno.png"
img = cv2.imread(image_path)

if img is None:
    print("Erreur : impossible de charger l'image stéganographiée")
    exit()

# Pré-traitement
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

# OCR Tesseract
print("\n=== TESSERACT ===")
try:
    text_tesseract = pytesseract.image_to_string(gray, lang="eng")
    print(text_tesseract if text_tesseract.strip() else "Aucun texte détecté")
except Exception as e:
    print(f"Erreur Tesseract : {e}")

# OCR EasyOCR
print("\n=== EASYOCR ===")
try:
    reader = easyocr.Reader(['en', 'fr'], gpu=False)
    results = reader.readtext(gray, detail=0)
    text_easyocr = " ".join(results)
    print(text_easyocr if text_easyocr.strip() else "Aucun texte détecté")
except Exception as e:
    print(f"Erreur EasyOCR : {e}")

# Steganography (LSB)
print("\n=== STEGANOGRAPHY ===")
try:
    hidden_text = lsb.reveal(image_path)
    print(hidden_text if hidden_text else "Aucun message caché trouvé")
except Exception as e:
    print(f"Erreur lors de la révélation : {e}")