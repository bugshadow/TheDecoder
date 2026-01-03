#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Le Décodeur - Analyse Forensique d'Images (Phase 1)
====================================================
Outil CLI pour l'analyse forensique d'images avec détection de stéganographie,
OCR, analyse de métadonnées et génération de rapports.

Auteur: Forensic Analysis Tool
Version: 1.0.0
"""

import argparse
import os
import sys
import json
import re
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import cv2
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
from colorama import init, Fore, Style
from stegano import lsb
import pytesseract
import easyocr

from llm_analyzer import IntelligentForensicAnalyzer
LLM_AVAILABLE = True

# ReportLab pour PDF
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Initialiser colorama pour Windows
init(autoreset=True)

# Configuration Tesseract (adapter le chemin selon l'installation)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ============================================================================
# CONSTANTES
# ============================================================================

# Signatures binaires connues
BINARY_SIGNATURES = {
    'ZIP': b'PK\x03\x04',
    'ZIP_EMPTY': b'PK\x05\x06',
    'ZIP_SPANNED': b'PK\x07\x08',
    'PDF': b'%PDF',
    'PNG': b'\x89PNG\r\n\x1a\n',
    'JPEG': b'\xff\xd8\xff',
    'GIF87a': b'GIF87a',
    'GIF89a': b'GIF89a',
    'BMP': b'BM',
    'EXE_MZ': b'MZ',
    'RAR': b'Rar!\x1a\x07',
    '7Z': b'7z\xbc\xaf\x27\x1c',
    'GZIP': b'\x1f\x8b\x08',
    'TAR': b'ustar',
}

# Patterns pour la recherche de chaînes
STRING_PATTERNS = [
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'https?://[^\s<>"]+',
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    r'-----BEGIN .+-----',
    r'password[:\s=]+\S+',
    r'secret[:\s=]+\S+',
    r'key[:\s=]+[a-fA-F0-9]{16,}',
]

# ============================================================================
# CLASSES D'ANALYSE
# ============================================================================

class ForensicAnalyzer:
    """Classe principale pour l'analyse forensique d'images."""
    
    def __init__(self, image_path: str, verbose: bool = False):
        self.image_path = Path(image_path)
        self.verbose = verbose
        self.results: Dict[str, Any] = {
            'image': str(self.image_path.name),
            'image_path': str(self.image_path.absolute()),
            'analysis_date': datetime.now().isoformat(),
            'ocr': {},
            'steganography': {
                'lsb': None,
                'exif': {},
                'ascii_strings': [],
                'binary_signatures': [],
                'bit_plane_anomaly': False,
                'histogram_anomaly': False
            },
            'summary': {
                'extraction_success': False,
                'suspicion_level': 'low',
                'methods_with_findings': [],
                'total_findings': 0
            }
        }
        
        # Charger l'image
        self.cv_image = None
        self.pil_image = None
        self.raw_bytes = None
        self._load_image()
    
    def _load_image(self):
        """Charge l'image avec différentes bibliothèques."""
        if not self.image_path.exists():
            raise FileNotFoundError(f"Image non trouvée: {self.image_path}")
        
        # Charger avec OpenCV
        self.cv_image = cv2.imread(str(self.image_path))
        if self.cv_image is None:
            raise ValueError(f"Impossible de charger l'image: {self.image_path}")
        
        # Charger avec PIL
        self.pil_image = Image.open(self.image_path)
        
        # Lire les bytes bruts
        with open(self.image_path, 'rb') as f:
            self.raw_bytes = f.read()
        
        if self.verbose:
            print(f"{Fore.CYAN}[INFO] Image chargée: {self.image_path.name}")
            print(f"{Fore.CYAN}[INFO] Dimensions: {self.cv_image.shape}")
            print(f"{Fore.CYAN}[INFO] Taille: {len(self.raw_bytes)} bytes")
    
    def preprocess_image(self) -> np.ndarray:
        """Pré-traitement de l'image pour l'analyse."""
        gray = cv2.cvtColor(self.cv_image, cv2.COLOR_BGR2GRAY)
        
        # Normalisation
        normalized = cv2.normalize(gray, None, 0, 255, cv2.NORM_MINMAX)
        
        if self.verbose:
            print(f"{Fore.CYAN}[INFO] Pré-traitement effectué (grayscale + normalisation)")
        
        return normalized
    
    # ========================================================================
    # MÉTHODE 1: OCR (Tesseract + EasyOCR)
    # ========================================================================
    
    def analyze_ocr(self) -> Dict[str, Any]:
        """Extrait le texte visible avec OCR."""
        print(f"\n{Fore.YELLOW}[ANALYSE] OCR - Détection de texte visible...")
        
        gray = self.preprocess_image()
        ocr_results = {
            'tesseract': {'text': '', 'success': False},
            'easyocr': {'text': '', 'success': False}
        }
        
        # Tesseract OCR
        try:
            # Try English only first (French may not be installed)
            text_tesseract = pytesseract.image_to_string(gray, lang='eng')
            text_tesseract = text_tesseract.strip()
            ocr_results['tesseract'] = {
                'text': text_tesseract,
                'success': bool(text_tesseract)
            }
            if self.verbose:
                print(f"{Fore.CYAN}[TESSERACT] Texte détecté: {len(text_tesseract)} caractères")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[TESSERACT] Erreur: {e}")
        
        # EasyOCR
        try:
            reader = easyocr.Reader(['en', 'fr'], gpu=False, verbose=False)
            results = reader.readtext(gray, detail=0)
            text_easyocr = ' '.join(results).strip()
            ocr_results['easyocr'] = {
                'text': text_easyocr,
                'success': bool(text_easyocr)
            }
            if self.verbose:
                print(f"{Fore.CYAN}[EASYOCR] Texte détecté: {len(text_easyocr)} caractères")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[EASYOCR] Erreur: {e}")
        
        self.results['ocr'] = ocr_results
        return ocr_results
    
    # ========================================================================
    # MÉTHODE 2: LSB Steganography
    # ========================================================================
    
    def analyze_lsb(self) -> Optional[str]:
        """Tente d'extraire un message caché via LSB."""
        print(f"\n{Fore.YELLOW}[ANALYSE] LSB - Stéganographie bit de poids faible...")
        
        # LSB fonctionne mieux avec PNG/BMP
        if self.image_path.suffix.lower() not in ['.png', '.bmp']:
            if self.verbose:
                print(f"{Fore.CYAN}[LSB] Format non optimal ({self.image_path.suffix}), tentative quand même...")
        
        try:
            hidden_message = lsb.reveal(str(self.image_path))
            if hidden_message:
                self.results['steganography']['lsb'] = hidden_message
                self.results['summary']['extraction_success'] = True
                if self.verbose:
                    print(f"{Fore.GREEN}[LSB] Message extrait: {hidden_message[:100]}...")
                return hidden_message
            else:
                if self.verbose:
                    print(f"{Fore.CYAN}[LSB] Aucun message détecté")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.CYAN}[LSB] Pas de message LSB standard: {e}")
        
        return None
    
    # ========================================================================
    # MÉTHODE 3: Analyse EXIF
    # ========================================================================
    
    def analyze_exif(self) -> Dict[str, Any]:
        """Analyse les métadonnées EXIF."""
        print(f"\n{Fore.YELLOW}[ANALYSE] EXIF - Métadonnées de l'image...")
        
        exif_data = {
            'standard': {},
            'suspicious': [],
            'comments': [],
            'raw_tags': {}
        }
        
        # Extraction avec PIL
        try:
            pil_exif = self.pil_image._getexif()
            if pil_exif:
                for tag_id, value in pil_exif.items():
                    tag_name = TAGS.get(tag_id, f"Unknown_{tag_id}")
                    
                    # Convertir bytes en string si possible
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    
                    exif_data['raw_tags'][tag_name] = str(value)
                    
                    # Détecter les champs suspects
                    if tag_name in ['UserComment', 'ImageDescription', 'XPComment', 'XPTitle']:
                        if value and str(value).strip():
                            exif_data['comments'].append({
                                'field': tag_name,
                                'value': str(value)
                            })
                            exif_data['suspicious'].append(f"{tag_name}: {value}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.CYAN}[EXIF/PIL] {e}")
        
        # Extraction avec piexif pour plus de détails
        try:
            if self.image_path.suffix.lower() in ['.jpg', '.jpeg', '.tiff']:
                piexif_dict = piexif.load(str(self.image_path))
                for ifd in ['0th', '1st', 'Exif', 'GPS', 'Interop']:
                    if ifd in piexif_dict and piexif_dict[ifd]:
                        for tag, value in piexif_dict[ifd].items():
                            tag_name = piexif.TAGS[ifd].get(tag, {}).get('name', f'Unknown_{tag}')
                            if isinstance(value, bytes):
                                try:
                                    value = value.decode('utf-8', errors='ignore')
                                except:
                                    pass
                            exif_data['standard'][f"{ifd}:{tag_name}"] = str(value)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.CYAN}[EXIF/piexif] {e}")
        
        # Vérifier les commentaires PNG
        if self.image_path.suffix.lower() == '.png':
            try:
                if hasattr(self.pil_image, 'info') and self.pil_image.info:
                    for key, value in self.pil_image.info.items():
                        if key not in ['dpi', 'gamma']:
                            exif_data['comments'].append({
                                'field': f'PNG:{key}',
                                'value': str(value)
                            })
            except:
                pass
        
        self.results['steganography']['exif'] = exif_data
        
        if self.verbose:
            print(f"{Fore.CYAN}[EXIF] {len(exif_data['raw_tags'])} tags trouvés")
            print(f"{Fore.CYAN}[EXIF] {len(exif_data['suspicious'])} éléments suspects")
        
        return exif_data
    
    # ========================================================================
    # MÉTHODE 4: Recherche de chaînes ASCII
    # ========================================================================
    
    def analyze_strings(self) -> List[str]:
        """Recherche des chaînes ASCII suspectes dans les bytes."""
        print(f"\n{Fore.YELLOW}[ANALYSE] STRINGS - Recherche de chaînes ASCII...")
        
        found_strings = []
        
        # Extraire toutes les chaînes lisibles (min 4 caractères)
        ascii_pattern = re.compile(rb'[\x20-\x7e]{4,}')
        all_strings = ascii_pattern.findall(self.raw_bytes)
        
        # Chercher les patterns intéressants
        text_content = self.raw_bytes.decode('utf-8', errors='ignore')
        
        for pattern in STRING_PATTERNS:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            found_strings.extend(matches)
        
        # Chercher après la fin normale de l'image
        image_end_markers = {
            'jpeg': b'\xff\xd9',
            'png': b'IEND',
        }
        
        suffix = self.image_path.suffix.lower()
        if suffix in ['.jpg', '.jpeg']:
            marker = image_end_markers['jpeg']
        elif suffix == '.png':
            marker = image_end_markers['png']
        else:
            marker = None
        
        if marker:
            marker_pos = self.raw_bytes.rfind(marker)
            if marker_pos != -1 and marker_pos < len(self.raw_bytes) - len(marker) - 10:
                trailing_data = self.raw_bytes[marker_pos + len(marker):]
                try:
                    trailing_text = trailing_data.decode('utf-8', errors='ignore').strip()
                    if trailing_text and len(trailing_text) > 3:
                        found_strings.append(f"[TRAILING DATA] {trailing_text[:200]}")
                except:
                    pass
        
        # Dédupliquer
        found_strings = list(set(found_strings))
        
        self.results['steganography']['ascii_strings'] = found_strings
        
        if self.verbose:
            print(f"{Fore.CYAN}[STRINGS] {len(all_strings)} chaînes brutes, {len(found_strings)} patterns suspects")
        
        return found_strings
    
    # ========================================================================
    # MÉTHODE 5: Détection de signatures binaires
    # ========================================================================
    
    def detect_signatures(self) -> List[Dict[str, Any]]:
        """Détecte la présence de fichiers cachés via leurs signatures."""
        print(f"\n{Fore.YELLOW}[ANALYSE] SIGNATURES - Détection de fichiers cachés...")
        
        found_signatures = []
        
        # Ignorer la signature de l'image elle-même
        image_type = None
        if self.raw_bytes[:4] == b'\x89PNG':
            image_type = 'PNG'
        elif self.raw_bytes[:2] == b'\xff\xd8':
            image_type = 'JPEG'
        
        for sig_name, sig_bytes in BINARY_SIGNATURES.items():
            # Chercher à partir d'un offset (pas au début pour éviter l'image elle-même)
            offset = 0 if sig_name != image_type else 100
            
            pos = self.raw_bytes.find(sig_bytes, offset)
            while pos != -1:
                # Vérifier que ce n'est pas au tout début (signature légitime)
                if pos > 50 or sig_name != image_type:
                    found_signatures.append({
                        'type': sig_name,
                        'offset': pos,
                        'hex_offset': hex(pos)
                    })
                pos = self.raw_bytes.find(sig_bytes, pos + 1)
        
        self.results['steganography']['binary_signatures'] = found_signatures
        
        if self.verbose:
            print(f"{Fore.CYAN}[SIGNATURES] {len(found_signatures)} signatures détectées")
        
        return found_signatures
    
    # ========================================================================
    # MÉTHODE 6: Analyse des bit-planes
    # ========================================================================
    
    def analyze_bitplanes(self) -> Tuple[bool, Optional[np.ndarray]]:
        """Analyse les plans de bits pour détecter des anomalies."""
        print(f"\n{Fore.YELLOW}[ANALYSE] BIT-PLANES - Analyse des bits faibles...")
        
        gray = cv2.cvtColor(self.cv_image, cv2.COLOR_BGR2GRAY)
        
        # Extraire le LSB plane
        lsb_plane = gray & 1
        lsb_plane = lsb_plane * 255  # Amplifier pour visualisation
        
        # Calculer l'entropie du plan LSB
        hist = cv2.calcHist([lsb_plane], [0], None, [256], [0, 256])
        hist = hist / hist.sum()
        hist = hist[hist > 0]
        entropy = -np.sum(hist * np.log2(hist))
        
        # Une image naturelle a généralement une entropie LSB < 0.9
        # Une image avec stéganographie a souvent une entropie proche de 1.0
        anomaly_detected = entropy > 0.95
        
        # Analyser la distribution des pixels LSB
        lsb_ratio = np.mean(lsb_plane) / 255
        # Si le ratio est très proche de 0.5, c'est suspect (données aléatoires)
        ratio_suspicious = 0.48 < lsb_ratio < 0.52
        
        self.results['steganography']['bit_plane_anomaly'] = anomaly_detected or ratio_suspicious
        self.results['steganography']['bit_plane_details'] = {
            'lsb_entropy': float(entropy),
            'lsb_ratio': float(lsb_ratio),
            'anomaly_entropy': anomaly_detected,
            'anomaly_ratio': ratio_suspicious
        }
        
        if self.verbose:
            print(f"{Fore.CYAN}[BIT-PLANES] Entropie LSB: {entropy:.4f}")
            print(f"{Fore.CYAN}[BIT-PLANES] Ratio LSB: {lsb_ratio:.4f}")
            print(f"{Fore.CYAN}[BIT-PLANES] Anomalie: {'OUI' if anomaly_detected or ratio_suspicious else 'NON'}")
        
        return anomaly_detected or ratio_suspicious, lsb_plane
    
    # ========================================================================
    # MÉTHODE 7: Analyse statistique (histogrammes)
    # ========================================================================
    
    def analyze_histogram(self) -> Tuple[bool, Dict[str, Any]]:
        """Analyse statistique des histogrammes."""
        print(f"\n{Fore.YELLOW}[ANALYSE] HISTOGRAMME - Analyse statistique...")
        
        # Histogramme par canal
        channels = cv2.split(self.cv_image)
        channel_names = ['Blue', 'Green', 'Red']
        
        stats = {}
        anomalies = []
        
        for i, (channel, name) in enumerate(zip(channels, channel_names)):
            hist = cv2.calcHist([channel], [0], None, [256], [0, 256]).flatten()
            
            # Statistiques
            mean = np.mean(channel)
            std = np.std(channel)
            
            # Détecter les pics anormaux (indicateurs de manipulation)
            peaks = np.where(hist > np.mean(hist) * 5)[0]
            
            # Détecter les "gaps" (valeurs manquantes consécutives)
            zero_runs = []
            current_run = 0
            for val in hist:
                if val == 0:
                    current_run += 1
                else:
                    if current_run > 5:
                        zero_runs.append(current_run)
                    current_run = 0
            
            stats[name] = {
                'mean': float(mean),
                'std': float(std),
                'peaks': peaks.tolist()[:10],
                'zero_gaps': len(zero_runs)
            }
            
            # Anomalie si trop de peaks ou de gaps
            if len(peaks) > 20 or len(zero_runs) > 10:
                anomalies.append(name)
        
        histogram_anomaly = len(anomalies) > 0
        
        self.results['steganography']['histogram_anomaly'] = histogram_anomaly
        self.results['steganography']['histogram_details'] = {
            'channel_stats': stats,
            'anomalous_channels': anomalies
        }
        
        if self.verbose:
            print(f"{Fore.CYAN}[HISTOGRAM] Canaux analysés: {len(channel_names)}")
            print(f"{Fore.CYAN}[HISTOGRAM] Anomalies: {anomalies if anomalies else 'Aucune'}")
        
        return histogram_anomaly, stats
    
    # ========================================================================
    # COMPARAISON & CORRÉLATION
    # ========================================================================
    
    def correlate_results(self):
        """Corrèle les résultats et calcule le niveau de suspicion."""
        print(f"\n{Fore.YELLOW}[CORRÉLATION] Analyse des résultats...")
        
        findings = []
        
        # OCR
        ocr = self.results['ocr']
        if ocr.get('tesseract', {}).get('success') or ocr.get('easyocr', {}).get('success'):
            findings.append('OCR')
        
        # LSB
        if self.results['steganography']['lsb']:
            findings.append('LSB')
        
        # EXIF
        exif = self.results['steganography']['exif']
        if exif.get('suspicious') or exif.get('comments'):
            findings.append('EXIF')
        
        # Strings
        if self.results['steganography']['ascii_strings']:
            findings.append('STRINGS')
        
        # Signatures
        if self.results['steganography']['binary_signatures']:
            findings.append('SIGNATURES')
        
        # Bit-planes
        if self.results['steganography']['bit_plane_anomaly']:
            findings.append('BIT-PLANES')
        
        # Histogram
        if self.results['steganography']['histogram_anomaly']:
            findings.append('HISTOGRAM')
        
        # Calculer le niveau de suspicion
        total = len(findings)
        if total == 0:
            level = 'none'
        elif total <= 2:
            level = 'low'
        elif total <= 4:
            level = 'medium'
        else:
            level = 'high'
        
        self.results['summary']['methods_with_findings'] = findings
        self.results['summary']['total_findings'] = total
        self.results['summary']['suspicion_level'] = level
        
        # Extraction réussie si LSB a trouvé quelque chose
        self.results['summary']['extraction_success'] = bool(self.results['steganography']['lsb'])
    
    # ========================================================================
    # EXÉCUTION COMPLÈTE
    # ========================================================================
    
    def run_all_analyses(self):
        """Exécute toutes les analyses."""
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.WHITE}{Style.BRIGHT} LE DÉCODEUR - Analyse Forensique d'Images")
        print(f"{Fore.WHITE}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.CYAN}[+] Image analysée : {self.image_path.name}")
        print(f"{Fore.CYAN}[+] Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Exécuter chaque analyse
        self.analyze_ocr()
        self.analyze_lsb()
        self.analyze_exif()
        self.analyze_strings()
        self.detect_signatures()
        self.analyze_bitplanes()
        self.analyze_histogram()
        
        # Corréler les résultats
        self.correlate_results()

        # Analyse intelligente (LLM + NLP)
        if LLM_AVAILABLE:
            try:
                print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
                print(f"{Fore.WHITE}{Style.BRIGHT} PHASE 2 : ANALYSE INTELLIGENTE (LLM + NLP)")
                print(f"{Fore.WHITE}{Style.BRIGHT}{'='*60}")
                
                llm_analyzer = IntelligentForensicAnalyzer()
                intelligent_results = llm_analyzer.analyze_forensic_data(self.results)
                
                # Ajouter les résultats au dictionnaire principal
                self.results['intelligent_analysis'] = intelligent_results
                
                # Afficher un résumé dans le terminal
                if intelligent_results.get('status') == 'success':
                    print(f"\n{Fore.GREEN}[+] Analyse intelligente complétée :")
                    print(f"  📊 Score de suspicion : {intelligent_results['suspicion_score']}/100")
                    print(f"  ⚠️  Niveau de danger : {intelligent_results['danger_level'].upper()}")
                    print(f"  📝 Nature : {intelligent_results['nature']}")
                
            except Exception as e:
                print(f"\n{Fore.YELLOW}[WARNING] Analyse intelligente échouée : {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                print(f"{Fore.CYAN}[INFO] Les résultats de base restent disponibles.")
        
        return self.results


# ============================================================================
# GÉNÉRATION DES RAPPORTS
# ============================================================================

def print_terminal_report(results: Dict[str, Any]):
    """Affiche le rapport dans le terminal."""
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT} RAPPORT D'ANALYSE FORENSIQUE")
    print(f"{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    
    print(f"\n{Fore.GREEN}[+] Image analysée : {results['image']}")
    
    # OCR
    print(f"\n{Fore.YELLOW}[OCR]")
    ocr = results['ocr']
    tesseract_ok = ocr.get('tesseract', {}).get('success', False)
    easyocr_ok = ocr.get('easyocr', {}).get('success', False)
    if tesseract_ok or easyocr_ok:
        print(f"  {Fore.GREEN}✓ Texte détecté : OUI")
        if tesseract_ok:
            text = ocr['tesseract']['text'][:100]
            print(f"    Tesseract: {text}...")
    else:
        print(f"  {Fore.WHITE}○ Texte détecté : NON")
    
    # LSB
    print(f"\n{Fore.YELLOW}[LSB]")
    lsb_result = results['steganography']['lsb']
    if lsb_result:
        print(f"  {Fore.GREEN}✓ Message caché : OUI")
        print(f"    Message: {lsb_result[:100]}...")
    else:
        print(f"  {Fore.WHITE}○ Message caché : NON")
    
    # EXIF
    print(f"\n{Fore.YELLOW}[EXIF]")
    exif = results['steganography']['exif']
    if exif.get('suspicious') or exif.get('comments'):
        print(f"  {Fore.GREEN}✓ Métadonnées suspectes : OUI")
        for item in exif.get('suspicious', [])[:3]:
            print(f"    {item}")
    else:
        print(f"  {Fore.WHITE}○ Métadonnées suspectes : NON")
    
    # STRINGS
    print(f"\n{Fore.YELLOW}[STRINGS]")
    strings = results['steganography']['ascii_strings']
    if strings:
        print(f"  {Fore.GREEN}✓ Chaînes détectées : {len(strings)}")
        for s in strings[:5]:
            print(f"    {s[:80]}")
    else:
        print(f"  {Fore.WHITE}○ Chaînes détectées : 0")
    
    # SIGNATURES
    print(f"\n{Fore.YELLOW}[SIGNATURES]")
    sigs = results['steganography']['binary_signatures']
    if sigs:
        print(f"  {Fore.RED}✓ Fichiers cachés : OUI")
        for sig in sigs[:5]:
            print(f"    {sig['type']} @ offset {sig['hex_offset']}")
    else:
        print(f"  {Fore.WHITE}○ Archive/Fichier caché : NON")
    
    # BIT-PLANES
    print(f"\n{Fore.YELLOW}[BIT-PLANES]")
    if results['steganography']['bit_plane_anomaly']:
        print(f"  {Fore.RED}✓ Anomalies détectées : OUI")
        details = results['steganography'].get('bit_plane_details', {})
        print(f"    Entropie: {details.get('lsb_entropy', 0):.4f}")
    else:
        print(f"  {Fore.WHITE}○ Anomalies détectées : NON")
    
    # HISTOGRAM
    print(f"\n{Fore.YELLOW}[HISTOGRAM]")
    if results['steganography']['histogram_anomaly']:
        print(f"  {Fore.RED}✓ Anomalies statistiques : OUI")
    else:
        print(f"  {Fore.WHITE}○ Anomalies statistiques : NON")
    
    # CONCLUSION
    print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT}[CONCLUSION]")
    print(f"{Fore.WHITE}{Style.BRIGHT}{'='*60}")
    
    summary = results['summary']
    level = summary['suspicion_level']
    
    level_colors = {
        'none': Fore.GREEN,
        'low': Fore.GREEN,
        'medium': Fore.YELLOW,
        'high': Fore.RED
    }
    level_color = level_colors.get(level, Fore.WHITE)
    
    print(f"  Méthodes avec résultats : {', '.join(summary['methods_with_findings']) or 'Aucune'}")
    print(f"  Niveau de suspicion : {level_color}{level.upper()}")
    
    if summary['extraction_success']:
        print(f"  {Fore.GREEN}✓ Extraction directe : RÉUSSIE")
    else:
        print(f"  {Fore.YELLOW}○ Extraction directe : NON CONFIRMÉE")
    
    if level in ['medium', 'high']:
        print(f"\n  {Fore.YELLOW}⚠ Plusieurs indices de dissimulation détectés.")
        print(f"  {Fore.YELLOW}  Une analyse approfondie est recommandée.")

    # Section Analyse Intelligente
    if 'intelligent_analysis' in results:
        ia = results['intelligent_analysis']
        
        if ia.get('status') == 'success':
            print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
            print(f"{Fore.WHITE}{Style.BRIGHT}[ANALYSE INTELLIGENTE - LLM]")
            print(f"{Fore.WHITE}{Style.BRIGHT}{'='*60}")
            
            # Score et niveau
            score = ia['suspicion_score']
            danger = ia['danger_level']
            
            danger_colors = {
                'low': Fore.GREEN,
                'medium': Fore.YELLOW,
                'high': Fore.RED,
                'critical': Fore.RED + Style.BRIGHT
            }
            danger_color = danger_colors.get(danger, Fore.WHITE)
            
            print(f"\n  📊 Score de suspicion IA : {danger_color}{score}/100{Style.RESET_ALL}")
            print(f"  🎯 Niveau de danger : {danger_color}{danger.upper()}{Style.RESET_ALL}")
            print(f"  📝 Nature du contenu : {ia['nature']}")
            
            # Résumé
            if ia['summary']:
                print(f"\n  {Fore.CYAN}Résumé :{Style.RESET_ALL}")
                print(f"    {ia['summary'][:200]}...")
            
            # Recommandations
            if ia['recommendations']:
                print(f"\n  {Fore.YELLOW}Recommandations :{Style.RESET_ALL}")
                for i, rec in enumerate(ia['recommendations'][:3], 1):
                    print(f"    {i}. {rec}")
            
            # Indicateurs de risque
            if ia['risk_indicators']:
                print(f"\n  {Fore.RED}Indicateurs de risque :{Style.RESET_ALL}")
                for indicator in ia['risk_indicators'][:3]:
                    print(f"    • {indicator}")
            
            # Métadonnées
            meta = ia.get('llm_metadata', {})
            print(f"\n  {Fore.CYAN}Modèle utilisé :{Style.RESET_ALL} {meta.get('model', 'Unknown')}")
            print(f"  {Fore.CYAN}Tokens consommés :{Style.RESET_ALL} {meta.get('tokens', 0)}")


def json_serializer(obj):
    """Custom JSON serializer for numpy types."""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def generate_json_report(results: Dict[str, Any], output_path: Path):
    """Génère le rapport JSON."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=json_serializer)
    print(f"\n{Fore.GREEN}[+] Rapport JSON généré : {output_path}")


def generate_pdf_report(results: Dict[str, Any], output_path: Path, image_path: Path):
    """Génère le rapport PDF avec ReportLab."""
    print(f"\n{Fore.CYAN}[INFO] Génération du rapport PDF...")
    
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )
    
    styles = getSampleStyleSheet()
    
    # Styles personnalisés
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#1a1a2e'),
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor('#16213e'),
        borderPadding=5,
        backColor=colors.HexColor('#e8e8e8')
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    elements = []
    
    # Titre
    elements.append(Paragraph("LE DÉCODEUR", title_style))
    elements.append(Paragraph("Rapport d'Analyse Forensique d'Images", styles['Heading3']))
    elements.append(Spacer(1, 20))
    
    # Informations générales
    elements.append(Paragraph("Informations Générales", heading_style))
    
    info_data = [
        ['Image analysée:', results['image']],
        ['Chemin:', results['image_path']],
        ['Date d\'analyse:', results['analysis_date']],
    ]
    
    info_table = Table(info_data, colWidths=[4*cm, 12*cm])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 20))
    
    # Résultats d'analyse
    elements.append(Paragraph("Résultats d'Analyse", heading_style))
    
    # Tableau des résultats
    steg = results['steganography']
    ocr = results['ocr']
    
    def get_status(condition):
        return "✓ OUI" if condition else "○ NON"
    
    results_data = [
        ['Méthode', 'Résultat', 'Détails'],
        ['OCR (Tesseract)', get_status(ocr.get('tesseract', {}).get('success')), 
         ocr.get('tesseract', {}).get('text', '')[:50] or '-'],
        ['OCR (EasyOCR)', get_status(ocr.get('easyocr', {}).get('success')),
         ocr.get('easyocr', {}).get('text', '')[:50] or '-'],
        ['LSB Stéganographie', get_status(steg['lsb']), 
         (steg['lsb'] or '-')[:50]],
        ['Métadonnées EXIF', get_status(steg['exif'].get('suspicious')),
         str(len(steg['exif'].get('suspicious', []))) + ' éléments suspects'],
        ['Chaînes ASCII', get_status(steg['ascii_strings']),
         str(len(steg['ascii_strings'])) + ' chaînes trouvées'],
        ['Signatures binaires', get_status(steg['binary_signatures']),
         str(len(steg['binary_signatures'])) + ' signatures'],
        ['Anomalies bit-planes', get_status(steg['bit_plane_anomaly']),
         f"Entropie: {steg.get('bit_plane_details', {}).get('lsb_entropy', 0):.3f}"],
        ['Anomalies histogramme', get_status(steg['histogram_anomaly']),
         ', '.join(steg.get('histogram_details', {}).get('anomalous_channels', [])) or '-'],
    ]
    
    results_table = Table(results_data, colWidths=[5*cm, 3*cm, 8*cm])
    results_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
    ]))
    elements.append(results_table)
    elements.append(Spacer(1, 30))
    
    # Conclusion
    elements.append(Paragraph("Conclusion", heading_style))
    
    summary = results['summary']
    level = summary['suspicion_level']
    level_colors_map = {
        'none': '#28a745',
        'low': '#28a745', 
        'medium': '#ffc107',
        'high': '#dc3545'
    }
    
    conclusion_text = f"""
    <b>Niveau de suspicion:</b> <font color="{level_colors_map.get(level, '#000')}">{level.upper()}</font><br/>
    <b>Méthodes avec résultats:</b> {', '.join(summary['methods_with_findings']) or 'Aucune'}<br/>
    <b>Nombre total de découvertes:</b> {summary['total_findings']}<br/>
    <b>Extraction directe:</b> {'Réussie' if summary['extraction_success'] else 'Non confirmée'}
    """
    elements.append(Paragraph(conclusion_text, normal_style))
    
    if level in ['medium', 'high']:
        warning_style = ParagraphStyle(
            'Warning',
            parent=normal_style,
            textColor=colors.HexColor('#856404'),
            backColor=colors.HexColor('#fff3cd'),
            borderPadding=10
        )
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            "⚠ Plusieurs indices de dissimulation détectés. Une analyse approfondie est recommandée.",
            warning_style
        ))

    # Section Analyse Intelligente
    if 'intelligent_analysis' in results:
        ia = results['intelligent_analysis']
        
        if ia.get('status') == 'success':
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("Analyse Intelligente (LLM + NLP)", heading_style))
            
            # Tableau résumé IA
            ia_data = [
                ['Métrique', 'Valeur'],
                ['Score de suspicion IA', f"{ia['suspicion_score']}/100"],
                ['Niveau de danger', ia['danger_level'].upper()],
                ['Nature du contenu', ia['nature']],
                ['Modèle LLM', ia.get('llm_metadata', {}).get('model', 'Unknown')],
                ['Tokens utilisés', str(ia.get('llm_metadata', {}).get('tokens', 0))],
            ]
            
            ia_table = Table(ia_data, colWidths=[5*cm, 11*cm])
            ia_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ]))
            elements.append(ia_table)
            
            # Résumé IA
            if ia['summary']:
                elements.append(Spacer(1, 10))
                elements.append(Paragraph("<b>Résumé de l'analyse :</b>", normal_style))
                elements.append(Paragraph(ia['summary'], normal_style))
            
            # Recommandations
            if ia['recommendations']:
                elements.append(Spacer(1, 10))
                elements.append(Paragraph("<b>Recommandations :</b>", normal_style))
                for i, rec in enumerate(ia['recommendations'], 1):
                    elements.append(Paragraph(f"{i}. {rec}", normal_style))
    
    # Footer
    elements.append(Spacer(1, 40))
    footer_style = ParagraphStyle(
        'Footer',
        parent=normal_style,
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    elements.append(Paragraph(
        f"Le Décodeur - Analyse Forensique d'Images v1.0 | Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        footer_style
    ))
    
    # Générer le PDF
    doc.build(elements)
    print(f"{Fore.GREEN}[+] Rapport PDF généré : {output_path}")


# ============================================================================
# POINT D'ENTRÉE CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Le Décodeur - Analyse Forensique d\'Images (Phase 1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples:
  python decodeur.py --image photo.png
  python decodeur.py --image photo.png --verbose
  python decodeur.py --image photo.png --output ./reports --pdf
        '''
    )
    
    parser.add_argument(
        '--image', '-i',
        type=str,
        required=True,
        help='Chemin vers l\'image à analyser (obligatoire)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='Dossier de sortie pour les rapports (optionnel)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Affichage détaillé des étapes'
    )
    
    parser.add_argument(
        '--pdf',
        action='store_true',
        help='Générer un rapport PDF en plus du JSON'
    )
    
    args = parser.parse_args()
    
    # Vérifier que l'image existe
    image_path = Path(args.image)
    if not image_path.exists():
        print(f"{Fore.RED}[ERREUR] Image non trouvée: {args.image}")
        sys.exit(1)
    
    # Créer le dossier de sortie si spécifié
    if args.output:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = image_path.parent
    
    try:
        # Exécuter l'analyse
        analyzer = ForensicAnalyzer(str(image_path), verbose=args.verbose)
        results = analyzer.run_all_analyses()
        
        # Afficher le rapport terminal
        print_terminal_report(results)
        
        # Générer le rapport JSON
        json_path = output_dir / f"{image_path.stem}_forensic_report.json"
        generate_json_report(results, json_path)
        
        # Générer le rapport PDF si demandé
        if args.pdf:
            pdf_path = output_dir / f"{image_path.stem}_forensic_report.pdf"
            generate_pdf_report(results, pdf_path, image_path)
        
        print(f"\n{Fore.GREEN}[+] Analyse terminée avec succès!")
        
    except Exception as e:
        print(f"{Fore.RED}[ERREUR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
