# 🔍 Le Décodeur - Analyse Forensique d'Images

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Phase: 1](https://img.shields.io/badge/Phase-1-orange.svg)]()

> **Outil CLI professionnel pour l'analyse forensique d'images avec détection de stéganographie, OCR, et analyse de métadonnées.**

---

## 📋 Table des Matières

1. [Introduction](#-introduction)
2. [Fonctionnalités](#-fonctionnalités)
3. [Installation](#-installation)
4. [Utilisation](#-utilisation)
5. [Méthodes d'Analyse](#-méthodes-danalyse)
6. [Formats de Sortie](#-formats-de-sortie)
7. [Architecture](#-architecture)
8. [Exemples](#-exemples)
9. [Philosophie Forensic](#-philosophie-forensic)
10. [Dépannage](#-dépannage)

---

## 🎯 Introduction

**Le Décodeur** est un outil d'analyse forensique d'images en ligne de commande (CLI) conçu pour les professionnels de la cybersécurité et les analystes forensiques numériques.

### Objectifs Principaux

- ✅ Charger et valider une image fournie par l'utilisateur
- ✅ Effectuer un pré-traitement automatique de l'image
- ✅ Appliquer **7 méthodes de stéganalyse** différentes
- ✅ Tenter d'extraire des données cachées
- ✅ Détecter des indices de dissimulation
- ✅ Comparer et corréler les résultats
- ✅ Générer des rapports structurés (Terminal, JSON, PDF)

### Ce que cet outil N'est PAS (Phase 1)

- ❌ Pas d'intégration LLM (Gemini, OpenAI, Ollama)
- ❌ Pas de NLP (spaCy, NER, résumé)
- ❌ Pas d'API web
- ❌ Pas d'interface graphique

---

## ✨ Fonctionnalités

### Pipeline d'Analyse

```
┌─────────────────┐
│   Image (input) │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Pré-traitement │  ← OpenCV (grayscale, normalisation)
└────────┬────────┘
         ▼
┌─────────────────┐
│   OCR (texte)   │  ← Tesseract + EasyOCR
└────────┬────────┘
         ▼
┌─────────────────┐
│   Stéganalyse   │  ← 7 méthodes différentes
│  multi-méthodes │
└────────┬────────┘
         ▼
┌─────────────────┐
│   Corrélation   │  ← Comparaison des résultats
└────────┬────────┘
         ▼
┌─────────────────┐
│    Rapports     │  ← Terminal + JSON + PDF
└─────────────────┘
```

### Méthodes Implémentées

| # | Méthode | Description | Extraction |
|---|---------|-------------|------------|
| 1 | **OCR** | Détection de texte visible (Tesseract + EasyOCR) | ✅ Oui |
| 2 | **LSB** | Stéganographie Least Significant Bit | ✅ Oui |
| 3 | **EXIF** | Analyse des métadonnées (commentaires, tags suspects) | ⚠️ Partielle |
| 4 | **Strings** | Recherche de chaînes ASCII (URLs, flags, clés) | ✅ Oui |
| 5 | **Signatures** | Détection de fichiers cachés (ZIP, PDF, EXE) | ⚠️ Détection |
| 6 | **Bit-planes** | Analyse des plans de bits faibles (entropie LSB) | ⚠️ Détection |
| 7 | **Histogramme** | Analyse statistique des canaux couleur | ⚠️ Détection |

---

## 📦 Installation

### Prérequis

- **Python 3.8+**
- **Tesseract OCR** installé sur le système
- **pip** pour l'installation des dépendances

### 1. Cloner ou télécharger le projet

```bash
cd "c:\Users\bouha\OneDrive\Dokumente\Cycle Ingenieur\S1\Digital skills\Project Fin module"
```

### 2. Créer un environnement virtuel

```bash
python -m venv venv
```

### 3. Activer l'environnement virtuel

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
.\venv\Scripts\activate.bat
```

### 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5. Installer Tesseract OCR

Télécharger et installer depuis: https://github.com/UB-Mannheim/tesseract/wiki

Par défaut, le script attend Tesseract dans:
```
C:\Program Files\Tesseract-OCR\tesseract.exe
```

---

## 🖥️ Utilisation

### 1. Interface Web (Streamlit)
L'interface graphique moderne permet une utilisation simplifiée via le navigateur.

```bash
# Lancer l'application web
streamlit run streamlit_app.py
```
*L'application sera accessible sur `http://localhost:8501`*

### 2. Interface Ligne de Commande (CLI)
Pour les experts préférant le terminal :

```bash
python decodeur.py --image <chemin_image>
```

### Options Disponibles

| Option | Court | Description | Obligatoire |
|--------|-------|-------------|-------------|
| `--image` | `-i` | Chemin vers l'image à analyser | ✅ Oui |
| `--output` | `-o` | Dossier de sortie pour les rapports | ❌ Non |
| `--verbose` | `-v` | Affichage détaillé des étapes | ❌ Non |
| `--pdf` | | Génération du rapport PDF détaillé | ❌ Non |
| `--docs` | `-d` | Afficher la documentation complète | ❌ Non |

### Exemples de Commandes

```bash
# Analyse simple
python decodeur.py --image photo.png

# Analyse avec détails
python decodeur.py --image photo.png --verbose

# Analyse avec rapport PDF
python decodeur.py --image photo.png --pdf

# Analyse complète avec sortie personnalisée
python decodeur.py --image photo.png --output ./reports --verbose --pdf

# Afficher la documentation complète
python decodeur.py --docs

# Ou le raccourci
python decodeur.py -d

# Avec l'environnement virtuel (Windows PowerShell)
.\venv\Scripts\python.exe decodeur.py --image test_steno.png --verbose --pdf
```

### 📖 Documentation Interactive

Pour obtenir la documentation complète du programme directement dans le terminal, utilisez:

```bash
# Commande longue
python decodeur.py --docs

# Raccourci
python decodeur.py -d
```

Cela affichera un guide complet incluant:
- 📋 Description détaillée de l'outil
- 🔍 Toutes les méthodes d'analyse disponibles
- 📊 Types de résultats générés (JSON, PDF, Terminal)
- 💡 Exemples d'utilisation détaillés
- ⚠️ Explications des niveaux de suspicion (NONE, LOW, MEDIUM, HIGH)
- 📦 Dépendances principales requises
- 🧠 Capacités d'analyse IA/LLM avec recommandations
- 🔧 Configuration recommandée

---

## 🔬 Méthodes d'Analyse

### 1️⃣ OCR - Reconnaissance de Caractères

**Objectif:** Extraire le texte visible dans l'image.

**Technologies:**
- **Tesseract OCR** - Moteur OCR open-source de Google
- **EasyOCR** - Bibliothèque OCR basée sur l'apprentissage profond

**Résultat attendu:**
```json
{
  "tesseract": {"text": "...", "success": true/false},
  "easyocr": {"text": "...", "success": true/false}
}
```

**Pourquoi deux moteurs?** Chaque moteur a ses forces - Tesseract excelle sur le texte imprimé standard, EasyOCR gère mieux les polices variées et les langues multiples.

---

### 2️⃣ LSB - Least Significant Bit

**Objectif:** Extraire un message caché encodé dans les bits de poids faible.

**Bibliothèque:** `stegano` (module `lsb`)

**Formats supportés:** PNG, BMP (sans perte de compression)

**Principe:**
```
Pixel original: 11001010 (202)
Bit caché:               1
Pixel modifié: 11001011 (203)
```

La différence est imperceptible à l'œil humain mais permet de stocker 1 bit par pixel.

**Résultat attendu:**
```json
{
  "lsb": "Message secret découvert" // ou null si rien trouvé
}
```

---

### 3️⃣ EXIF - Métadonnées

**Objectif:** Détecter des données cachées dans les métadonnées de l'image.

**Champs analysés:**
- `UserComment` - Commentaires utilisateur
- `ImageDescription` - Description de l'image
- `XPComment` - Commentaires Windows
- `XPTitle` - Titre Windows
- Commentaires PNG (champs `tEXt`, `iTXt`)

**Bibliothèques:** `Pillow` + `piexif`

**Résultat attendu:**
```json
{
  "exif": {
    "standard": {...},
    "suspicious": ["UserComment: SECRET_DATA"],
    "comments": [{"field": "...", "value": "..."}],
    "raw_tags": {...}
  }
}
```

---

### 4️⃣ Strings - Chaînes ASCII

**Objectif:** Détecter du texte brut injecté dans les octets de l'image.

**Patterns recherchés:**
| Pattern | Description | Exemple |
|---------|-------------|---------|
| `FLAG{...}` | Flags CTF | `FLAG{s3cr3t_fl4g}` |
| `CTF{...}` | Flags CTF alternatif | `CTF{hidden}` |
| URLs | Liens web | `https://example.com` |
| Emails | Adresses email | `secret@domain.com` |
| Clés PEM | Certificats | `-----BEGIN RSA-----` |
| Mots-clés | Password/Secret/Key | `password: xyz123` |

**Données trailing:** L'outil détecte également les données ajoutées après la fin normale de l'image (après `IEND` pour PNG ou `\xff\xd9` pour JPEG).

---

### 5️⃣ Signatures Binaires

**Objectif:** Repérer des fichiers cachés concaténés à l'image.

**Signatures détectées:**

| Type | Signature (hex) | Description |
|------|-----------------|-------------|
| ZIP | `50 4B 03 04` | Archive ZIP |
| PDF | `25 50 44 46` | Document PDF |
| PNG | `89 50 4E 47` | Image PNG |
| JPEG | `FF D8 FF` | Image JPEG |
| GIF | `47 49 46 38` | Image GIF |
| BMP | `42 4D` | Image Bitmap |
| EXE | `4D 5A` | Exécutable Windows |
| RAR | `52 61 72 21` | Archive RAR |
| 7Z | `37 7A BC AF` | Archive 7-Zip |
| GZIP | `1F 8B 08` | Fichier compressé |

**Note:** La signature de l'image elle-même est ignorée (au début du fichier).

---

### 6️⃣ Bit-Planes Analysis

**Objectif:** Détecter des anomalies statistiques dans les bits faibles.

**Métriques calculées:**

1. **Entropie LSB:**
   - Image naturelle: `< 0.9`
   - Image avec stéganographie: `≈ 1.0` (données aléatoires)

2. **Ratio LSB:**
   - Normal: distribution variable
   - Suspect: ratio proche de `0.5` (données aléatoires)

**Indicateurs d'anomalie:**
- `anomaly_entropy`: Entropie > 0.95
- `anomaly_ratio`: Ratio entre 0.48 et 0.52

---

### 7️⃣ Analyse Histogramme

**Objectif:** Repérer des manipulations via l'analyse statistique des couleurs.

**Métriques par canal (R, G, B):**
- **Moyenne** et **écart-type** des valeurs
- **Pics anormaux** (valeurs > 5× la moyenne)
- **Gaps** (séquences de valeurs manquantes)

**Indicateurs de manipulation:**
- Plus de 20 pics anormaux
- Plus de 10 gaps consécutifs

---

## 📊 Formats de Sortie

### 1. Sortie Terminal

```
============================================================
 LE DÉCODEUR - Analyse Forensique d'Images
============================================================
[+] Image analysée : test_steno.png
[+] Date : 2026-01-03 11:55:59

[ANALYSE] OCR - Détection de texte visible...
[ANALYSE] LSB - Stéganographie bit de poids faible...
...

============================================================
 RAPPORT D'ANALYSE FORENSIQUE
============================================================

[OCR]
  ✓ Texte détecté : OUI

[LSB]
  ✓ Message caché : OUI
    Message: Message cache : TEST FORENSIC...

...

[CONCLUSION]
============================================================
  Méthodes avec résultats : OCR, LSB, SIGNATURES
  Niveau de suspicion : MEDIUM
  ✓ Extraction directe : RÉUSSIE
```

### 2. Rapport JSON

Le rapport JSON contient toutes les données structurées:

```json
{
  "image": "test_steno.png",
  "image_path": "C:\\...\\test_steno.png",
  "analysis_date": "2026-01-03T11:49:12.638272",
  "ocr": {
    "tesseract": {"text": "...", "success": true},
    "easyocr": {"text": "...", "success": true}
  },
  "steganography": {
    "lsb": "Message cache : TEST FORENSIC",
    "exif": {...},
    "ascii_strings": [],
    "binary_signatures": [...],
    "bit_plane_anomaly": false,
    "histogram_anomaly": false,
    "bit_plane_details": {...},
    "histogram_details": {...}
  },
  "summary": {
    "extraction_success": true,
    "suspicion_level": "medium",
    "methods_with_findings": ["OCR", "LSB", "SIGNATURES"],
    "total_findings": 3
  }
}
```

### 3. Rapport PDF

Le rapport PDF contient:
- **En-tête:** Titre, date, informations générales
- **Tableau des résultats:** 9 méthodes forensiques (incluant bit-planes et histogramme)
- **Analyse Intelligente (LLM + NLP)** : Score détaillé, patterns détectés, recommandations complètes
  - 📊 Score de suspicion IA (0-100)
  - 🎯 Niveau de danger (NONE, LOW, MEDIUM, HIGH)
  - 📝 Nature du contenu identifiée
  - 📋 Résumé détaillé de l'analyse
  - 🔍 Analyse détaillée des patterns
  - ✅ Recommandations d'investigation
  - 🔧 Métadonnées du modèle LLM
- **Conclusion:** Niveau de suspicion global
- **Footer:** Version et timestamp

Générer un PDF:
```bash
python decodeur.py --image photo.png --pdf --verbose
```

---

## 📖 Utilisation de l'Environnement Virtuel (venv)

### Pourquoi utiliser venv?

L'environnement virtuel `venv` isole les dépendances du projet:
- ✅ Évite les conflits de versions avec d'autres projets
- ✅ Facilite la collaboration entre développeurs  
- ✅ Reproduction fiable des analyses
- ✅ Sécurité et maintenabilité

### Configuration rapide

**Windows (PowerShell):**
```powershell
# Créer le venv
python -m venv venv

# Activer
.\venv\Scripts\Activate.ps1

# Installer les dépendances
pip install -r requirements.txt

# Utiliser l'outil
python decodeur.py --image photo.png --pdf

# Afficher la documentation
python decodeur.py --docs
```

**Windows (CMD):**
```cmd
python -m venv venv
.\venv\Scripts\activate.bat
pip install -r requirements.txt
python decodeur.py --image photo.png --pdf
```

**Linux/Mac:**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python decodeur.py --image photo.png --pdf
```

---

## 🏗️ Architecture

### Structure du Code

```
decodeur.py
│
├── CONSTANTES
│   ├── BINARY_SIGNATURES      # Signatures de fichiers connus
│   └── STRING_PATTERNS        # Patterns regex à rechercher
│
├── ForensicAnalyzer (classe)
│   ├── __init__()             # Initialisation, chargement image
│   ├── _load_image()          # Chargement multi-format
│   ├── preprocess_image()     # Pré-traitement OpenCV
│   ├── analyze_ocr()          # Méthode 1: OCR
│   ├── analyze_lsb()          # Méthode 2: LSB
│   ├── analyze_exif()         # Méthode 3: EXIF
│   ├── analyze_strings()      # Méthode 4: Strings
│   ├── detect_signatures()    # Méthode 5: Signatures
│   ├── analyze_bitplanes()    # Méthode 6: Bit-planes
│   ├── analyze_histogram()    # Méthode 7: Histogramme
│   ├── correlate_results()    # Corrélation finale
│   └── run_all_analyses()     # Exécution pipeline
│
├── RAPPORTS
│   ├── print_terminal_report()    # Affichage console
│   ├── generate_json_report()     # Export JSON
│   └── generate_pdf_report()      # Export PDF (ReportLab)
│
└── main()                     # Point d'entrée CLI
```

### Dépendances

```
opencv-python    # Traitement d'image
numpy            # Calculs numériques
pillow           # Manipulation d'images + EXIF
piexif           # EXIF détaillé (JPEG/TIFF)
colorama         # Couleurs terminal (Windows)
stegano          # Stéganographie LSB
pytesseract      # OCR Tesseract
easyocr          # OCR deep learning
reportlab        # Génération PDF
```

---

## 📝 Exemples

### Exemple 1: Analyser une image simple

```bash
python decodeur.py --image photo.jpg
```

### Exemple 2: Image avec message LSB caché

```bash
python decodeur.py --image secret.png --verbose
```

**Sortie attendue:**
```
[LSB]
  ✓ Message caché : OUI
    Message: Mon message secret...
```

### Exemple 3: Générer tous les rapports

```bash
python decodeur.py --image suspect.png --output ./forensic_reports --verbose --pdf
```

**Fichiers générés:**
- `./forensic_reports/suspect_forensic_report.json`
- `./forensic_reports/suspect_forensic_report.pdf`

---

## 🧠 Philosophie Forensic

### Principes Respectés

1. **Une seule méthode n'est jamais suffisante**
   - L'outil applique 7 méthodes différentes pour une analyse complète

2. **Chaque technique fournit un indice**
   - Même un résultat négatif est informatif

3. **Les résultats négatifs sont informatifs**
   - L'absence de données cachées est aussi une information

4. **L'image analysée ne doit jamais être modifiée**
   - L'outil est **read-only** - aucune modification de l'image source

5. **L'outil ne conclut jamais seul**
   - Il fournit des indices et un niveau de suspicion
   - L'analyste humain prend la décision finale

### Niveaux de Suspicion

| Niveau | Critère | Interprétation |
|--------|---------|----------------|
| `none` | 0 méthodes positives | Image probablement normale |
| `low` | 1-2 méthodes positives | Faible probabilité de dissimulation |
| `medium` | 3-4 méthodes positives | Investigation approfondie recommandée |
| `high` | 5+ méthodes positives | Forte probabilité de données cachées |

---

## 🔧 Dépannage

### Erreur: Tesseract non trouvé

```
pytesseract.pytesseract.TesseractNotFoundError
```

**Solution:** Modifier le chemin dans `decodeur.py` ligne 45:
```python
pytesseract.pytesseract.tesseract_cmd = r'C:\Votre\Chemin\tesseract.exe'
```

### Erreur: Module non trouvé

```
ModuleNotFoundError: No module named 'xxx'
```

**Solution:**
```bash
pip install xxx
```

### Warning: pin_memory

```
UserWarning: 'pin_memory' argument is set as true but no accelerator is found
```

**Solution:** Ce warning est normal sans GPU. EasyOCR fonctionne quand même sur CPU.

### Performances lentes avec EasyOCR

EasyOCR charge des modèles de deep learning (~100MB). La première exécution télécharge les modèles.

**Solutions:**
- Utiliser `--verbose` pour voir la progression
- Les exécutions suivantes seront plus rapides (modèles en cache)

---

## 📄 Licence

MIT License - Libre d'utilisation, modification et distribution.

---

## 👥 Auteurs

Développé dans le cadre du projet **Digital Skills** - Cycle Ingénieur S1

- **Phase 1 (Forensique)** : Omar Bouhaddach
- **Phase 2 (IA - LLM + NLP)** : Douha 

---

## 🔮 Roadmap

- [x] **Phase 1:** Analyse forensique avec 7 méthodes
- [x] **Phase 2:** Intégration LLM pour analyse intelligente
- [x] **Phase 2:** NLP pour structuration des résultats
- [x] **Phase 3:** API REST et interface web
- [x] **Phase 5:** Dashboard de visualisation interactif

---




## 📥 Téléchargement depuis GitHub

Pour récupérer ce projet sur votre machine :

### Option 1 : Via Git (Recommandé)
```bash
# Clone le dépôt
git clone https://github.com/votre-username/shadowtrace.git

# Entrer dans le dossier
cd shadowtrace
```

### Option 2 : Via ZIP
1. Aller sur la page GitHub du projet
2. Cliquer sur le bouton vert **Code**
3. Sélectionner **Download ZIP**
4. Extraire l'archive
5. Ouvrir un terminal dans le dossier extrait


---

## ⚠️ Avertissement

Cet outil est destiné à un **usage éthique et légal uniquement**.

- ✅ Analyse forensique légitime
- ✅ Recherche en cybersécurité
- ✅ Formation et éducation
- ❌ Utilisation malveillante
- ❌ Violation de la vie privée

Toujours obtenir les autorisations nécessaires avant d'analyser des images.

---



---

<p align="center">
  <i>Développé avec ❤️ pour la cybersécurité et l'analyse forensique</i>
</p>
