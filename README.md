# 🔍 ShadowTrace - Analyse Forensique d'Images Intelligente

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Status: Active](https://img.shields.io/badge/Status-Active-success.svg)]()

> **Outil CLI professionnel d'analyse forensique d'images combinant stéganalyse avancée et intelligence artificielle.**

---

## 📋 Table des Matières

1. [Introduction](#-introduction)
2. [Fonctionnalités](#-fonctionnalités)
3. [Installation](#-installation)
4. [Utilisation](#-utilisation)
5. [Méthodes d'Analyse](#-méthodes-danalyse)
6. [Analyse Intelligente (IA)](#-analyse-intelligente-ia)
7. [Formats de Sortie](#-formats-de-sortie)
8. [Architecture](#-architecture)
9. [Exemples](#-exemples)
10. [Philosophie Forensic](#-philosophie-forensic)
11. [Dépannage](#-dépannage)
12. [Roadmap](#-roadmap)

---

## 🎯 Introduction

**ShadowTrace** est un outil d'analyse forensique d'images en ligne de commande (CLI) conçu pour les professionnels de la cybersécurité et les analystes forensiques numériques.

### Objectifs Principaux

- ✅ Charger et valider une image fournie par l'utilisateur
- ✅ Effectuer un pré-traitement automatique de l'image
- ✅ Appliquer **7 méthodes de stéganalyse** différentes
- ✅ Tenter d'extraire des données cachées
- ✅ Détecter des indices de dissimulation
- ✅ **Analyser intelligemment avec IA (LLM + NLP)**
- ✅ Comparer et corréler les résultats
- ✅ Générer des rapports structurés (Terminal, JSON, PDF)

---

## ✨ Fonctionnalités

### Pipeline d'Analyse Complet
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
│  Analyse IA     │  ← LLM (Llama 3.1 405B) + NLP
│  (LLM + NLP)    │
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
| **8** | **🆕 Analyse IA** | **Analyse sémantique intelligente (LLM + NLP)** | **✅ Score + Recommandations** |

---

## 📦 Installation

### Prérequis

- **Python 3.8+**
- **Tesseract OCR** installé sur le système (optionnel)
- **pip** pour l'installation des dépendances
- **Connexion Internet** (pour l'analyse IA)

### 1. Cloner le projet
```bash
git clone https://github.com/votre-username/shadowtrace.git
cd shadowtrace
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

**Linux/Mac:**
```bash
source venv/bin/activate
```

### 4. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 5. Télécharger les modèles spaCy
```bash
# Modèle français
python -m spacy download fr_core_news_sm

# Modèle anglais
python -m spacy download en_core_web_sm
```

### 6. Installer Tesseract OCR (optionnel)

Télécharger et installer depuis: https://github.com/UB-Mannheim/tesseract/wiki

Par défaut, le script attend Tesseract dans:
```
C:\Program Files\Tesseract-OCR\tesseract.exe
```

### 7. Configuration de l'analyse IA

Créez un fichier `.env` à la racine du projet :
```bash
# Clé API OpenRouter (gratuit)
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxx
OPENROUTER_MODEL=meta-llama/llama-3.1-405b-instruct:free
LLM_PROVIDER=openrouter

# Informations app (optionnel)
OPENROUTER_APP_NAME=ShadowTrace
```

**Obtenir une clé API gratuite** : https://openrouter.ai/

---

## 🖥️ Utilisation

### Commande de Base
```bash
python decodeur.py --image <chemin_image>
```

### Options Disponibles

| Option | Court | Description | Obligatoire |
|--------|-------|-------------|-------------|
| `--image` | `-i` | Chemin vers l'image à analyser | ✅ Oui |
| `--output` | `-o` | Dossier de sortie pour les rapports | ❌ Non |
| `--verbose` | `-v` | Affichage détaillé des étapes | ❌ Non |
| `--pdf` | | Génération du rapport PDF | ❌ Non |

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

# Avec l'environnement virtuel
.\venv\Scripts\python.exe decodeur.py --image test_steno.png --verbose --pdf
```

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

## 🤖 Analyse Intelligente (IA)

### 8️⃣ Phase 2 : LLM + NLP

**Nouveau !** L'analyse intelligente combine :
- **LLM (Llama 3.1 405B)** : Analyse sémantique du texte extrait
- **NLP (spaCy)** : Structuration des résultats

**Pipeline :**
```
Textes extraits (OCR + LSB + EXIF)
         ↓
    LLM (Llama 3.1 405B)
         │
         ├─> Génère rapport en langage naturel
         ├─> Score de suspicion (0-100)
         ├─> Nature du contenu
         ├─> Recommandations
         └─> Indicateurs de risque
         ↓
    NLP (spaCy)
         │
         ├─> Extrait le score
         ├─> Structure les listes
         ├─> Extrait les entités
         └─> Normalise les données
         ↓
    JSON structuré
```

**Résultats IA :**
```json
{
  "intelligent_analysis": {
    "status": "success",
    "suspicion_score": 72,
    "danger_level": "medium",
    "nature": "suspicious",
    "summary": "Lettre professionnelle avec message LSB caché...",
    "intention": "Dissimulation de données sensibles...",
    "risk_indicators": [
      "Présence de stéganographie LSB active",
      "10 signatures binaires détectées"
    ],
    "recommendations": [
      "Analyser les fichiers EXE détectés",
      "Vérifier l'origine du message LSB"
    ],
    "entities": {
      "persons": ["Madame", "Monsieur"],
      "emails": [],
      "urls": []
    },
    "llm_metadata": {
      "model": "meta-llama/llama-3.1-405b-instruct:free",
      "tokens": 1192
    }
  }
}
```

**Niveaux de danger automatiques :**

| Score | Niveau | Interprétation |
|-------|--------|----------------|
| 0-29 | `low` | Contenu probablement anodin |
| 30-59 | `medium` | Suspicion modérée, investigation recommandée |
| 60-79 | `high` | Forte probabilité de contenu malveillant |
| 80-100 | `critical` | Menace critique, action immédiate |

**Coût :** 0€ (Llama 3.1 405B gratuit via OpenRouter)

---

## 📊 Formats de Sortie

### 1. Sortie Terminal
```
============================================================
 SHADOWTRACE - Analyse Forensique d'Images
============================================================
[+] Image analysée : test_steno.png
[+] Date : 2026-01-03 17:45:59

[ANALYSE] OCR - Détection de texte visible...
[ANALYSE] LSB - Stéganographie bit de poids faible...
...

============================================================
 PHASE 2 : ANALYSE INTELLIGENTE (LLM + NLP)
============================================================

[+] Textes collectés depuis : OCR (easyocr), Stéganographie LSB
[+] Longueur totale : 992 caractères

[LLM] Utilisation du modèle : meta-llama/llama-3.1-405b-instruct:free
[LLM] ✓ Réponse reçue (1192 tokens)

[NLP] ✓ Score extrait: 20/100
[NLP] ✓ Nature: professional
[NLP] ✓ Niveau de danger: low

============================================================
 RAPPORT D'ANALYSE FORENSIQUE
============================================================

[OCR]
  ✓ Texte détecté : OUI

[LSB]
  ✓ Message caché : OUI
    Message: Message cache : TEST FORENSIC...

[CONCLUSION]
============================================================
  Méthodes avec résultats : OCR, LSB, SIGNATURES
  Niveau de suspicion : MEDIUM
  ✓ Extraction directe : RÉUSSIE

============================================================
[ANALYSE INTELLIGENTE - LLM]
============================================================

  📊 Score de suspicion IA : 20/100
  🎯 Niveau de danger : LOW
  📝 Nature du contenu : professional

  Résumé :
    Lettre professionnelle avec message caché "TEST FORENSIC"...

  Recommandations :
    1. Analyser les fichiers EXE détectés
    2. Vérifier l'authenticité de la lettre

  Modèle utilisé : meta-llama/llama-3.1-405b-instruct:free
  Tokens consommés : 1192
```

### 2. Rapport JSON

Le rapport JSON contient toutes les données structurées incluant l'analyse IA :
```json
{
  "image": "test_steno.png",
  "analysis_date": "2026-01-03T11:49:12",
  "ocr": {...},
  "steganography": {...},
  "intelligent_analysis": {
    "status": "success",
    "suspicion_score": 20,
    "danger_level": "low",
    "recommendations": [...]
  },
  "summary": {...}
}
```

### 3. Rapport PDF

Le rapport PDF contient:
- **En-tête:** Titre, date, informations générales
- **Tableau des résultats:** 7 méthodes forensiques
- **Analyse Intelligente (LLM + NLP)** : Score, recommandations, résumé
- **Conclusion:** Niveau de suspicion
- **Footer:** Version et timestamp

---

## 🏗️ Architecture

### Structure du Projet
```
shadowtrace/
├── decodeur.py               # Script principal (Phase 1 + intégration)
├── llm_analyzer.py           # Module IA (Phase 2: LLM + NLP)
├── config.py                 # Configuration (mots-clés, modèles)
├── .env                      # Variables d'environnement (non versionné)
├── requirements.txt          # Dépendances
├── README.md                 # Documentation
└── reports/                  # Rapports générés
```

### Dépendances

**Phase 1 - Forensique :**
```
opencv-python    # Traitement d'image
numpy            # Calculs numériques
pillow           # Manipulation d'images + EXIF
piexif           # EXIF détaillé
colorama         # Couleurs terminal
stegano          # Stéganographie LSB
pytesseract      # OCR Tesseract
easyocr          # OCR deep learning
reportlab        # Génération PDF
```

**Phase 2 - Intelligence Artificielle :**
```
openai           # Client API (compatible OpenRouter)
python-dotenv    # Gestion variables d'environnement
spacy            # NLP (structuration)
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

[ANALYSE INTELLIGENTE - LLM]
  📊 Score IA : 45/100
  🎯 Danger : MEDIUM
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

6. **🆕 L'IA enrichit l'analyse mais ne remplace pas l'expert**
   - Le LLM fournit une interprétation intelligente
   - L'analyste conserve le contrôle final

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

### Erreur : Analyse IA échoue
```
[WARNING] Analyse intelligente échouée
```

**Solutions:**
1. Vérifier que `.env` existe et contient `OPENROUTER_API_KEY`
2. Vérifier la connexion Internet
3. Tester la clé : https://openrouter.ai/
4. Les résultats de Phase 1 restent disponibles

---

## 📄 Licence

MIT License - Libre d'utilisation, modification et distribution.

---

## 👥 Auteurs

Développé dans le cadre du projet **Digital Skills** - Cycle Ingénieur S1

- **Phase 1 (Forensique)** : [Nom du binôme]
- **Phase 2 (IA - LLM + NLP)** : [Votre nom]

---

## 🔮 Roadmap

- [x] **Phase 1:** Analyse forensique avec 7 méthodes
- [x] **Phase 2:** Intégration LLM pour analyse intelligente
- [x] **Phase 2:** NLP pour structuration des résultats
- [ ] **Phase 3:** API REST et interface web
- [ ] **Phase 4:** Base de données + Historique des analyses
- [ ] **Phase 5:** Dashboard de visualisation interactif

---

## 🤝 Contribution

Les contributions sont les bienvenues ! 

1. Fork le projet
2. Créer une branche (`git checkout -b feature/amazing-feature`)
3. Commit (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

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

## 📞 Contact

- GitHub : [@votre-username](https://github.com/votre-username)
- Projet : [ShadowTrace](https://github.com/votre-username/shadowtrace)

---

<p align="center">
  <i>Développé avec ❤️ pour la cybersécurité et l'analyse forensique</i>
</p>