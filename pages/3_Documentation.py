import streamlit as st
import utils
import os

st.set_page_config(page_title="Documentation - ShadowTrace", page_icon="📚", layout="wide")

utils.load_css()

st.markdown("# 📚 Documentation Technique & Guide Utilisateur")
st.markdown("### ShadowTrace: Plateforme d'Analyse Forensique Avancée")

st.markdown("---")

# Navigation rapide
st.markdown("""
<div style="background-color: #262730; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
    <strong>Navigation Rapide :</strong> &nbsp;
    <a href="#architecture-du-syst-me" style="text-decoration:none; color:#00CCFF;">Architecture</a> &nbsp;|&nbsp;
    <a href="#m-thodes-d-analyse-d-taill-es" style="text-decoration:none; color:#00CCFF;">Méthodes d'Analyse</a> &nbsp;|&nbsp;
    <a href="#installation-configuration" style="text-decoration:none; color:#00CCFF;">Installation</a> &nbsp;|&nbsp;
    <a href="#guide-d-utilisation" style="text-decoration:none; color:#00CCFF;">Utilisation</a> &nbsp;|&nbsp;
    <a href="#d-pannage-faq" style="text-decoration:none; color:#00CCFF;">Dépannage</a>
</div>
""", unsafe_allow_html=True)

# 1. Architecture
st.markdown("## 🏗️ Architecture du Système")
st.markdown("ShadowTrace repose sur une architecture modulaire combinant analyse de bas niveau et intelligence artificielle.")

st.markdown("### Pipeline de Traitement")
st.markdown("""
Le flux de données suit un processus rigoureux en deux phases :
1.  **Phase Forensique (Extraction)** : Analyse technique de l'image (pixels, bits, métadonnées).
2.  **Phase Intelligente (Interprétation)** : Analyse sémantique des résultats par LLM.
""")

# Diagramme Mermaid
utils.mermaid("""
graph TD
    A[Image Suspecte] --> B(Pré-traitement OpenCV);
    B --> C{Moteur d'Analyse};
    
    subgraph Phase 1: Extraction Forensique
    C --> D[OCR<br>Tesseract + EasyOCR];
    C --> E[Stéganalyse<br>LSB & Bit-Planes];
    C --> F[Métadonnées<br>EXIF & Strings];
    C --> G[File Carving<br>Signatures Binaires];
    C --> H[Statistiques<br>Histogrammes];
    end
    
    D --> I[Résultats Bruts];
    E --> I;
    F --> I;
    G --> I;
    H --> I;
    
    I --> J{Corrélation};
    J --> K[Score de Suspicion];
    
    subgraph Phase 2: Intelligence Artificielle
    I --> L[Prompt Engineering];
    L --> M[LLM Llama 3.1];
    M --> N[NLP Structuration];
    end
    
    N --> O[Rapport Final];
    K --> O;
""", height=600)


st.markdown("---")

# 2. Méthodes d'Analyse
st.markdown("## 🔍 Méthodes d'Analyse Détaillées")
st.info("Chaque module fonctionne de manière indépendante pour garantir la robustesse des résultats.")

with st.expander("1. Stéganographie LSB (Least Significant Bit)", expanded=True):
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        **Principe Technique :**
        La stéganographie LSB remplace le bit le moins significatif de chaque octet de couleur par un bit du message secret.
        
        **Exemple Binaire :**
        - Pixel Original (Rouge) : `1011010`**`0`** (180)
        - Bit à cacher : **`1`**
        - Pixel Modifié : `1011010`**`1`** (181)
        
        L'œil humain ne peut pas distinguer la différence entre la valeur 180 et 181.
        
        **Détection par ShadowTrace :**
        L'outil calcule l'entropie de Shannon sur le plan binaire 0.
        - **Entropie < 0.9** : Image naturelle probable.
        - **Entropie ≈ 1.0** : Bruit aléatoire suspect (signe de chiffrement ou compression).
        """)
    with col2:
        st.markdown("#### Représentation Visuelle")
        st.code("""
        [Plan 7 (MSB)] 1101... (Visible)
        [Plan 6]       0100...
        ...
        [Plan 1]       1010...
        [Plan 0 (LSB)] 1011... (Données?)
        """, language="text")

with st.expander("2. OCR (Reconnaissance Optique de Caractères)"):
    st.markdown("""
    **Double Moteur de Détection :**
    Nous utilisons une approche hybride pour maximiser le taux de détection.
    
    | Moteur | Technologie | Forces |
    |--------|-------------|--------|
    | **Tesseract** | LSTM (Réseau de neurones récurrents) | Excellent pour les documents scannés et polices standards. |
    | **EasyOCR** | Deep Learning (ResNet + LSTM) | Capable de lire du texte dans des scènes naturelles, sous rotation ou avec bruit. |
    
    **Cas d'usage :**
    - Détection de mots de passe écrits sur des post-its dans une photo.
    - Extraction de texte caché en couleur très claire sur fond blanc.
    """)

with st.expander("3. Analyse des Signatures (File Carving)"):
    st.markdown("""
    **Technique :**
    Le File Carving consiste à rechercher des en-têtes de fichiers (Magic Bytes) à l'intérieur de l'image.
    
    **Signatures Détectées :**
    - `PK` (`50 4B 03 04`) : Archives ZIP, fichiers Office (DOCX, XLSX), APK.
    - `%PDF` (`25 50 44 46`) : Documents PDF.
    - `MZ` (`4D 5A`) : Exécutables Windows (EXE, DLL).
    - `RAR`, `7Z`, `GZIP` : Archives compressées.
    
    **Scénario d'attaque détecté :**
    Un attaquant concatène une archive ZIP à la fin d'une image PNG (`cat image.png virus.zip > evil.png`). L'image reste affichable, mais contient le virus.
    """)

with st.expander("4. Métadonnées EXIF & Strings"):
    st.markdown("""
    **Analyse EXIF :**
    Extraction des métadonnées standards (GPS, Date) et recherche de champs détournés (`UserComment`, `ImageDescription`) souvent utilisés pour stocker des payloads en Base64.
    
    **Analyse Strings (Chaînes) :**
    Extraction brute des chaînes ASCII et Unicode avec filtrage par expressions régulières (Regex).
    - **Patterns recherchés :** Emails, URLs, Adresses IP, Flags CTF (`FLAG{...}`), Clés privées RSA (`-----BEGIN...`).
    """)

st.markdown("---")

# 3. Installation
st.markdown("## 📥 Installation & Configuration")

tab_install, tab_env = st.tabs(["Installation Standard", "Configuration .env"])

with tab_install:
    st.markdown("""
    ### Prérequis
    - Python 3.8 ou supérieur
    - Git
    - Connexion Internet (pour le téléchargement des modèles)

    ### Pas à pas
    ```bash
    # 1. Cloner le dépôt
    git clone https://github.com/votre-username/shadowtrace.git
    cd shadowtrace

    # 2. Créer un environnement virtuel (Recommandé)
    python -m venv venv
    
    # 3. Activer l'environnement
    # Windows :
    .\venv\Scripts\Activate.ps1
    # Mac/Linux :
    source venv/bin/activate

    # 4. Installer les dépendances
    pip install -r requirements.txt
    
    # 5. Télécharger les modèles NLP
    python -m spacy download fr_core_news_sm
    python -m spacy download en_core_web_sm
    ```
    """)

with tab_env:
    st.markdown("""
    ### Configuration API (IA)
    Pour activer l'analyse intelligente, créez un fichier `.env` à la racine :
    
    ```properties
    # .env
    LLM_PROVIDER=openrouter
    OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxx
    OPENROUTER_MODEL=meta-llama/llama-3.1-405b-instruct:free
    ```
    
    **Note :** Sans clé API, l'outil fonctionnera en mode "Forensique Standard" (Phase 1 uniquement) sans interprétation sémantique.
    """)

st.markdown("---")

# 4. Guide d'utilisation
st.markdown("## 🖥️ Guide d'Utilisation")

col_web, col_cli = st.columns(2)

with col_web:
    st.markdown("### 🌐 Interface Web (Streamlit)")
    st.markdown("Idéale pour les démonstrations et l'analyse visuelle.")
    st.code("streamlit run streamlit_app.py", language="bash")
    st.markdown("""
    1. Ouvrez votre navigateur sur `http://localhost:8501`.
    2. Glissez-déposez une image dans la zone de téléchargement.
    3. Les résultats s'affichent en temps réel avec des indicateurs visuels.
    4. Téléchargez le rapport JSON/PDF généré.
    """)

with col_cli:
    st.markdown("### 💻 Ligne de Commande (CLI)")
    st.markdown("Pour l'automatisation et les experts.")
    st.code("python decodeur.py --image <fichier> [options]", language="bash")
    
    st.markdown("**Options courantes :**")
    st.markdown("""
    - `--verbose` (`-v`) : Affiche les détails d'exécution.
    - `--pdf` : Génère un rapport PDF complet.
    - `--output <dir>` : Spécifie le dossier de sortie.
    """)
    
    st.markdown("**Exemple complet :**")
    st.code("python decodeur.py -i evidence.png -v --pdf", language="bash")

st.markdown("---")

# 5. Dépannage
st.markdown("## 🔧 Dépannage (FAQ)")

with st.expander("Erreur : TesseractNotFoundError", expanded=False):
    st.error("pytesseract.pytesseract.TesseractNotFoundError: tesseract is not installed")
    st.markdown("""
    **Solution :** Tesseract OCR n'est pas installé sur votre système ou n'est pas dans le PATH.
    1. Installez Tesseract : [Wiki Installation](https://github.com/UB-Mannheim/tesseract/wiki)
    2. Ou spécifiez le chemin dans `decodeur.py` :
    ```python
    pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    ```
    """)

with st.expander("Erreur : Module NumPy", expanded=False):
    st.error("A module that was compiled using NumPy 1.x cannot be run in NumPy 2.x")
    st.markdown("""
    **Solution :** Incompatibilité de version. Downgradez NumPy :
    ```bash
    pip install "numpy<2.0"
    ```
    """)

with st.expander("Problème : Analyse IA échouée", expanded=False):
    st.warning("Warning: Analyse intelligente échouée")
    st.markdown("""
    **Causes possibles :**
    - Clé API manquante ou invalide dans `.env`.
    - Pas de connexion internet.
    - Quota API dépassé.
    
    *L'outil continuera de fonctionner en mode dégradé (analyse technique uniquement).*
    """)

st.markdown("---")

# Footer
st.markdown("""
<div style="text-align: center; color: #666;">
    <p>ShadowTrace v1.0 • Développé pour le module Digital Skills (Cycle Ingénieur S1)</p>
    <p><em>"La vérité se cache dans les détails."</em></p>
</div>
""", unsafe_allow_html=True)
