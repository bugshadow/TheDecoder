import streamlit as st
import utils
from PIL import Image

# Configuration de la page
st.set_page_config(
    page_title="Revelator - Analyse Forensique",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Chargement du design
utils.load_css()

# Hero Section
col1, col2 = st.columns([1, 1])

with col1:
    st.markdown('<div style="margin-top: 100px;"></div>', unsafe_allow_html=True)
    st.markdown("# Revelator")
    st.markdown("### Analyse Forensique d'Images Intelligente")
    st.markdown("""
    <div class="hero-text">
    Un outil professionnel combinant la stéganalyse avancée et l'intelligence artificielle pour détecter, analyser et extraire les données cachées dans les images numériques.
    Conçu pour les experts en cybersécurité.
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("Démarrer une Analyse  ►"):
        st.switch_page("pages/2_Analyse.py")

with col2:
    # Placeholder pour une illustration ou un graphique cool 3D (si possible, sinon vide ou logo)
    # On utilise un composant vide stylisé pour l'équilibre
    st.markdown("""
    <div style="
        background: radial-gradient(circle, rgba(0,255,194,0.1) 0%, rgba(14,17,23,0) 70%);
        height: 400px;
        width: 100%;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: pulse 4s infinite;
    ">
        <div style="font-size: 5rem; color: #00FFC2; font-family: 'Courier New'; opacity: 0.8;">
            010101<br>101010<br>001100
        </div>
    </div>
    <style>
    @keyframes pulse {
        0% { transform: scale(0.95); opacity: 0.5; }
        50% { transform: scale(1.05); opacity: 0.8; }
        100% { transform: scale(0.95); opacity: 0.5; }
    }
    </style>
    """, unsafe_allow_html=True)

st.markdown("---")

# Fonctionnalités
st.markdown("<h2>Capacités du Système</h2>", unsafe_allow_html=True)

col_feat1, col_feat2, col_feat3 = st.columns(3)

with col_feat1:
    utils.card("O.C.R. Avancé", 
               "Extraction de texte multilingue utilisant Tesseract et EasyOCR pour une précision maximale.")
    utils.card("Analyse de Métadonnées", 
               "Inspection profonde des tags EXIF, commentaires cachés et marqueurs de fichiers suspects.")

with col_feat2:
    utils.card("Stéganalyse LSB", 
               "Détection algortihmique de messages cachés dans les bits de poids faible des pixels.")
    utils.card("Intelligence Artificielle", 
               "Analyse sémantique des données extraites via LLM (Llama 3.1) pour l'évaluation des menaces.",
               icon="🧠") # Icone via caractère, limite emoji mais technique

with col_feat3:
    utils.card("Extraction de Signatures", 
               "Identification de fichiers binaires (ZIP, EXE, PDF) dissimulés dans la structure de l'image.")
    utils.card("Rapports Complets", 
               "Génération automatique de rapports d'investigation en formats JSON et PDF.")

# Workflow
st.markdown("---")
st.markdown("<h2>Architecture du Pipeline</h2>", unsafe_allow_html=True)

st.markdown("""
<div style="background-color: rgba(22, 27, 34, 0.5); padding: 30px; border-radius: 15px; text-align: center;">
    <div style="display: flex; justify-content: space-around; align-items: center; flex-wrap: wrap;">
        <div style="border: 1px solid #00FFC2; padding: 15px; border-radius: 10px; width: 150px;">Image Input</div>
        <div style="color: #00FFC2;">➔</div>
        <div style="border: 1px solid #2E86AB; padding: 15px; border-radius: 10px; width: 150px;">Pré-traitement</div>
        <div style="color: #2E86AB;">➔</div>
        <div style="border: 1px solid #2E86AB; padding: 15px; border-radius: 10px; width: 150px;">Extraction Multi-Moteur</div>
        <div style="color: #2E86AB;">➔</div>
        <div style="border: 1px solid #FF0055; padding: 15px; border-radius: 10px; width: 150px;">Analyse LLM</div>
        <div style="color: #FF0055;">➔</div>
        <div style="border: 1px solid #FFFFFF; padding: 15px; border-radius: 10px; width: 150px;">Rapport Final</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Footer discret
st.markdown("<br><br><br>", unsafe_allow_html=True)
st.markdown("<div style='text-align: center; color: #555;'>Projet Digital Skills - Cycle Ingénieur S1</div>", unsafe_allow_html=True)
