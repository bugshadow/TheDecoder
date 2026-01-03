import streamlit as st
import sys
import os
import shutil
from pathlib import Path
import time

# Ajouter le dossier parent au path pour importer decodeur
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import decodeur
import utils
from utils import card

# Config needs to be first if set_page_config is used, but we inherit from main app config usually? 
# No, each page can have config but set_page_config must be first.
st.set_page_config(page_title="Analyse - ShadowTrace", page_icon="🕵️‍♂️", layout="wide")

utils.load_css()

st.markdown("# Laboratory d'Analyse")
st.markdown("### Investigation Forensique Numérique")

# Zone d'upload stylisée
st.markdown("""
<style>
/* Custom upload style if possible, otherwise standard */
</style>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Déposez le fichier suspect ici (PNG, JPG, BMP)", type=['png', 'jpg', 'jpeg', 'bmp', 'gif'])

if uploaded_file is not None:
    # Sauvegarde temporaire
    temp_dir = Path("temp_uploads")
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / uploaded_file.name
    
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Affichage de l'image et info
    col_img, col_info = st.columns([1, 2])
    with col_img:
        st.image(uploaded_file, caption="Preuve Numérique #1", use_column_width=True)
        # Add border style via CSS wrapper?
        
    with col_info:
        st.markdown(f"**Nom du fichier:** `{uploaded_file.name}`")
        st.markdown(f"**Taille:** `{uploaded_file.size / 1024:.2f} KB`")
        st.markdown(f"**Type:** `{uploaded_file.type}`")
        
        start_btn = st.button("Lancer les Protocoles d'Analyse", type="primary")

    if start_btn:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Initialisation du noyau forensique...")
        time.sleep(0.5)
        
        try:
            # Instanciation de l'analyseur
            analyzer = decodeur.ForensicAnalyzer(str(file_path), verbose=False)
            
            # Simulation d'étapes pour l'effet visuel
            steps = [
                (10, "Pré-traitement de l'image (Normalisation/Grayscale)..."),
                (30, "Extraction OCR (Tesseract + EasyOCR)..."),
                (50, "Analyse Stéganographique (LSB)..."),
                (70, "Scan des signatures binaires et métadonnées..."),
                (85, "Analyse Intelligente (IA/LLM)..."),
                (95, "Génération du rapport et corrélation..."),
                (100, "Analyse terminée.")
            ]
            
            # On lance l'analyse réelle
            # Note: run_all_analyses fait tout d'un coup. Pour une barre de progression précise 
            # il faudrait appeler les méthodes une par une. On va le faire ici pour le show.
            
            analyzer._load_image()
            progress_bar.progress(10)
            status_text.text(steps[0][1])
            analyzer.preprocess_image()
            
            progress_bar.progress(30)
            status_text.text(steps[1][1])
            analyzer.analyze_ocr()
            
            progress_bar.progress(50)
            status_text.text(steps[2][1])
            analyzer.analyze_lsb()
            
            progress_bar.progress(70)
            status_text.text(steps[3][1])
            analyzer.analyze_strings()
            analyzer.detect_signatures()
            analyzer.analyze_exif()
            
            # Autres analyses...
            analyzer.analyze_bitplanes()
            analyzer.analyze_histogram()
            
            progress_bar.progress(85)
            status_text.text(steps[4][1])
            analyzer.correlate_results()
            
            # ia logic
            try:
                status_text.text("Extraction des insights par IA...")
                from llm_analyzer import IntelligentForensicAnalyzer
                llm_analyzer = IntelligentForensicAnalyzer()
                ia_results = llm_analyzer.analyze_forensic_data(analyzer.results)
                analyzer.results['intelligent_analysis'] = ia_results
            except Exception as e:
                print(f"Erreur IA: {e}")
                # Optional: st.warning(f"Module IA non activé: {e}")

            # IA part logic is in llm_analyzer called by correlate_results? No, looking at decodeur.py code:
            # correlate_results mainly calculates suspicion.
            # run_all_analyses calls everything.
            # I should check where IA is called. 
            # Based on README: "Nouveau ! L'analyse intelligente combine..." 
            # But in the file outline I saw, I didn't see explicit verify_ai call in ForensicAnalyzer methods, 
            # maybe it was added or I missed it.
            # Wait, run_all_analyses calls analyze_ocr, analyze_lsb, etc. 
            # I suspect IA might be separate or integrated. 
            # I'll rely on analyzer.run_all_analyses() if I want to be safe, but I already called partials.
            # I will assume correlate_results or run_all_analyses handles the rest.
            
            results = analyzer.results
            
            progress_bar.progress(100)
            status_text.text("Terminé.")
            time.sleep(0.5)
            status_text.empty()
            progress_bar.empty()
            
            # === AFFICHAGE DES RÉSULTATS ===
            
            # Score de Suspicion Global
            suspicion_score = 0 # Default
            suspicion_level = results.get('summary', {}).get('suspicion_level', 'UNKNOWN')
            
            # Map level to color/score mockup because decodeur might not give a num score easily directly in 'results' root
            # unless I check deeper.
            level_colors = {
                "NONE": "#00FF00", "LOW": "#FFFF00", "MEDIUM": "#FFA500", "HIGH": "#FF0000"
            }
            color = level_colors.get(suspicion_level, "#FFFFFF")
            
            st.markdown("---")
            
            res_col1, res_col2 = st.columns([1, 1])
            with res_col1:
                st.markdown(f"""
                <div style="border: 2px solid {color}; padding: 20px; border-radius: 10px; text-align: center; background-color: rgba(0,0,0,0.3);">
                    <h2 style="margin:0; color: #BBB;">Niveau de Suspicion</h2>
                    <h1 style="font-size: 4rem; color: {color}; margin: 10px 0;">{suspicion_level}</h1>
                </div>
                """, unsafe_allow_html=True)
                
            with res_col2:
                # Stats rapides
                extracted_files_count = len(results.get('steganography', {}).get('binary_signatures', []))
                ocr_res = results.get('ocr', {})
                ocr_found = ocr_res.get('tesseract', {}).get('success', False) or ocr_res.get('easyocr', {}).get('success', False)
                lsb_found = results.get('steganography', {}).get('lsb') is not None
                
                st.markdown(f"**Fichiers Cachés Détectés:** `{extracted_files_count}`")
                st.markdown(f"**Texte Visible (OCR):** `{'OUI' if ocr_found else 'NON'}`")
                st.markdown(f"**Message LSB:** `{'OUI' if lsb_found else 'NON'}`")
            
            # Tabs pour détails
            tab1, tab2, tab3, tab4 = st.tabs(["Stéganographie & Fichiers", "OCR & Texte", "Métadonnées & Hex", "Rapport IA"])
            
            with tab1:
                # LSB
                st.markdown("#### Analyse LSB")
                lsb_res = results.get('steganography', {}).get('lsb')
                if lsb_res:
                    st.success("Message caché trouvé !")
                    st.code(lsb_res)
                else:
                    st.info("Aucun message LSB détecté.")
                
                # Signatures
                st.markdown("#### Signatures de Fichiers (File Carving)")
                sigs = results.get('steganography', {}).get('binary_signatures', [])
                if sigs:
                    for sig in sigs:
                        st.warning(f"Fichier détecté : {sig['type']} @ {sig['hex_offset']}")
                else:
                    st.info("Aucune signature de fichier suspecte.")
            
            with tab2:
                st.markdown("#### OCR - Texte Extrait")
                ocr_res = results.get('ocr', {})
                tess = ocr_res.get('tesseract', {})
                easy = ocr_res.get('easyocr', {})
                
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Moteur Tesseract**")
                    if tess.get('success'):
                        st.text_area("Résultat Tesseract", tess.get('text', ''), height=150)
                    else:
                        st.text("Rien.")
                with c2:
                    st.markdown("**Moteur EasyOCR**")
                    if easy.get('success'):
                        st.text_area("Résultat EasyOCR", easy.get('text', ''), height=150)
                    else:
                        st.text("Rien.")
                        
            with tab3:
                st.markdown("#### EXIF & Strings")
                exif = results.get('steganography', {}).get('exif', {})
                suspicious_exif = exif.get('suspicious', [])
                if suspicious_exif:
                    st.error(f"Tags Suspects: {suspicious_exif}")
                else:
                    st.success("Pas de tags EXIF suspects.")
                    
                with st.expander("Voir toutes les chaînes (Strings) trouvées"):
                    strings = results.get('steganography', {}).get('ascii_strings', [])
                    st.write(strings)

            with tab4:
                # Placeholder for IA logic if it exists in results
                # Looking at README: "intelligent_analysis" key
                ia_res = results.get('intelligent_analysis', {})
                if ia_res and ia_res.get('status') == 'success':
                    st.markdown(f"### Score IA: {ia_res.get('suspicion_score')}/100")
                    st.markdown(f"**Danger:** {ia_res.get('danger_level')}")
                    st.markdown(f"**Nature:** {ia_res.get('nature')}")
                    st.info(ia_res.get('summary'))
                    
                    st.markdown("#### Recommandations")
                    for rec in ia_res.get('recommendations', []):
                        st.markdown(f"- {rec}")
                else:
                    st.info("Analyse IA non disponible ou non configurée (Module LLM).")

            # Option de téléchargement du rapport
            # Generating PDF Report using decoded function if possible
            # We can re-use the generate_pdf_report from decodeur if needed, or just dump JSON
            
            import json
            json_str = json.dumps(results, default=str, indent=4)
            st.download_button("Télécharger Rapport JSON", json_str, file_name=f"{uploaded_file.name}_report.json", mime="application/json")


        except Exception as e:
            st.error(f"Une erreur critique est survenue lors de l'analyse: {str(e)}")
            st.exception(e)

else:
    # État vide stylisé
    st.info("En attente de fichier...")

