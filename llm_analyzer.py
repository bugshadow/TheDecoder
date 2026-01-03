"""
Module d'analyse intelligente : LLM → NLP → Résultats structurés
1. LLM analyse le texte extrait (génère rapport en langage naturel)
2. NLP structure la réponse du LLM (extrait score, entités, recommandations)
"""

import spacy
import re
import os
from typing import Dict, List, Any
from openai import OpenAI
from config import SUSPICIOUS_KEYWORDS, LLM_MODELS, NLP_LANGUAGES
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()


class LLMAnalyzer:
    """
    PHASE 1 : Analyse sémantique brute avec LLM
    Input : Texte extrait de l'image
    Output : Rapport en langage naturel
    """
    
    def __init__(self, provider: str = None):
        """Initialise le client LLM"""
        self.provider = provider or os.getenv('LLM_PROVIDER', 'openrouter')
        
        if self.provider == 'openai':
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY manquante dans .env")
            self.client = OpenAI(api_key=api_key)
            self.model = LLM_MODELS['openai']
            
        elif self.provider == 'openrouter':
            api_key = os.getenv('OPENROUTER_API_KEY')
            if not api_key:
                raise ValueError("OPENROUTER_API_KEY manquante dans .env")
            
            app_name = os.getenv('OPENROUTER_APP_NAME', 'Forensic-Analyzer')
            app_url = os.getenv('OPENROUTER_APP_URL', '')
            
            self.client = OpenAI(
                api_key=api_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": app_url,
                    "X-Title": app_name
                }
            )
            self.model = os.getenv('OPENROUTER_MODEL', 'meta-llama/llama-3.1-405b-instruct:free')
            print(f"[LLM] Utilisation du modèle : {self.model}")
            
        else:
            raise NotImplementedError(f"Provider {self.provider} non implémenté")
    
    def build_forensic_prompt(self, text: str, context: Dict) -> str:
        """Construit le prompt forensique pour le LLM"""
        lsb_info = "Message LSB trouvé" if context.get('has_lsb') else "Pas de LSB"
        signatures_info = f"{context.get('signature_count', 0)} signatures binaires détectées"
        
        prompt = f"""Tu es un expert en analyse forensique numérique et cybersécurité. 

CONTEXTE DE L'EXTRACTION:
- Source: Analyse d'image par stéganalyse
- Méthodes utilisées: OCR, LSB, EXIF, signatures binaires
- Stéganographie LSB: {lsb_info}
- Fichiers cachés: {signatures_info}

TEXTE EXTRAIT:
{text}

MISSION:
Analyse ce texte de manière forensique et fournis un rapport structuré en suivant EXACTEMENT ce format:

=== RÉSUMÉ ===
[2-3 phrases décrivant le contenu]

=== NATURE DU CONTENU ===
[Un mot parmi: ANODIN, PROFESSIONNEL, SUSPECT, MALVEILLANT]

=== INTENTION PROBABLE ===
[Description de l'intention de l'auteur]

=== SCORE DE SUSPICION ===
[Un nombre entre 0 et 100]

=== INDICATEURS DE RISQUE ===
- [Indicateur 1]
- [Indicateur 2]

=== ÉLÉMENTS SUSPECTS DÉTECTÉS ===
- [Élément 1]
- [Élément 2]

=== RECOMMANDATIONS ===
- [Action 1]
- [Action 2]

=== ENTITÉS CLÉS ===
- Personnes: [liste]
- Organisations: [liste]
- Lieux: [liste]
- Emails: [liste]
- URLs: [liste]
- Dates: [liste]

Sois précis et factuel."""
        
        return prompt
    
    def analyze(self, text: str, context: Dict = None) -> Dict[str, Any]:
        """Analyse le texte avec le LLM"""
        if not text.strip():
            return {'raw_response': 'Aucun texte à analyser', 'status': 'empty'}
        
        context = context or {}
        
        try:
            prompt = self.build_forensic_prompt(text, context)
            print("[LLM] Envoi de la requête au modèle...")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Tu es un expert en cybersécurité et analyse forensique."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500
            )
            
            analysis_text = response.choices[0].message.content
            print(f"[LLM] ✓ Réponse reçue ({response.usage.total_tokens} tokens)")
            
            return {
                'raw_response': analysis_text,
                'model_used': self.model,
                'tokens_used': response.usage.total_tokens if response.usage else 0,
                'status': 'success'
            }
            
        except Exception as e:
            print(f"[LLM] ✗ Erreur: {str(e)}")
            return {'error': str(e), 'raw_response': '', 'status': 'error'}


class NLPStructurer:
    """PHASE 2 : Structuration de la réponse LLM avec NLP"""
    
    def __init__(self):
        """Initialise les modèles NLP"""
        self.nlp_models = {}
        for lang_code, model_name in NLP_LANGUAGES.items():
            try:
                self.nlp_models[lang_code] = spacy.load(model_name)
                print(f"[NLP] Modèle {model_name} chargé")
            except OSError:
                print(f"[NLP] ⚠ Modèle {model_name} manquant")
    
    def extract_score(self, text: str) -> int:
        """Extrait le score de suspicion"""
        patterns = [
            r'SCORE[^\d]*(\d{1,3})',
            r'suspicion[^\d]*(\d{1,3})',
            r'(\d{1,3})\s*/\s*100',
            r'score:\s*(\d{1,3})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                score = int(match.group(1))
                if 0 <= score <= 100:
                    return score
        return -1
    
    def extract_section(self, text: str, section_name: str) -> str:
        """Extrait une section spécifique"""
        patterns = [
            rf'\*\*===\s*{section_name}\s*===\*\*\s*\n(.*?)(?=\n\*\*===|\Z)',
            rf'===\s*{section_name}\s*===\s*\n(.*?)(?=\n===|\Z)',
            rf'\*\*{section_name}\*\*\s*\n(.*?)(?=\n\*\*[A-Z]|\Z)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""
    
    def extract_list_items(self, text: str) -> List[str]:
        """Extrait les éléments d'une liste"""
        lines = text.split('\n')
        items = []
        
        for line in lines:
            line = line.strip().strip('*').strip()
            if not line:
                continue
            
            match = re.match(r'^[-•*]\s*(.+)$', line)
            if match:
                items.append(match.group(1).strip())
                continue
            
            match = re.match(r'^\d+\.\s*(.+)$', line)
            if match:
                items.append(match.group(1).strip())
        
        return items
    
    def extract_entities_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extrait les entités nommées"""
        entities = {
            'persons': [], 'organizations': [], 'locations': [],
            'emails': [], 'urls': [], 'dates': []
        }
        
        entities['emails'] = re.findall(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', text)
        entities['urls'] = re.findall(r'https?://[^\s,\]]+', text)
        
        patterns = {
            'persons': r'Personnes?\s*:\s*([^\n]+)',
            'organizations': r'Organisations?\s*:\s*([^\n]+)',
            'locations': r'Lieux?\s*:\s*([^\n]+)',
            'dates': r'Dates?\s*:\s*([^\n]+)',
        }
        
        for entity_type, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                items_text = match.group(1)
                items = re.split(r'[,;]', items_text)
                entities[entity_type] = [
                    item.strip() for item in items 
                    if item.strip() and item.strip().lower() != 'aucun'
                ]
        
        return entities
    
    def classify_nature(self, text: str) -> str:
        """Extrait et normalise la nature du contenu"""
        nature_section = self.extract_section(text, "NATURE DU CONTENU").strip('*').strip()
        
        nature_map = {
            'anodin': 'benign', 'professionnel': 'professional',
            'suspect': 'suspicious', 'malveillant': 'malicious'
        }
        
        text_lower = nature_section.lower()
        for keyword, value in nature_map.items():
            if keyword in text_lower:
                return value
        return 'unknown'
    
    def structure_llm_response(self, llm_response: Dict) -> Dict[str, Any]:
        """Structure la réponse brute du LLM"""
        if llm_response.get('status') != 'success':
            return {'status': 'error', 'error': llm_response.get('error', 'Unknown error')}
        
        raw_text = llm_response.get('raw_response', '')
        print("\n[NLP] Structuration de la réponse LLM...")
        
        summary = self.extract_section(raw_text, "RÉSUMÉ")
        nature = self.classify_nature(raw_text)
        intention = self.extract_section(raw_text, "INTENTION PROBABLE")
        score = self.extract_score(raw_text)
        
        risk_indicators = self.extract_list_items(self.extract_section(raw_text, "INDICATEURS DE RISQUE"))
        suspicious_elements = self.extract_list_items(self.extract_section(raw_text, "ÉLÉMENTS SUSPECTS"))
        recommendations = self.extract_list_items(self.extract_section(raw_text, "RECOMMANDATIONS"))
        
        entities = self.extract_entities_from_text(self.extract_section(raw_text, "ENTITÉS CLÉS"))
        
        danger_level = 'unknown'
        if score >= 0:
            if score < 30:
                danger_level = 'low'
            elif score < 60:
                danger_level = 'medium'
            elif score < 80:
                danger_level = 'high'
            else:
                danger_level = 'critical'
        
        print(f"[NLP] ✓ Score extrait: {score}/100")
        print(f"[NLP] ✓ Nature: {nature}")
        print(f"[NLP] ✓ Niveau de danger: {danger_level}")
        
        return {
            'status': 'success', 'summary': summary, 'nature': nature,
            'intention': intention, 'suspicion_score': score, 'danger_level': danger_level,
            'risk_indicators': risk_indicators, 'suspicious_elements': suspicious_elements,
            'recommendations': recommendations, 'entities': entities,
            'llm_metadata': {
                'model': llm_response.get('model_used'),
                'tokens': llm_response.get('tokens_used'),
                'raw_response': raw_text
            }
        }


class IntelligentForensicAnalyzer:
    """Orchestrateur : LLM → NLP → Résultats finaux"""
    
    def __init__(self):
        self.llm = LLMAnalyzer()
        self.nlp = NLPStructurer()
    
    def collect_texts_from_forensic(self, forensic_results: Dict) -> tuple:
        all_texts, sources = [], []
        
        if forensic_results.get('ocr'):
            for ocr_type in ['easyocr', 'tesseract']:
                ocr_data = forensic_results['ocr'].get(ocr_type, {})
                if ocr_data.get('success') and ocr_data.get('text'):
                    all_texts.append(ocr_data['text'])
                    sources.append(f'OCR ({ocr_type})')
        
        lsb_text = forensic_results.get('steganography', {}).get('lsb')
        if lsb_text:
            all_texts.append(lsb_text)
            sources.append('Stéganographie LSB')
        
        return "\n\n--- SECTION SÉPARÉE ---\n\n".join(all_texts), sources
    
    def build_context(self, forensic_results: Dict) -> Dict:
        steg = forensic_results.get('steganography', {})
        return {
            'has_lsb': bool(steg.get('lsb')),
            'signature_count': len(steg.get('binary_signatures', [])),
            'has_bit_plane_anomaly': steg.get('bit_plane_anomaly', False),
            'has_histogram_anomaly': steg.get('histogram_anomaly', False),
            'suspicion_level': forensic_results.get('summary', {}).get('suspicion_level', 'unknown')
        }
    
    def analyze_forensic_data(self, forensic_results: Dict) -> Dict[str, Any]:
        print("\n" + "="*70)
        print("  ANALYSE INTELLIGENTE : LLM → NLP → STRUCTURATION")
        print("="*70)
        
        combined_text, sources = self.collect_texts_from_forensic(forensic_results)
        
        if not combined_text.strip():
            return {'status': 'no_text_found', 'message': 'Aucun texte exploitable'}
        
        print(f"\n[+] Textes collectés depuis : {', '.join(set(sources))}")
        print(f"[+] Longueur totale : {len(combined_text)} caractères")
        
        context = self.build_context(forensic_results)
        
        print("\n" + "─"*70)
        print("[PHASE 1] ANALYSE SÉMANTIQUE (LLM)")
        print("─"*70)
        llm_results = self.llm.analyze(combined_text, context)
        
        if llm_results.get('status') == 'error':
            return {'status': 'error', 'phase': 'llm', 'error': llm_results.get('error')}
        
        print("\n" + "─"*70)
        print("[PHASE 2] STRUCTURATION DES DONNÉES (NLP)")
        print("─"*70)
        structured_results = self.nlp.structure_llm_response(llm_results)
        
        structured_results['sources'] = list(set(sources))
        structured_results['text_length'] = len(combined_text)
        
        print("\n" + "="*70)
        print("  ✓ ANALYSE COMPLÉTÉE")
        print("="*70)
        
        return structured_results


if __name__ == '__main__':
    import json
    
    test_data = {
        "ocr": {"easyocr": {"text": "Test contact: hack@example.com", "success": True}},
        "steganography": {"lsb": "PASSWORD=admin123", "binary_signatures": [{"type": "EXE_MZ"}]},
        "summary": {"suspicion_level": "medium"}
    }
    
    analyzer = IntelligentForensicAnalyzer()
    results = analyzer.analyze_forensic_data(test_data)
    print(json.dumps(results, indent=2, ensure_ascii=False))