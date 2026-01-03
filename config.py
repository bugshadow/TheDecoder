"""Configuration pour l'analyseur LLM"""

# Patterns de détection
SUSPICIOUS_KEYWORDS = [
    'password', 'secret', 'confidential', 'private', 'hack',
    'exploit', 'payload', 'malware', 'ransomware', 'phishing',
    'mot de passe', 'confidentiel', 'privé', 'caché'
]

# Modèles LLM disponibles
LLM_MODELS = {
    'openai': 'gpt-4o-mini',  # Plus économique
    'ollama': 'llama3.2'       # Local
}

# Configuration NLP
NLP_LANGUAGES = {
    'fr': 'fr_core_news_sm',
    'en': 'en_core_web_sm'
}