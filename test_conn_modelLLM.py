"""Test de connexion à OpenRouter avec Llama 3.1 405B"""

import os
from dotenv import load_dotenv
from openai import OpenAI

# Charge les variables d'environnement
load_dotenv()

print("="*60)
print("TEST DE CONNEXION - hermes_405b via OpenRouter")
print("="*60)

try:
    # Vérifie que la clé existe
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        print("\n✗ ERREUR : OPENROUTER_API_KEY manquante dans .env")
        exit(1)
    
    print(f"\n[+] Clé API trouvée : {api_key[:20]}...")
    
    # Configure le client
    client = OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1"
    )
    
    print("[+] Envoi d'une requête test...")
    
    # Requête simple
    response = client.chat.completions.create(
        model="nousresearch/hermes-3-llama-3.1-405b:free",
        messages=[
            {
                "role": "system",
                "content": "Tu es un expert en cybersécurité."
            },
            {
                "role": "user",
                "content": "Dis 'Connexion réussie' en une phrase."
            }
        ],
        max_tokens=50
    )
    
    print("\n✓ CONNEXION RÉUSSIE !")
    print(f"\nRéponse : {response.choices[0].message.content}")
    print(f"Tokens utilisés : {response.usage.total_tokens}")
    print("\n✓ Tu peux maintenant utiliser llm_analyzer.py !")
    
except Exception as e:
    print(f"\n✗ ERREUR : {e}")
    print("\nVérifie :")
    print("1. Le fichier .env existe")
    print("2. OPENROUTER_API_KEY est correcte")
    print("3. Tu as activé ton venv")