import streamlit as st
import base64

def load_css():
    """Charge le CSS personnalisé pour un design professionnel et magnifique."""
    
    # Définition des couleurs et styles
    primary_color = "#00FFC2"  # Neon Green/Teal
    secondary_color = "#2E86AB" # Muted Blue
    bg_color = "#0E1117"
    card_bg = "rgba(22, 27, 34, 0.8)"
    
    st.markdown(f"""
        <style>
        /* Import Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&display=swap');

        /* Global Settings */
        html, body, [class*="css"] {{
            font-family: 'Inter', sans-serif;
            background-color: {bg_color};
            color: #E0E0E0;
        }}
        
        /* Headers */
        h1, h2, h3, h4, h5, h6 {{
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700;
            color: #FFFFFF;
        }}
        
        h1 {{
            font-size: 3.5rem !important;
            background: linear-gradient(90deg, #FFFFFF 0%, {primary_color} 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem !important;
        }}
        
        h2 {{
            font-size: 2.0rem !important;
            border-bottom: 2px solid {primary_color};
            padding-bottom: 0.5rem;
            margin-top: 2rem !important;
            display: inline-block;
        }}

        /* Cards / Containers */
        .stCard {{
            background-color: {card_bg};
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            margin-bottom: 20px;
        }}
        
        .stCard:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 255, 194, 0.1);
            border-color: {primary_color};
        }}

        /* Buttons */
        .stButton > button {{
            background: linear-gradient(45deg, {secondary_color}, {primary_color});
            color: #000000;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            padding: 0.6rem 1.2rem;
            transition: all 0.3s ease;
        }}
        
        .stButton > button:hover {{
            opacity: 0.9;
            transform: scale(1.02);
            box-shadow: 0 0 15px rgba(0, 255, 194, 0.4);
        }}

        /* Metrics */
        [data-testid="stMetricValue"] {{
            font-family: 'Space Grotesk', monospace;
            color: {primary_color} !important;
        }}

        /* Sidebar */
        [data-testid="stSidebar"] {{
            background-color: #090B10;
            border-right: 1px solid rgba(255,255,255,0.05);
        }}

        /* Hide Streamlit Branding */
        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
        
        /* Custom Classes */
        .hero-text {{
            font-size: 1.2rem;
            color: #B0B0B0;
            margin-bottom: 2rem;
            line-height: 1.6;
        }}
        
        .check-list {{
            list-style-type: none;
            padding-left: 0;
        }}
        .check-list li {{
            margin-bottom: 10px;
            padding-left: 25px;
            position: relative;
        }}
        .check-list li:before {{
            content: '✓';
            position: absolute;
            left: 0;
            color: {primary_color};
            font-weight: bold;
        }}
        </style>
    """, unsafe_allow_html=True)

import textwrap

def card(title, content, icon=None):
    """Affiche une carte stylisée."""
    icon_html = f"<div style='font-size: 2rem; margin-bottom: 10px;'>{icon}</div>" if icon else ""
    html_content = (
        f'<div class="stCard">'
        f'{icon_html}'
        f'<h3 style="margin-top: 0; font-size: 1.5rem;">{title}</h3>'
        f'<p style="color: #cccccc;">{content}</p>'
        f'</div>'
    )
    st.markdown(html_content, unsafe_allow_html=True)

def mermaid(code: str, height: int = 500):
    """
    Renders a Mermaid diagram using MDN/CDN injection.
    """
    import streamlit.components.v1 as components
    
    html_code = f"""
    <div class="mermaid">
    {code}
    </div>
    <script type="module">
      import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
      mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
    """
    components.html(html_code, height=height)

