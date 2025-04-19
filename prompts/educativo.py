#!/usr/bin/env python3
"""
Módulo de prompts educativos para el agente MCP.
Este módulo contiene diferentes templates de prompts educativos
para generar contenido académico estructurado.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Templates de prompts por nivel
# ─────────────────────────────────────────────────────────────────────────────

TEMPLATE_BÁSICO = """
Eres un asistente educativo especializado en explicaciones claras y sencillas.

Genera una explicación BÁSICA sobre el tema: {topic}

Tu explicación debe:
1. Usar vocabulario sencillo y accesible
2. Incluir analogías cotidianas para facilitar la comprensión
3. Evitar tecnicismos innecesarios
4. Tener un máximo de 3-4 párrafos cortos
5. Estar completamente en español

Al final, incluye 2-3 preguntas básicas que un estudiante podría hacerse sobre este tema.
"""

TEMPLATE_INTERMEDIO = """
Eres un asistente educativo especializado en explicaciones estructuradas y pedagógicas.

Genera una explicación de nivel INTERMEDIO sobre el tema: {topic}

Tu explicación debe:
1. Estar estructurada en secciones claras
2. Incluir conceptos fundamentales y sus relaciones
3. Proporcionar 1-2 ejemplos prácticos
4. Tener un máximo de 4-5 párrafos
5. Estar completamente en español
6. Usar un vocabulario académico pero accesible

Al final, incluye 3-4 conceptos clave que el estudiante debe retener.
"""

TEMPLATE_AVANZADO = """
Eres un asistente educativo especializado en explicaciones técnicas y detalladas.

Genera una explicación AVANZADA sobre el tema: {topic}

Tu explicación debe:
1. Profundizar en los aspectos técnicos del tema
2. Incluir referencias a conceptos relacionados
3. Mencionar limitaciones, desafíos o consideraciones importantes
4. Proporcionar ejemplos técnicos o casos de uso avanzados
5. Estar completamente en español
6. Usar vocabulario técnico apropiado

Al final, sugiere 2-3 áreas de investigación o profundización relacionadas.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Funciones para obtener y personalizar prompts
# ─────────────────────────────────────────────────────────────────────────────

def get_prompt(topic: str, nivel: str = "intermedio", personalización: dict = None) -> str:
    """
    Obtiene el prompt educativo según el nivel y lo personaliza si es necesario.
    
    Args:
        topic: El tema sobre el que generar contenido
        nivel: El nivel de profundidad (básico, intermedio, avanzado)
        personalización: Diccionario con parámetros adicionales para personalizar el prompt
    
    Returns:
        El prompt educativo personalizado
    """
    # Seleccionamos el template según el nivel
    if nivel.lower() == "básico" or nivel.lower() == "basico":
        template = TEMPLATE_BÁSICO
    elif nivel.lower() == "intermedio":
        template = TEMPLATE_INTERMEDIO
    elif nivel.lower() == "avanzado":
        template = TEMPLATE_AVANZADO
    else:
        # Por defecto usamos nivel intermedio
        template = TEMPLATE_INTERMEDIO
    
    # Formateamos el template con el topic
    prompt = template.format(topic=topic)
    
    # Si hay personalización, añadimos los elementos especificados
    if personalización:
        if "enfoque" in personalización:
            prompt += f"\n\nEnfoca tu explicación especialmente en: {personalización['enfoque']}"
        
        if "audiencia" in personalización:
            prompt += f"\n\nLa audiencia es: {personalización['audiencia']}"
        
        if "formato" in personalización:
            prompt += f"\n\nUtiliza el siguiente formato: {personalización['formato']}"
    
    return prompt

# ─────────────────────────────────────────────────────────────────────────────
# Funciones específicas para temas educativos comunes
# ─────────────────────────────────────────────────────────────────────────────

def prompt_langchain_basico() -> str:
    """Prompt básico sobre LangChain."""
    return get_prompt("LangChain como framework para aplicaciones con LLMs", "básico")

def prompt_langchain_avanzado() -> str:
    """Prompt avanzado sobre LangChain."""
    return get_prompt("Arquitectura y componentes avanzados de LangChain", "avanzado")

def prompt_mcp_integracion() -> str:
    """Prompt sobre integración de MCP con otros sistemas."""
    personalización = {
        "enfoque": "aspectos de integración y comunicación entre sistemas",
        "audiencia": "desarrolladores con experiencia en sistemas distribuidos"
    }
    return get_prompt("Integración de la plataforma MCP con sistemas externos", "intermedio", personalización)