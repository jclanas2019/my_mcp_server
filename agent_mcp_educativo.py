#!/usr/bin/env python3
import socket
import json
import uuid
import warnings
import os
import sys
from typing import Dict, List, Any, Optional

# Suprimimos warnings de depreciación
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Añadimos el directorio raíz al path para importar prompts
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from prompts import educativo  # Importamos el módulo educativo.py
except ImportError:
    print("⚠️ Módulo prompts.educativo no encontrado. Se usarán prompts por defecto.")
    educativo = None

# Importaciones para LLM
from langchain_ollama import OllamaLLM

# ─────────────────────────────────────────────────────────────────────────────
# ID de sesión único por ejecución de agente
# ─────────────────────────────────────────────────────────────────────────────

SESSION_ID = str(uuid.uuid4())
print(f"🧠 Ejecutando sesión MCP con session_id: {SESSION_ID}")

# ─────────────────────────────────────────────────────────────────────────────
# LLM: Ollama con modelo gemma3:1b
# ─────────────────────────────────────────────────────────────────────────────

llm = OllamaLLM(model="gemma3:1b")

# ─────────────────────────────────────────────────────────────────────────────
# Definición de herramientas MCP con manejo mejorado de errores
# ─────────────────────────────────────────────────────────────────────────────

def leer_notas() -> str:
    """Lee todas las notas académicas registradas en esta sesión."""
    msg = {
        "type": "call_tool",
        "tool": "leer_notas",
        "arguments": {},
        "session_id": SESSION_ID
    }
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=10) as s:
            s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            response = s.recv(8192)  # Aumentamos el buffer para recibir respuestas más grandes
            
            try:
                # Intentamos decodificar el JSON
                result = json.loads(response.decode("utf-8"))
                return result.get("text", "No hay notas registradas.")
            except json.JSONDecodeError as e:
                # Si hay error en el JSON, tratamos de limpiar la respuesta
                print(f"⚠️ Error al decodificar JSON: {e}")
                resp_text = response.decode("utf-8").strip()
                if resp_text.startswith("{") and "text" in resp_text:
                    # Intentamos extraer el texto manualmente
                    try:
                        texto_inicio = resp_text.find('"text":') + 8
                        texto_fin = resp_text.find('"}', texto_inicio)
                        if texto_fin == -1:
                            texto_fin = len(resp_text) - 1
                        return resp_text[texto_inicio:texto_fin].strip('"')
                    except Exception:
                        pass
                # Si todo falla, devolvemos la respuesta cruda
                return f"Respuesta del servidor (formato no JSON): {resp_text}"
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return f"Error al conectar con el servidor MCP: {e}"

def append_nota(nota: str, max_retries=3) -> str:
    """
    Agrega una nota textual al registro académico con reintentos y mejor manejo de errores.
    
    Args:
        nota: El texto de la nota a agregar
        max_retries: Número máximo de intentos en caso de error
    """
    # Si la nota es muy larga, la acortamos para evitar problemas
    if len(nota) > 1500:
        print("⚠️ Nota demasiado larga, acortando a 1500 caracteres...")
        nota = nota[:1497] + "..."
    
    msg = {
        "type": "call_tool",
        "tool": "append_nota",
        "arguments": {"nota": nota},
        "session_id": SESSION_ID
    }
    
    attempt = 0
    while attempt < max_retries:
        try:
            with socket.create_connection(("127.0.0.1", 5050), timeout=10) as s:
                s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                response = s.recv(8192)  # Aumentamos el buffer
                
                try:
                    # Intentamos decodificar el JSON
                    result = json.loads(response.decode("utf-8"))
                    return result.get("text", "Nota agregada con éxito.")
                except json.JSONDecodeError as e:
                    # Si hay error en el JSON
                    print(f"⚠️ Intento {attempt+1}: Error al decodificar JSON: {e}")
                    
                    # Intentamos limpiar la respuesta
                    resp_text = response.decode("utf-8").strip()
                    if "Nota registrada" in resp_text or "agregada" in resp_text:
                        return "Nota agregada con éxito."
                    
                    # Si es el último intento, devolvemos lo que tenemos
                    if attempt == max_retries - 1:
                        return f"Posible éxito al registrar nota. Respuesta del servidor: {resp_text[:100]}..."
                    
                    # Si no es el último intento, esperamos y reintentamos
                    import time
                    time.sleep(1)  # Pausa de 1 segundo antes de reintentar
        except Exception as e:
            print(f"❌ Intento {attempt+1}: Error de conexión: {e}")
            if attempt == max_retries - 1:
                return f"Error al conectar con el servidor MCP: {e}"
            import time
            time.sleep(1)  # Pausa antes de reintentar
        
        attempt += 1

# ─────────────────────────────────────────────────────────────────────────────
# Pipeline de procesamiento de prompts educativos
# ─────────────────────────────────────────────────────────────────────────────

def ejecutar_pipeline_educativo(topic: str, nivel: str = "intermedio") -> str:
    """
    Ejecuta el pipeline de prompts educativos y genera contenido académico.
    
    Args:
        topic: El tema principal sobre el que generar contenido
        nivel: El nivel de profundidad (básico, intermedio, avanzado)
    
    Returns:
        El contenido educativo generado
    """
    # Obtenemos el prompt adecuado
    if educativo:
        try:
            # Intentamos usar la función get_prompt si existe
            if hasattr(educativo, "get_prompt"):
                prompt_educativo = educativo.get_prompt(topic=topic, nivel=nivel)
            # Si no, buscamos los templates directamente
            elif hasattr(educativo, f"TEMPLATE_{nivel.upper()}"):
                template = getattr(educativo, f"TEMPLATE_{nivel.upper()}")
                prompt_educativo = template.format(topic=topic)
            else:
                # Usamos un prompt por defecto
                prompt_educativo = crear_prompt_por_defecto(topic, nivel)
        except Exception as e:
            print(f"⚠️ Error al obtener prompt de educativo.py: {e}")
            prompt_educativo = crear_prompt_por_defecto(topic, nivel)
    else:
        # Si no se pudo importar el módulo educativo
        prompt_educativo = crear_prompt_por_defecto(topic, nivel)
    
    # Generamos contenido con el LLM usando el prompt
    try:
        contenido = llm.invoke(prompt_educativo)
        if hasattr(contenido, 'content'):
            contenido = contenido.content
    except Exception as e:
        print(f"❌ Error al invocar LLM: {e}")
        contenido = f"Error al generar contenido: {e}"
    
    return contenido

def crear_prompt_por_defecto(topic: str, nivel: str) -> str:
    """Crea un prompt educativo por defecto si no se puede usar el módulo educativo."""
    niveles = {
        "básico": "conceptos fundamentales, explicaciones sencillas y ejemplos cotidianos",
        "intermedio": "conceptos intermedios, relaciones entre ideas y ejemplos prácticos",
        "avanzado": "conceptos avanzados, limitaciones técnicas y casos de uso complejos"
    }
    
    descripcion = niveles.get(nivel.lower(), niveles["intermedio"])
    
    return f"""
    Eres un asistente educativo especializado en explicaciones pedagógicas.
    
    Genera una explicación de nivel {nivel.upper()} sobre el tema: {topic}
    
    Tu explicación debe incluir {descripcion}.
    
    Estructura tu respuesta con:
    1. Una introducción clara
    2. Desarrollo de 2-3 conceptos principales
    3. Ejemplos prácticos cuando sea posible
    4. Una conclusión breve
    
    El contenido debe estar completamente en español y ser académicamente riguroso.
    
    Limita tu respuesta a un máximo de 4-5 párrafos.
    """

# ─────────────────────────────────────────────────────────────────────────────
# Ejecución secuencial con pipeline educativo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        # 1. Primero leemos las notas existentes
        print("\n--- Paso 1: Leyendo notas existentes ---")
        result_leer = leer_notas()
        print(f"🔍 Resultado: {result_leer}")
        
        # 2. Generamos nuevo contenido educativo
        print("\n--- Paso 2: Generando contenido educativo ---")
        tema = "LangChain y su integración con MCP"
        nivel = "intermedio"
        
        # Acortamos el contenido para evitar problemas con JSON
        nuevo_contenido = ejecutar_pipeline_educativo(tema, nivel)
        if len(nuevo_contenido) > 1200:
            print("⚠️ Contenido generado muy extenso, acortando para evitar errores...")
            contenido_resumido = nuevo_contenido[:1200] + "...\n[Contenido acortado por limitaciones técnicas]"
        else:
            contenido_resumido = nuevo_contenido
            
        print(f"📝 Contenido generado sobre {tema} (nivel {nivel}):")
        print("---------------------------------------------------")
        print(contenido_resumido)
        print("---------------------------------------------------")
        
        # 3. Guardamos la nota (versión acortada)
        print("\n--- Paso 3: Guardando nota educativa ---")
        result_append = append_nota(contenido_resumido)
        print(f"✅ Resultado: {result_append}")
        
        print("\n--- Proceso de pipeline educativo completado ---")
    
    except Exception as e:
        print(f"❌ Error general en la ejecución: {e}")