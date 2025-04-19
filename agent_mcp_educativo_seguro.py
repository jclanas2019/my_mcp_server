#!/usr/bin/env python3
import socket
import json
import uuid
import warnings
import os
import sys
import time
import hmac
import hashlib
import base64
import ssl
import logging
import re
import secrets
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta

# Configuración de logging seguro
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s - [%(filename)s:%(lineno)d]',
    handlers=[
        logging.FileHandler("mcp_agent_secure.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mcp_agent")

# Suprimimos warnings de depreciación
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Configuración de seguridad
# ─────────────────────────────────────────────────────────────────────────────

# NOTA: En un entorno de producción, estas claves deberían cargarse 
# desde variables de entorno o un gestor de secretos seguro
SECRET_KEY = secrets.token_hex(32)  # Genera una clave secreta de 32 bytes
SESSION_TIMEOUT = 3600  # Sesión expira después de 1 hora
MAX_CONTENT_LENGTH = 2000  # Máximo tamaño de contenido permitido
SERVER_HOST = "127.0.0.1"  # Solo conexiones locales
SERVER_PORT = 5050

# Lista de patrones de texto potencialmente maliciosos para filtrar
MALICIOUS_PATTERNS = [
    r"<script.*?>.*?</script>",  # Scripts JS
    r".*?`.*?`.*?",  # Inyección de comandos
    r"(?:--.*?$|;.*?--)",  # Inyección SQL
    r"(?i)(?:eval|exec|system|popen|subprocess)",  # Funciones peligrosas
]

# ─────────────────────────────────────────────────────────────────────────────
# Funciones de seguridad
# ─────────────────────────────────────────────────────────────────────────────

def generate_secure_session_id() -> str:
    """Genera un ID de sesión criptográficamente seguro."""
    # Combinamos un UUID4 con un token aleatorio y timestamp
    random_component = secrets.token_hex(16)
    timestamp = int(time.time())
    session_base = f"{uuid.uuid4()}-{random_component}-{timestamp}"
    
    # Creamos una firma HMAC para verificar integridad
    signature = hmac.new(
        SECRET_KEY.encode(),
        session_base.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Devolvemos ID con firma para verificación posterior
    return f"{session_base}|{signature}"

def validate_session_id(session_id: str) -> bool:
    """Valida que un ID de sesión sea legítimo y no haya expirado."""
    try:
        # Separamos el ID base de la firma
        if "|" not in session_id:
            logger.warning(f"Formato de session_id inválido: {session_id}")
            return False
            
        base, signature = session_id.split("|", 1)
        
        # Verificamos la firma HMAC
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            base.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning(f"Firma de session_id inválida: {session_id}")
            return False
        
        # Verificamos la expiración
        try:
            components = base.split("-")
            if len(components) < 3:
                return False
                
            timestamp = int(components[-1])
            current_time = int(time.time())
            
            if current_time - timestamp > SESSION_TIMEOUT:
                logger.warning(f"Session_id expirado: {session_id}")
                return False
                
            return True
        except (ValueError, IndexError):
            logger.warning(f"Error al procesar timestamp en session_id: {session_id}")
            return False
    except Exception as e:
        logger.error(f"Error en validación de session_id: {e}")
        return False

def sanitize_input(text: str) -> str:
    """Sanitiza texto de entrada para prevenir inyecciones."""
    if not text:
        return ""
        
    # Reemplazamos caracteres que podrían ser peligrosos
    sanitized = text
    
    # Escapamos caracteres especiales JSON
    sanitized = sanitized.replace("\\", "\\\\")
    sanitized = sanitized.replace('"', '\\"')
    
    # Eliminamos caracteres de control
    sanitized = ''.join(c for c in sanitized if ord(c) >= 32 or c == '\n')
    
    # Detectamos y bloqueamos patrones maliciosos
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, sanitized):
            logger.warning(f"Detectado patrón malicioso en texto: {pattern}")
            sanitized = re.sub(pattern, "[CONTENIDO FILTRADO]", sanitized)
    
    return sanitized

def validate_json_structure(data: Dict) -> bool:
    """Valida que un diccionario JSON tenga la estructura esperada."""
    required_fields = ["type", "tool", "arguments", "session_id"]
    
    # Verificamos campos requeridos
    for field in required_fields:
        if field not in data:
            logger.warning(f"Campo requerido faltante en JSON: {field}")
            return False
    
    # Verificamos tipos de datos
    if not isinstance(data["type"], str):
        logger.warning(f"Campo 'type' debe ser string")
        return False
        
    if not isinstance(data["tool"], str):
        logger.warning(f"Campo 'tool' debe ser string")
        return False
        
    if not isinstance(data["arguments"], dict):
        logger.warning(f"Campo 'arguments' debe ser un diccionario")
        return False
        
    if not isinstance(data["session_id"], str):
        logger.warning(f"Campo 'session_id' debe ser string")
        return False
    
    return True

def secure_socket_communication(message: Dict, timeout: int = 10) -> Tuple[bool, Any]:
    """Establece comunicación segura con el servidor MCP."""
    try:
        # Validamos estructura del mensaje antes de enviar
        if not validate_json_structure(message):
            return False, "Estructura de mensaje inválida"
        
        # Validamos session_id
        if not validate_session_id(message["session_id"]):
            return False, "ID de sesión inválido o expirado"
        
        # Preparamos el mensaje con sanitización
        sanitized_message = message.copy()
        
        # Sanitizamos argumentos
        if "nota" in sanitized_message["arguments"]:
            sanitized_message["arguments"]["nota"] = sanitize_input(
                sanitized_message["arguments"]["nota"]
            )
            
            # Limitamos longitud del contenido
            if len(sanitized_message["arguments"]["nota"]) > MAX_CONTENT_LENGTH:
                sanitized_message["arguments"]["nota"] = sanitized_message["arguments"]["nota"][:MAX_CONTENT_LENGTH] + "..."
                logger.warning("Contenido truncado por exceder longitud máxima")
        
        # Convertimos a JSON y enviamos
        json_data = json.dumps(sanitized_message) + "\n"
        
        # Creamos socket con timeout
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=timeout) as sock:
            # Enviamos datos
            sock.sendall(json_data.encode("utf-8"))
            
            # Recibimos respuesta con límite de tamaño para prevenir DoS
            chunks = []
            max_size = 16384  # 16KB máximo total
            total_received = 0
            
            while total_received < max_size:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                    
                chunks.append(chunk)
                total_received += len(chunk)
                
                # Si recibimos demasiados datos, abortamos
                if total_received >= max_size:
                    logger.warning("Respuesta demasiado grande, posible ataque DoS")
                    break
            
            response_data = b''.join(chunks)
            
            # Intentamos parsear la respuesta
            try:
                response = json.loads(response_data.decode("utf-8"))
                return True, response.get("text", "Operación completada")
            except json.JSONDecodeError:
                # Si falla el JSON, devolvemos el texto crudo pero sanitizado
                raw_text = response_data.decode("utf-8", errors="replace")
                sanitized_response = sanitize_input(raw_text)
                logger.warning("Error decodificando JSON de respuesta")
                return False, sanitized_response
    
    except socket.timeout:
        logger.error("Timeout en conexión con servidor MCP")
        return False, "Error: Timeout en conexión con servidor"
    except ConnectionRefusedError:
        logger.error("Conexión rechazada por el servidor MCP")
        return False, "Error: Servidor MCP no disponible"
    except Exception as e:
        logger.error(f"Error en comunicación con servidor MCP: {e}")
        return False, f"Error de comunicación: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# Importación segura de módulos
# ─────────────────────────────────────────────────────────────────────────────

try:
    # Añadimos el directorio raíz al path para importar prompts
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(base_dir) and os.path.isdir(base_dir):
        sys.path.append(base_dir)
        logger.info(f"Directorio base añadido al path: {base_dir}")
    else:
        logger.warning(f"Directorio base no encontrado: {base_dir}")
        
    # Importamos módulos con manejo de excepciones
    try:
        from prompts import educativo
        logger.info("Módulo educativo importado correctamente")
    except ImportError:
        logger.warning("Módulo prompts.educativo no encontrado. Se usarán prompts por defecto.")
        educativo = None
except Exception as e:
    logger.error(f"Error configurando path e importaciones: {e}")
    educativo = None

# Importaciones para LLM con verificación
try:
    from langchain_ollama import OllamaLLM
    logger.info("Módulo LangChain importado correctamente")
except ImportError as e:
    logger.critical(f"Error importando dependencias críticas: {e}")
    print(f"Error crítico: No se pueden cargar dependencias necesarias. Consulte el log para más detalles.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Inicialización segura
# ─────────────────────────────────────────────────────────────────────────────

# Generamos ID de sesión seguro
SESSION_ID = generate_secure_session_id()
logger.info(f"Sesión MCP inicializada con ID seguro: {SESSION_ID.split('|')[0]}...")

# LLM: Ollama con modelo gemma3:1b (usando timeouts)
llm = OllamaLLM(
    model="gemma3:1b",
    temperature=0.2,  # Menos aleatorio para mayor determinismo
    stop_sequences=["<script", "```", "sudo ", "rm -"],  # Bloqueamos secuencias potencialmente peligrosas
)

# ─────────────────────────────────────────────────────────────────────────────
# Herramientas MCP securizadas
# ─────────────────────────────────────────────────────────────────────────────

def leer_notas() -> str:
    """Lee todas las notas académicas registradas en esta sesión de forma segura."""
    msg = {
        "type": "call_tool",
        "tool": "leer_notas",
        "arguments": {},
        "session_id": SESSION_ID
    }
    
    success, result = secure_socket_communication(msg)
    
    if success:
        logger.info("Notas leídas exitosamente")
        return result
    else:
        logger.warning(f"Error al leer notas: {result}")
        return "No se pudieron recuperar las notas debido a un error de comunicación."

def append_nota(nota: str, max_retries: int = 2) -> str:
    """
    Agrega una nota textual al registro académico con seguridad mejorada.
    
    Args:
        nota: El texto de la nota a agregar (será sanitizado)
        max_retries: Número máximo de intentos en caso de error
    """
    # Sanitizamos la nota antes de procesarla
    sanitized_nota = sanitize_input(nota)
    
    # Verificamos límites de tamaño
    if len(sanitized_nota) > MAX_CONTENT_LENGTH:
        logger.warning(f"Nota excede tamaño máximo ({len(sanitized_nota)} > {MAX_CONTENT_LENGTH}), truncando...")
        sanitized_nota = sanitized_nota[:MAX_CONTENT_LENGTH] + "...[Contenido truncado por seguridad]"
    
    # Mensaje base
    msg = {
        "type": "call_tool",
        "tool": "append_nota",
        "arguments": {"nota": sanitized_nota},
        "session_id": SESSION_ID
    }
    
    # Implementamos reintentos con backoff exponencial
    attempt = 0
    while attempt < max_retries:
        success, result = secure_socket_communication(msg)
        
        if success:
            logger.info(f"Nota agregada exitosamente (intento {attempt+1})")
            return result
        else:
            logger.warning(f"Error al agregar nota (intento {attempt+1}): {result}")
            # Backoff exponencial entre reintentos
            wait_time = 2 ** attempt
            time.sleep(wait_time)
            attempt += 1
    
    return "No se pudo agregar la nota después de varios intentos. Por favor, inténtelo de nuevo más tarde."

# ─────────────────────────────────────────────────────────────────────────────
# Pipeline de procesamiento de prompts educativos con seguridad
# ─────────────────────────────────────────────────────────────────────────────

def ejecutar_pipeline_educativo(topic: str, nivel: str = "intermedio") -> str:
    """
    Ejecuta el pipeline de prompts educativos con seguridad mejorada.
    
    Args:
        topic: El tema principal sobre el que generar contenido (será sanitizado)
        nivel: El nivel de profundidad (básico, intermedio, avanzado)
    
    Returns:
        El contenido educativo generado y sanitizado
    """
    # Sanitizamos los parámetros
    topic_sanitized = sanitize_input(topic)
    nivel_sanitized = sanitize_input(nivel).lower()
    
    # Validamos el nivel
    niveles_validos = ["básico", "basico", "intermedio", "avanzado"]
    if nivel_sanitized not in niveles_validos:
        logger.warning(f"Nivel inválido: {nivel_sanitized}, usando 'intermedio'")
        nivel_sanitized = "intermedio"
    
    logger.info(f"Generando contenido educativo sobre: {topic_sanitized} (nivel: {nivel_sanitized})")
    
    # Obtenemos el prompt adecuado con manejo seguro de excepciones
    try:
        if educativo and hasattr(educativo, "get_prompt"):
            prompt_educativo = educativo.get_prompt(topic=topic_sanitized, nivel=nivel_sanitized)
            logger.info("Usando prompt del módulo educativo")
        elif educativo and hasattr(educativo, f"TEMPLATE_{nivel_sanitized.upper()}"):
            template = getattr(educativo, f"TEMPLATE_{nivel_sanitized.upper()}")
            prompt_educativo = template.format(topic=topic_sanitized)
            logger.info(f"Usando template {nivel_sanitized.upper()} del módulo educativo")
        else:
            # Usamos un prompt por defecto
            prompt_educativo = crear_prompt_por_defecto(topic_sanitized, nivel_sanitized)
            logger.info("Usando prompt por defecto")
    except Exception as e:
        logger.error(f"Error al obtener prompt: {e}")
        prompt_educativo = crear_prompt_por_defecto(topic_sanitized, nivel_sanitized)
        logger.info("Fallback a prompt por defecto tras error")
    
    # Generamos contenido con el LLM usando el prompt
    try:
        # Añadimos instrucciones de seguridad al prompt
        safe_prompt = prompt_educativo + "\n\nIMPORTANTE: No incluyas código ejecutable, scripts, comandos del sistema o contenido que pueda ser interpretado como malicioso."
        
        # Generamos con timeout para evitar bloqueos
        start_time = time.time()
        contenido = llm.invoke(safe_prompt)
        generation_time = time.time() - start_time
        
        logger.info(f"Contenido generado en {generation_time:.2f} segundos")
        
        if hasattr(contenido, 'content'):
            contenido = contenido.content
        
        # Sanitizamos el resultado
        contenido_sanitizado = sanitize_input(contenido)
        
        return contenido_sanitizado
    except Exception as e:
        logger.error(f"Error al invocar LLM: {e}")
        return f"Error al generar contenido educativo. Por favor, inténtelo de nuevo más tarde."

def crear_prompt_por_defecto(topic: str, nivel: str) -> str:
    """Crea un prompt educativo por defecto con controles de seguridad."""
    niveles = {
        "básico": "conceptos fundamentales, explicaciones sencillas y ejemplos cotidianos",
        "basico": "conceptos fundamentales, explicaciones sencillas y ejemplos cotidianos",
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
    
    RESTRICCIONES DE SEGURIDAD:
    - No incluyas fragmentos de código ejecutable
    - No menciones comandos del sistema operativo
    - No incluyas instrucciones que puedan ser interpretadas como maliciosas
    - Mantén el contenido educativo y apropiado
    """

# ─────────────────────────────────────────────────────────────────────────────
# Ejecución secuencial con pipeline educativo y seguridad
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        logger.info("=== Iniciando ejecución segura del agente MCP ===")
        print(f"🧠 Ejecutando sesión MCP con session_id: {SESSION_ID.split('|')[0]}...")
        
        # 1. Primero leemos las notas existentes
        print("\n--- Paso 1: Leyendo notas existentes de forma segura ---")
        result_leer = leer_notas()
        print(f"🔍 Resultado: {result_leer}")
        logger.info("Lectura de notas completada")
        
        # 2. Generamos nuevo contenido educativo
        print("\n--- Paso 2: Generando contenido educativo seguro ---")
        tema = "LangChain y su integración con MCP"
        nivel = "intermedio"
        
        nuevo_contenido = ejecutar_pipeline_educativo(tema, nivel)
        
        # Verificamos longitud para mostrar en consola
        if len(nuevo_contenido) > 1000:
            print(f"📝 Contenido generado sobre {tema} (nivel {nivel}):")
            print("---------------------------------------------------")
            print(nuevo_contenido[:1000] + "...\n[Contenido truncado para visualización]")
            print("---------------------------------------------------")
        else:
            print(f"📝 Contenido generado sobre {tema} (nivel {nivel}):")
            print("---------------------------------------------------")
            print(nuevo_contenido)
            print("---------------------------------------------------")
        
        logger.info(f"Contenido educativo generado ({len(nuevo_contenido)} caracteres)")
        
        # 3. Guardamos la nota de forma segura
        print("\n--- Paso 3: Guardando nota educativa de forma segura ---")
        result_append = append_nota(nuevo_contenido)
        print(f"✅ Resultado: {result_append}")
        logger.info("Nota guardada exitosamente")
        
        print("\n--- Proceso de pipeline educativo seguro completado ---")
        logger.info("=== Finalizada ejecución segura del agente MCP ===")
    
    except KeyboardInterrupt:
        print("\n⚠️ Ejecución interrumpida por el usuario")
        logger.warning("Ejecución interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error general en la ejecución: {e}")
        logger.error(f"Error general en la ejecución: {e}", exc_info=True)