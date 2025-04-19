#!/usr/bin/env python3
import socket
import json
import threading
import os
import hmac
import hashlib
import re
import time
import logging
import secrets
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple

# Importar handler original
try:
    from handler import handle_message
    from registry import init_registry
except ImportError as e:
    print(f"Error importando módulos originales: {e}")
    print("Usando implementaciones de fallback...")
    
    # Implementación de fallback para handle_message
    def handle_message(message):
        """Implementación de fallback para handle_message."""
        return {"text": f"Mensaje recibido: {message.get('tool')} - Operación simulada."}
    
    # Implementación de fallback para init_registry
    def init_registry():
        """Implementación de fallback para init_registry."""
        print("Inicializando registro (fallback)...")

# ─────────────────────────────────────────────────────────────────────────────
# Configuración de logging seguro
# ─────────────────────────────────────────────────────────────────────────────

# Configuración de logging
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, f"mcp_server_{datetime.now().strftime('%Y%m%d')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s - [%(filename)s:%(lineno)d]',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mcp_server")

# ─────────────────────────────────────────────────────────────────────────────
# Configuración de seguridad
# ─────────────────────────────────────────────────────────────────────────────

# En producción, cargar estas configuraciones de variables de entorno o un archivo de configuración seguro
HOST = "127.0.0.1"  # Solo permitir conexiones locales para mayor seguridad
PORT = 5050
BUFFER_SIZE = 4096
MAX_BUFFER_SIZE = 1024 * 1024  # 1MB límite máximo
MAX_CONNECTIONS = 10  # Limitar conexiones simultáneas
CONNECTION_TIMEOUT = 30  # Timeout en segundos
MAX_REQUESTS_PER_MINUTE = 30  # Límite de tasa para evitar abusos

# Clave secreta para firmar sesiones
SECRET_KEY = os.environ.get("MCP_SECRET_KEY", secrets.token_hex(32))
SESSION_TIMEOUT = 3600  # Sesión expira después de 1 hora

# Lista de patrones maliciosos a filtrar
MALICIOUS_PATTERNS = [
    r"<script.*?>.*?</script>",  # Scripts JS
    r".*?`.*?`.*?",  # Inyección de comandos
    r"(?:--.*?$|;.*?--)",  # Inyección SQL
    r"(?i)(?:eval|exec|system|popen|subprocess)",  # Funciones peligrosas
]

# Diccionario para limitar tasa por IP
rate_limits: Dict[str, list] = {}
# Diccionario para almacenar sesiones activas
active_sessions: Dict[str, datetime] = {}
# Mutex para rate_limits y active_sessions
lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Funciones de seguridad
# ─────────────────────────────────────────────────────────────────────────────

def validate_session_id(session_id: str) -> bool:
    """Valida que un ID de sesión sea legítimo y no haya expirado."""
    # Para compatibilidad con el código existente, acepta cualquier session_id
    # que no tenga el formato nuevo (para evitar romper clientes existentes)
    if "|" not in session_id:
        return True
        
    try:
        base, signature = session_id.split("|", 1)
        
        # Verificamos la firma HMAC
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            base.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning(f"Firma de session_id inválida: {session_id[:20]}...")
            return False
        
        # Verificamos si la sesión está en nuestro registro con lock para thread-safety
        with lock:
            expiry_time = active_sessions.get(session_id)
            if not expiry_time:
                # Verificamos si hay un timestamp en el session_id
                try:
                    components = base.split("-")
                    if len(components) >= 3:
                        timestamp = int(components[-1])
                        current_time = int(time.time())
                        if current_time - timestamp > SESSION_TIMEOUT:
                            logger.warning(f"Session_id expirado: {session_id[:20]}...")
                            return False
                        
                        # Si es válido, lo registramos para futuras verificaciones
                        active_sessions[session_id] = datetime.now() + timedelta(seconds=SESSION_TIMEOUT)
                        # Limpiamos sesiones expiradas ocasionalmente
                        if len(active_sessions) % 10 == 0:  # Cada 10 nuevas sesiones
                            cleanup_expired_sessions()
                        return True
                    else:
                        return False
                except (ValueError, IndexError):
                    logger.warning(f"Error al procesar timestamp en session_id: {session_id[:20]}...")
                    return False
            else:
                # Verificamos si la sesión ha expirado
                if expiry_time < datetime.now():
                    with lock:
                        active_sessions.pop(session_id, None)
                    logger.warning(f"Sesión expirada: {session_id[:20]}...")
                    return False
                return True
                
    except Exception as e:
        logger.error(f"Error en validación de session_id: {e}")
        return False

def cleanup_expired_sessions():
    """Limpia sesiones expiradas del diccionario de sesiones activas."""
    now = datetime.now()
    expired = [sid for sid, expiry in active_sessions.items() if expiry < now]
    for sid in expired:
        active_sessions.pop(sid, None)
    if expired:
        logger.info(f"Limpiadas {len(expired)} sesiones expiradas. {len(active_sessions)} activas.")

def check_rate_limit(client_addr: str) -> bool:
    """
    Verifica si una dirección IP ha excedido su límite de solicitudes.
    Implementa rate limiting basado en sliding window.
    """
    now = time.time()
    minute_ago = now - 60
    
    with lock:
        # Inicializamos si es un nuevo cliente
        if client_addr not in rate_limits:
            rate_limits[client_addr] = []
        
        # Filtrar timestamps antiguos
        rate_limits[client_addr] = [t for t in rate_limits[client_addr] if t > minute_ago]
        
        # Verificar límite
        if len(rate_limits[client_addr]) >= MAX_REQUESTS_PER_MINUTE:
            logger.warning(f"Rate limit excedido para {client_addr}: {len(rate_limits[client_addr])} req/min")
            return False
        
        # Registrar nueva solicitud
        rate_limits[client_addr].append(now)
        
        # Limpiar ocasionalmente las entradas antiguas
        if len(rate_limits) > 100:  # Si hay muchos clientes
            old_clients = [addr for addr, timestamps in rate_limits.items() 
                          if not timestamps or timestamps[-1] < minute_ago]
            for addr in old_clients:
                rate_limits.pop(addr, None)
        
        return True

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
            logger.warning(f"Detectado patrón malicioso en texto")
            sanitized = re.sub(pattern, "[CONTENIDO FILTRADO]", sanitized)
    
    return sanitized

def validate_message(message: Any) -> Tuple[bool, Optional[Dict], str]:
    """
    Valida la estructura y contenido de un mensaje.
    Retorna (is_valid, message_sanitized, error_message)
    """
    # Verificar que el mensaje es un diccionario
    if not isinstance(message, dict):
        return False, None, "El mensaje debe ser un objeto JSON"
    
    # Verificar campos requeridos
    required_fields = ["type", "tool"]
    for field in required_fields:
        if field not in message:
            return False, None, f"Campo requerido faltante: {field}"
    
    # Verificar tipos de datos
    if not isinstance(message.get("type"), str):
        return False, None, "El campo 'type' debe ser una cadena de texto"
    
    if not isinstance(message.get("tool"), str):
        return False, None, "El campo 'tool' debe ser una cadena de texto"
    
    # Validar session_id si existe
    if "session_id" in message:
        if not isinstance(message.get("session_id"), str):
            return False, None, "El campo 'session_id' debe ser una cadena de texto"
        
        if not validate_session_id(message.get("session_id", "")):
            return False, None, "ID de sesión inválido o expirado"
    
    # Sanitizar mensaje
    sanitized_message = message.copy()
    
    # Sanitizar tipo y herramienta
    sanitized_message["type"] = sanitize_input(sanitized_message["type"])
    sanitized_message["tool"] = sanitize_input(sanitized_message["tool"])
    
    # Sanitizar argumentos si existen
    if "arguments" in sanitized_message:
        if not isinstance(sanitized_message["arguments"], dict):
            return False, None, "El campo 'arguments' debe ser un objeto JSON"
        
        # Sanitizar cada argumento
        sanitized_args = {}
        for key, value in sanitized_message["arguments"].items():
            if isinstance(value, str):
                sanitized_args[sanitize_input(key)] = sanitize_input(value)
            else:
                sanitized_args[sanitize_input(key)] = value
        
        sanitized_message["arguments"] = sanitized_args
    
    return True, sanitized_message, ""

# ─────────────────────────────────────────────────────────────────────────────
# Manejador de clientes
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(conn, addr):
    """Maneja una conexión de cliente de forma segura."""
    client_id = f"{addr[0]}:{addr[1]}"
    logger.info(f"📡 Nueva conexión desde {client_id}")
    
    # Establecer timeout para prevenir conexiones zombies
    conn.settimeout(CONNECTION_TIMEOUT)
    
    try:
        with conn:
            buffer = b""
            total_size = 0
            
            while True:
                try:
                    # Verificar rate limit
                    if not check_rate_limit(addr[0]):
                        error_response = {
                            "error": "Demasiadas solicitudes. Inténtalo más tarde.",
                            "code": 429
                        }
                        conn.sendall((json.dumps(error_response) + "\n").encode("utf-8"))
                        logger.warning(f"Rate limit aplicado a {client_id}")
                        break
                    
                    # Recibir datos con límite de tamaño
                    chunk = conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    
                    # Actualizar buffer y tamaño total
                    buffer += chunk
                    total_size += len(chunk)
                    
                    # Verificar tamaño máximo
                    if total_size > MAX_BUFFER_SIZE:
                        error_response = {
                            "error": "Mensaje demasiado grande",
                            "code": 413
                        }
                        conn.sendall((json.dumps(error_response) + "\n").encode("utf-8"))
                        logger.warning(f"Mensaje excede tamaño máximo de {client_id}")
                        break
                    
                    # Intentar decodificar JSON
                    try:
                        message = json.loads(buffer.decode("utf-8"))
                        
                        # Validar y sanitizar mensaje
                        is_valid, sanitized_msg, error = validate_message(message)
                        
                        if not is_valid:
                            error_response = {
                                "error": error,
                                "code": 400
                            }
                            conn.sendall((json.dumps(error_response) + "\n").encode("utf-8"))
                            logger.warning(f"Mensaje inválido de {client_id}: {error}")
                            break
                        
                        # Procesar mensaje validado
                        logger.info(f"Procesando mensaje de {client_id}: {sanitized_msg['tool']}")
                        start_time = time.time()
                        response = handle_message(sanitized_msg)
                        process_time = time.time() - start_time
                        logger.info(f"Mensaje procesado en {process_time:.4f}s")
                        
                        # Sanitizar respuesta antes de enviar
                        if "text" in response and isinstance(response["text"], str):
                            response["text"] = sanitize_input(response["text"])
                        
                        # Enviar respuesta
                        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                        buffer = b""
                        total_size = 0
                        
                    except json.JSONDecodeError:
                        # Si no es JSON válido todavía, esperar más datos
                        continue
                        
                except socket.timeout:
                    logger.warning(f"Timeout de conexión para {client_id}")
                    break
                    
    except Exception as e:
        logger.error(f"❌ Error manejando cliente {client_id}: {e}", exc_info=True)
    finally:
        logger.info(f"🔌 Conexión cerrada: {client_id}")

# ─────────────────────────────────────────────────────────────────────────────
# Manejo de señales
# ─────────────────────────────────────────────────────────────────────────────

def signal_handler(sig, frame):
    """Maneja señales para cierre graceful del servidor."""
    logger.info("Señal de terminación recibida. Cerrando servidor...")
    sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Función principal del servidor MCP."""
    # Registrar manejadores de señales
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Inicializar registros
    try:
        init_registry()
        logger.info("Registro inicializado correctamente")
    except Exception as e:
        logger.warning(f"Error inicializando registro, usando fallback: {e}")
        # Continuamos con la implementación de fallback

    # Crear socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Tiempo de espera para cierre de socket
    server_socket.settimeout(1.0)

    try:
        # Enlazar socket
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CONNECTIONS)
        
        logger.info(f"✅ Servidor MCP seguro escuchando en {HOST}:{PORT}")
        print(f"✅ Servidor MCP seguro escuchando en {HOST}:{PORT}")
        
        # Lista de hilos de cliente activos
        client_threads = []
        
        # Bucle principal
        while True:
            try:
                # Aceptar conexión
                client_sock, addr = server_socket.accept()
                
                # Limpiar hilos terminados
                client_threads = [t for t in client_threads if t.is_alive()]
                
                # Verificar límite de conexiones
                if len(client_threads) >= MAX_CONNECTIONS:
                    logger.warning(f"Máximo de conexiones alcanzado. Rechazando {addr}")
                    client_sock.close()
                    continue
                
                # Crear y arrancar nuevo hilo
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_sock, addr),
                    name=f"Client-{addr[0]}:{addr[1]}",
                    daemon=True
                )
                client_threads.append(client_thread)
                client_thread.start()
                
                logger.info(f"Hilos activos: {len(client_threads)}")
                
            except socket.timeout:
                # Timeout normal para permitir verificar señales
                continue
            except Exception as e:
                logger.error(f"Error aceptando conexión: {e}")
                time.sleep(1)  # Pausa para evitar bucle rápido en caso de error
                
    except Exception as e:
        logger.critical(f"Error fatal en servidor: {e}", exc_info=True)
    finally:
        # Cerrar socket
        logger.info("Cerrando servidor MCP")
        server_socket.close()

if __name__ == "__main__":
    main()