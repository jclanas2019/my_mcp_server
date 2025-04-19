#!/usr/bin/env python3
import socket
import json
import uuid
import time
import warnings
import os
import sys
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple, Union

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s - [%(filename)s:%(lineno)d]',
    handlers=[
        logging.FileHandler("mcp_agent_discovery.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mcp_agent")

# Suprimimos warnings de depreciación
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Importaciones para LLM
try:
    from langchain_ollama import OllamaLLM
    logger.info("Módulo LangChain importado correctamente")
except ImportError as e:
    logger.critical(f"Error importando dependencias críticas: {e}")
    print(f"Error crítico: No se pueden cargar dependencias necesarias. Consulte el log para más detalles.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────────────────

# Configuración del servidor MCP
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5050
TIMEOUT = 5  # Reducimos el timeout para evitar esperas largas
MAX_RETRIES = 2  # Número máximo de reintentos para operaciones

# ─────────────────────────────────────────────────────────────────────────────
# ID de sesión único por ejecución de agente
# ─────────────────────────────────────────────────────────────────────────────

SESSION_ID = str(uuid.uuid4())
logger.info(f"Sesión MCP inicializada con ID: {SESSION_ID}")

# ─────────────────────────────────────────────────────────────────────────────
# LLM: Ollama con modelo gemma3:1b
# ─────────────────────────────────────────────────────────────────────────────

llm = OllamaLLM(
    model="gemma3:1b",
    temperature=0.7,
)
logger.info(f"Modelo LLM inicializado: gemma3:1b")

# ─────────────────────────────────────────────────────────────────────────────
# Implementación fallback para herramientas básicas
# ─────────────────────────────────────────────────────────────────────────────

class FallbackTools:
    """Implementación de herramientas que funciona incluso sin servidor."""
    
    def __init__(self):
        self.notas = []
        logger.info("Modo fallback: Herramientas básicas inicializadas localmente")
    
    def append_nota(self, nota: str) -> str:
        """Agrega una nota al almacenamiento local."""
        if not nota:
            return "Error: Nota vacía"
        self.notas.append(nota)
        return f"Nota registrada localmente: {nota}"
    
    def leer_notas(self) -> str:
        """Lee todas las notas del almacenamiento local."""
        if not self.notas:
            return "No hay notas registradas localmente."
        return "Notas registradas localmente:\n" + "\n".join(f"- {n}" for n in self.notas)

# Instancia global para fallback
fallback_tools = FallbackTools()

# ─────────────────────────────────────────────────────────────────────────────
# Registro local de herramientas descubiertas
# ─────────────────────────────────────────────────────────────────────────────

class ToolRegistry:
    """Registro local de herramientas descubiertas del servidor MCP."""
    
    def __init__(self):
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.last_discovery: float = 0
        self.discovery_ttl: int = 300  # Tiempo de vida del cache en segundos (5 minutos)
        self.fallback_mode: bool = False
    
    def add_tool(self, name: str, metadata: Dict[str, Any]):
        """Añade una herramienta al registro local."""
        self.tools[name] = metadata
        logger.info(f"Herramienta '{name}' añadida al registro local")
    
    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """Obtiene los metadatos de una herramienta por su nombre."""
        return self.tools.get(name)
    
    def list_tools(self) -> List[str]:
        """Lista los nombres de todas las herramientas registradas."""
        return list(self.tools.keys())
    
    def should_refresh(self) -> bool:
        """Determina si es necesario actualizar el registro desde el servidor."""
        current_time = time.time()
        return current_time - self.last_discovery > self.discovery_ttl
    
    def mark_refreshed(self):
        """Marca el registro como actualizado."""
        self.last_discovery = time.time()
    
    def clear(self):
        """Limpia el registro local."""
        self.tools = {}
        logger.info("Registro local limpiado")
    
    def enable_fallback_mode(self):
        """Habilita el modo fallback con herramientas básicas locales."""
        self.fallback_mode = True
        self.clear()
        
        # Registramos herramientas básicas simuladas
        self.add_tool("append_nota", {
            "description": "Agrega una nueva nota textual localmente (modo fallback).",
            "params": {
                "nota": {
                    "type": "string",
                    "description": "Texto de la nota a registrar",
                    "required": True
                }
            },
            "examples": [
                {"nota": "Esta es una nota de ejemplo"}
            ],
            "returns": "Confirmación de que la nota ha sido registrada localmente"
        })
        
        self.add_tool("leer_notas", {
            "description": "Lee todas las notas registradas localmente (modo fallback).",
            "params": {},
            "examples": [{}],
            "returns": "Lista de notas registradas o mensaje indicando que no hay notas"
        })
        
        logger.warning("Modo fallback activado con herramientas básicas locales")
    
    def disable_fallback_mode(self):
        """Deshabilita el modo fallback."""
        self.fallback_mode = False
        logger.info("Modo fallback desactivado")

# Instancia global del registro local
tool_registry = ToolRegistry()

# ─────────────────────────────────────────────────────────────────────────────
# Funciones de comunicación con el servidor MCP
# ─────────────────────────────────────────────────────────────────────────────

def check_server_status() -> bool:
    """
    Verifica si el servidor MCP está disponible.
    
    Returns:
        True si el servidor está disponible, False en caso contrario
    """
    try:
        # Intentamos conectarnos al servidor (socket simple, sin enviar datos)
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=2) as sock:
            # Si llegamos aquí, la conexión fue exitosa
            logger.info("Servidor MCP disponible")
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.warning(f"Servidor MCP no disponible en {SERVER_HOST}:{SERVER_PORT}")
        return False

def send_mcp_request(message: Dict[str, Any], timeout: int = TIMEOUT) -> Tuple[bool, Any]:
    """
    Envía una solicitud al servidor MCP y procesa la respuesta.
    
    Args:
        message: Mensaje a enviar al servidor
        timeout: Timeout para la conexión en segundos
    
    Returns:
        Tupla de (éxito, resultado)
    """
    # Si estamos en modo fallback, ni siquiera intentamos la conexión
    if tool_registry.fallback_mode:
        return False, "Servidor no disponible (modo fallback)"
    
    # Verificamos rápidamente si el servidor está disponible
    if not check_server_status():
        logger.warning("Omitiendo solicitud porque el servidor no está disponible")
        return False, "Servidor MCP no disponible"
    
    # Aseguramos que el mensaje tenga un session_id
    if "session_id" not in message:
        message["session_id"] = SESSION_ID
    
    try:
        # Creamos socket con timeout
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=timeout) as sock:
            # Enviamos datos
            json_data = json.dumps(message) + "\n"
            sock.sendall(json_data.encode("utf-8"))
            
            # Recibimos respuesta
            chunks = []
            sock.settimeout(timeout)  # Aseguramos timeout para recepción
            
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except socket.timeout:
                # Si timeout en recepción, usamos lo que hemos recibido hasta ahora
                logger.warning("Timeout recibiendo datos, usando datos parciales")
            
            response_data = b''.join(chunks)
            
            # Intentamos parsear la respuesta JSON
            try:
                response = json.loads(response_data.decode("utf-8"))
                return True, response
            except json.JSONDecodeError as e:
                logger.warning(f"Error decodificando JSON de respuesta: {e}")
                return False, response_data.decode("utf-8", errors="replace")
                
    except socket.timeout:
        logger.error("Timeout en conexión con servidor MCP")
        return False, "Error: Timeout en conexión con servidor"
    except ConnectionRefusedError:
        logger.error("Conexión rechazada por el servidor MCP")
        return False, "Error: Servidor MCP no disponible"
    except Exception as e:
        logger.error(f"Error en comunicación con servidor MCP: {e}")
        return False, f"Error de comunicación: {str(e)}"

def discover_tools(force_fallback: bool = False) -> bool:
    """
    Descubre automáticamente las herramientas disponibles en el servidor MCP.
    
    Args:
        force_fallback: Si es True, fuerza el modo fallback sin consultar al servidor
    
    Returns:
        True si el descubrimiento fue exitoso (o fallback activado), False en caso contrario.
    """
    logger.info("Iniciando descubrimiento de herramientas...")
    
    # Si se fuerza el modo fallback o no se puede conectar al servidor
    if force_fallback or not check_server_status():
        logger.warning("Activando modo fallback por servidor no disponible")
        tool_registry.enable_fallback_mode()
        return True
    
    # Si el registro no necesita actualizarse, usamos la caché
    if not tool_registry.should_refresh() and tool_registry.tools:
        logger.info(f"Usando caché de herramientas (TTL: {tool_registry.discovery_ttl}s)")
        return True
    
    # Solicitamos los metadatos de todas las herramientas
    msg = {
        "type": "get_all_tools_metadata",
        "session_id": SESSION_ID
    }
    
    success, result = send_mcp_request(msg)
    
    if not success:
        logger.error(f"Error en discovery de herramientas: {result}")
        logger.warning("Activando modo fallback por error en discovery")
        tool_registry.enable_fallback_mode()
        return True  # Retornamos True porque activamos fallback
    
    # Verificamos la respuesta
    if not isinstance(result, dict) or "metadata" not in result:
        logger.error(f"Respuesta de discovery inválida: {result}")
        tool_registry.enable_fallback_mode()
        return True  # Retornamos True porque activamos fallback
    
    # Desactivamos modo fallback si estaba activado
    if tool_registry.fallback_mode:
        tool_registry.disable_fallback_mode()
    
    # Limpiamos el registro actual
    tool_registry.clear()
    
    # Registramos las herramientas descubiertas
    for tool_name, metadata in result.get("metadata", {}).items():
        tool_registry.add_tool(tool_name, metadata)
    
    # Marcamos el registro como actualizado
    tool_registry.mark_refreshed()
    
    logger.info(f"Discovery completado: {len(tool_registry.list_tools())} herramientas descubiertas")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Generador dinámico de funciones para herramientas
# ─────────────────────────────────────────────────────────────────────────────

def create_tool_function(tool_name: str, metadata: Dict[str, Any]) -> Callable:
    """
    Crea dinámicamente una función que representa a una herramienta.
    
    Args:
        tool_name: Nombre de la herramienta
        metadata: Metadatos de la herramienta
    
    Returns:
        Función que ejecuta la herramienta
    """
    def tool_function(**kwargs) -> str:
        """Función generada dinámicamente para la herramienta."""
        # Si estamos en modo fallback, usamos implementación local
        if tool_registry.fallback_mode:
            if tool_name == "append_nota" and hasattr(fallback_tools, "append_nota"):
                return fallback_tools.append_nota(kwargs.get("nota", ""))
            
            elif tool_name == "leer_notas" and hasattr(fallback_tools, "leer_notas"):
                return fallback_tools.leer_notas()
            
            else:
                return f"Herramienta '{tool_name}' no disponible en modo fallback"
        
        # Validamos los argumentos según los metadatos
        if "params" in metadata:
            for param_name, param_info in metadata["params"].items():
                # Verificamos parámetros requeridos
                if param_info.get("required", False) and param_name not in kwargs:
                    return f"Error: Falta el parámetro requerido '{param_name}'"
        
        # Preparamos el mensaje para el servidor
        msg = {
            "type": "call_tool",
            "tool": tool_name,
            "arguments": kwargs,
            "session_id": SESSION_ID
        }
        
        # Implementamos reintentos
        attempt = 0
        while attempt < MAX_RETRIES:
            success, result = send_mcp_request(msg)
            
            if success and isinstance(result, dict) and "text" in result:
                return result["text"]
            
            # Si fallamos, reintentamos con backoff exponencial
            attempt += 1
            if attempt < MAX_RETRIES:
                retry_delay = 2 ** attempt  # 2, 4, 8 segundos...
                logger.warning(f"Reintentando llamada a '{tool_name}' en {retry_delay}s (intento {attempt+1}/{MAX_RETRIES})")
                time.sleep(retry_delay)
        
        # Si llegamos aquí, fallaron todos los intentos
        logger.error(f"Error al ejecutar '{tool_name}' después de {MAX_RETRIES} intentos. Activando fallback.")
        
        # Activamos fallback mode para futuras llamadas
        tool_registry.enable_fallback_mode()
        
        # Intentamos usar fallback para esta herramienta
        if tool_name == "append_nota" and hasattr(fallback_tools, "append_nota"):
            return fallback_tools.append_nota(kwargs.get("nota", ""))
        
        elif tool_name == "leer_notas" and hasattr(fallback_tools, "leer_notas"):
            return fallback_tools.leer_notas()
        
        return f"Error al ejecutar la herramienta '{tool_name}' después de {MAX_RETRIES} intentos"
    
    # Personalizamos la función con metadatos
    tool_function.__name__ = tool_name
    if "description" in metadata:
        tool_function.__doc__ = metadata["description"]
    
    return tool_function

# ─────────────────────────────────────────────────────────────────────────────
# API Dinámica para herramientas
# ─────────────────────────────────────────────────────────────────────────────

class MCPTools:
    """
    Clase que proporciona acceso dinámico a las herramientas del servidor MCP.
    Se actualiza automáticamente con las herramientas disponibles.
    """
    
    def __init__(self):
        """Inicializa la API dinámica de herramientas."""
        self._tool_functions = {}
        self._initialized = False
    
    def _ensure_initialized(self) -> bool:
        """
        Asegura que la API está inicializada con las herramientas actuales.
        Realiza discovery si es necesario.
        
        Returns:
            True si se inicializó correctamente, False en caso contrario
        """
        if not self._initialized or tool_registry.should_refresh():
            # Descubrimos las herramientas disponibles
            if not discover_tools():
                return False
            
            # Generamos dinámicamente las funciones
            self._tool_functions = {}
            for tool_name in tool_registry.list_tools():
                metadata = tool_registry.get_tool(tool_name)
                if metadata:
                    self._tool_functions[tool_name] = create_tool_function(tool_name, metadata)
            
            self._initialized = True
        
        return True
    
    def __getattr__(self, name: str) -> Callable:
        """
        Permite acceder a las herramientas como si fueran métodos de la clase.
        Ejemplo: mcp_tools.append_nota(nota="Hola mundo")
        
        Args:
            name: Nombre de la herramienta/método
            
        Returns:
            Función que ejecuta la herramienta
            
        Raises:
            AttributeError: Si la herramienta no existe
        """
        # Inicializamos si es necesario
        if not self._ensure_initialized():
            # Forzamos modo fallback si falla la inicialización
            discover_tools(force_fallback=True)
            self._ensure_initialized()
        
        # Verificamos si existe la herramienta
        if name in self._tool_functions:
            return self._tool_functions[name]
        
        # Si no existe, intentamos redescubrir (podría ser una herramienta nueva)
        tool_registry.last_discovery = 0  # Forzamos redescubrimiento
        if self._ensure_initialized() and name in self._tool_functions:
            return self._tool_functions[name]
        
        # Si sigue sin existir, verificamos si tenemos fallback para esta herramienta
        if name in ["append_nota", "leer_notas"]:
            # Forzamos modo fallback
            discover_tools(force_fallback=True)
            self._ensure_initialized()
            if name in self._tool_functions:
                return self._tool_functions[name]
        
        # Si todo lo anterior falla, es un error
        available_tools = ", ".join(self._tool_functions.keys())
        raise AttributeError(f"No existe la herramienta '{name}'. Herramientas disponibles: {available_tools}")
    
    def list_available_tools(self) -> List[str]:
        """
        Lista las herramientas disponibles.
        
        Returns:
            Lista de nombres de herramientas disponibles
        """
        # Aseguramos inicialización, forzando fallback si es necesario
        if not self._ensure_initialized():
            discover_tools(force_fallback=True)
            self._ensure_initialized()
        
        return list(self._tool_functions.keys())
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene información detallada sobre una herramienta.
        
        Args:
            tool_name: Nombre de la herramienta
            
        Returns:
            Diccionario con metadatos de la herramienta, o None si no existe
        """
        # Aseguramos inicialización, forzando fallback si es necesario
        if not self._ensure_initialized():
            discover_tools(force_fallback=True)
            self._ensure_initialized()
        
        return tool_registry.get_tool(tool_name)
    
    def show_tool_help(self, tool_name: str = None) -> str:
        """
        Muestra ayuda sobre las herramientas disponibles.
        
        Args:
            tool_name: Nombre específico de una herramienta, o None para mostrar todas
            
        Returns:
            Texto de ayuda formateado
        """
        # Aseguramos inicialización, forzando fallback si es necesario
        if not self._ensure_initialized():
            discover_tools(force_fallback=True)
            self._ensure_initialized()
        
        if tool_name:
            # Mostramos ayuda específica de una herramienta
            metadata = tool_registry.get_tool(tool_name)
            if not metadata:
                return f"No existe la herramienta '{tool_name}'"
            
            # Formateamos la ayuda
            help_text = [f"Herramienta: {tool_name}"]
            help_text.append("-" * 40)
            
            if "description" in metadata:
                help_text.append(f"Descripción: {metadata['description']}")
            
            if "params" in metadata and metadata["params"]:
                help_text.append("\nParámetros:")
                for param_name, param_info in metadata["params"].items():
                    required = " (requerido)" if param_info.get("required", False) else " (opcional)"
                    param_type = param_info.get("type", "string")
                    param_desc = param_info.get("description", "")
                    help_text.append(f"  {param_name}: {param_type}{required}")
                    if param_desc:
                        help_text.append(f"    {param_desc}")
            
            if "examples" in metadata and metadata["examples"]:
                help_text.append("\nEjemplos:")
                for i, example in enumerate(metadata["examples"], 1):
                    help_text.append(f"  Ejemplo {i}: {tool_name}({', '.join(f'{k}={v!r}' for k, v in example.items())})")
            
            if "returns" in metadata:
                help_text.append(f"\nRetorna: {metadata['returns']}")
            
            if tool_registry.fallback_mode:
                help_text.append("\n⚠️ NOTA: Funcionando en modo fallback (implementación local)")
            
            return "\n".join(help_text)
        else:
            # Mostramos lista de todas las herramientas
            tools = self.list_available_tools()
            if not tools:
                return "No hay herramientas disponibles"
            
            help_text = ["Herramientas disponibles:"]
            if tool_registry.fallback_mode:
                help_text[0] += " (MODO FALLBACK - Implementación local)"
            help_text.append("-" * 40)
            
            for tool_name in tools:
                metadata = tool_registry.get_tool(tool_name)
                description = metadata.get("description", "Sin descripción") if metadata else "Sin metadatos"
                help_text.append(f"{tool_name}: {description}")
            
            help_text.append("\nPara ver detalles de una herramienta específica, use show_tool_help('nombre_herramienta')")
            
            return "\n".join(help_text)
    
    def is_in_fallback_mode(self) -> bool:
        """
        Indica si se está funcionando en modo fallback.
        
        Returns:
            True si se está usando el modo fallback, False si se está conectando al servidor
        """
        return tool_registry.fallback_mode

# ─────────────────────────────────────────────────────────────────────────────
# Instancia global de herramientas MCP
# ─────────────────────────────────────────────────────────────────────────────

mcp_tools = MCPTools()

# ─────────────────────────────────────────────────────────────────────────────
# Funciones de uso común
# ─────────────────────────────────────────────────────────────────────────────

def generate_content(prompt: str) -> str:
    """
    Genera contenido usando el LLM.
    
    Args:
        prompt: Texto de prompt para el LLM
        
    Returns:
        Contenido generado
    """
    try:
        # Generamos contenido con el LLM
        start_time = time.time()
        response = llm.invoke(prompt)
        generation_time = time.time() - start_time
        
        logger.info(f"Contenido generado en {generation_time:.2f} segundos")
        
        # Procesamos la respuesta según su tipo
        if hasattr(response, 'content'):
            return response.content
        return str(response)
        
    except Exception as e:
        logger.error(f"Error generando contenido: {e}")
        return f"Error generando contenido: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# Ejemplo de uso con discovery automático
# ─────────────────────────────────────────────────────────────────────────────

def demo_agente_discovery():
    """Demuestra el uso del agente con discovery automático de herramientas."""
    try:
        print(f"🧠 Ejecutando sesión MCP con discovery automático - session_id: {SESSION_ID}")
        
        # Verificación inicial del servidor
        server_available = check_server_status()
        if not server_available:
            print("\n⚠️ Servidor MCP no disponible. Funcionando en modo fallback (local).\n")
        
        # 1. Listamos las herramientas disponibles
        print("\n--- Paso 1: Descubriendo herramientas disponibles ---")
        tools = mcp_tools.list_available_tools()
        
        if tool_registry.fallback_mode:
            print(f"📋 Herramientas disponibles en modo fallback: {', '.join(tools)}")
        else:
            print(f"📋 Herramientas descubiertas en servidor: {', '.join(tools)}")
        
        # 2. Mostramos información detallada de las herramientas
        print("\n--- Paso 2: Información detallada de herramientas ---")
        help_info = mcp_tools.show_tool_help()
        print(help_info)
        
        # 3. Usamos la herramienta leer_notas
        print("\n--- Paso 3: Leyendo notas existentes ---")
        if "leer_notas" in tools:
            result = mcp_tools.leer_notas()
            print(f"🔍 Resultado: {result}")
        else:
            print("❌ Herramienta 'leer_notas' no disponible")
        
        # 4. Generamos contenido con el LLM
        print("\n--- Paso 4: Generando contenido ---")
        prompt = """
        Genera una nota académica breve (2-3 oraciones) sobre algún concepto 
        interesante de LangChain o agentes de IA. La nota debe ser clara y concisa.
        """
        
        nuevo_contenido = generate_content(prompt)
        print(f"📝 Contenido generado: {nuevo_contenido}")
        
        # 5. Usamos la herramienta append_nota
        print("\n--- Paso 5: Guardando nota generada ---")
        if "append_nota" in tools:
            result = mcp_tools.append_nota(nota=nuevo_contenido)
            print(f"✅ Resultado: {result}")
        else:
            print("❌ Herramienta 'append_nota' no disponible")
        
        # 6. Verificamos que la nota se guardó correctamente
        print("\n--- Paso 6: Verificando que la nota se guardó ---")
        if "leer_notas" in tools:
            result = mcp_tools.leer_notas()
            print(f"🔍 Resultado: {result}")
        
        # Información sobre el modo de operación
        print("\n--- Estado del sistema ---")
        if mcp_tools.is_in_fallback_mode():
            print("⚠️ Funcionando en modo fallback (implementación local)")
            print("   Las notas se almacenan solo en memoria y se perderán al cerrar el programa.")
            print("   Para conectar con el servidor, asegúrese de que esté en ejecución en:")
            print(f"   {SERVER_HOST}:{SERVER_PORT}")
        else:
            print("✅ Conectado al servidor MCP correctamente")
        
        print("\n--- Demo completada ---")
        
    except Exception as e:
        logger.error(f"Error en demo: {e}", exc_info=True)
        print(f"\n❌ Error en demo: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo_agente_discovery()