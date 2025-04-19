#!/usr/bin/env python3
"""
MCP SDK - Model Communication Protocol Software Development Kit
===============================================================

Este SDK proporciona las clases y funciones necesarias para interactuar
con servidores MCP, crear agentes personalizados, y utilizar herramientas
de forma dinámica mediante discovery automático.

Autor: jc@lab-ai.org
Versión: 1.0.0
"""

import socket
import json
import uuid
import time
import logging
import inspect
import os
import sys
import warnings
from typing import Dict, List, Any, Optional, Callable, Tuple, Union, TypeVar, Generic

# Configuración básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_sdk")

# Suprimimos warnings de depreciación
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Definiciones de tipos
# ─────────────────────────────────────────────────────────────────────────────

T = TypeVar('T')
ToolResult = Union[str, Dict[str, Any], List[Any], None]
ToolFunction = Callable[..., ToolResult]

# ─────────────────────────────────────────────────────────────────────────────
# Excepciones personalizadas
# ─────────────────────────────────────────────────────────────────────────────

class MCPError(Exception):
    """Excepción base para errores del SDK MCP."""
    pass

class MCPConnectionError(MCPError):
    """Error de conexión con el servidor MCP."""
    pass

class MCPTimeoutError(MCPConnectionError):
    """Timeout en la conexión con el servidor MCP."""
    pass

class MCPToolNotFoundError(MCPError):
    """La herramienta solicitada no existe."""
    pass

class MCPInvalidMessageError(MCPError):
    """El mensaje enviado o recibido tiene un formato inválido."""
    pass

class MCPToolExecutionError(MCPError):
    """Error al ejecutar una herramienta."""
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Clases Base
# ─────────────────────────────────────────────────────────────────────────────

class MCPConfig:
    """
    Configuración para conexiones MCP.
    
    Attributes:
        host (str): Host del servidor MCP
        port (int): Puerto del servidor MCP
        timeout (int): Timeout para conexiones en segundos
        max_retries (int): Número máximo de reintentos
        retry_delay (int): Retraso base entre reintentos en segundos
        log_level (int): Nivel de logging
        session_id (str): ID de sesión para identificar al cliente
        use_fallback (bool): Si se debe usar fallback cuando el servidor no está disponible
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5050,
        timeout: int = 10,
        max_retries: int = 3,
        retry_delay: int = 2,
        log_level: int = logging.INFO,
        session_id: Optional[str] = None,
        use_fallback: bool = True
    ):
        """
        Inicializa una configuración MCP.
        
        Args:
            host: Host del servidor MCP
            port: Puerto del servidor MCP
            timeout: Timeout para conexiones en segundos
            max_retries: Número máximo de reintentos
            retry_delay: Retraso base entre reintentos en segundos
            log_level: Nivel de logging
            session_id: ID de sesión para identificar al cliente (generado automáticamente si es None)
            use_fallback: Si se debe usar fallback cuando el servidor no está disponible
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.log_level = log_level
        self.session_id = session_id or str(uuid.uuid4())
        self.use_fallback = use_fallback
        
        # Configurar nivel de logging
        logger.setLevel(log_level)

class MCPMessage:
    """
    Representa un mensaje enviado o recibido del servidor MCP.
    
    Attributes:
        type (str): Tipo de mensaje
        content (Dict[str, Any]): Contenido del mensaje
        session_id (str): ID de sesión
    """
    
    def __init__(self, type: str, content: Dict[str, Any], session_id: str):
        """
        Inicializa un mensaje MCP.
        
        Args:
            type: Tipo de mensaje
            content: Contenido del mensaje
            session_id: ID de sesión
        """
        self.type = type
        self.content = content
        self.session_id = session_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el mensaje a un diccionario para serialización."""
        msg = {
            "type": self.type,
            "session_id": self.session_id,
            **self.content
        }
        return msg
    
    def to_json(self) -> str:
        """Convierte el mensaje a JSON."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPMessage':
        """
        Crea un mensaje a partir de un diccionario.
        
        Args:
            data: Diccionario con los datos del mensaje
            
        Returns:
            Instancia de MCPMessage
            
        Raises:
            MCPInvalidMessageError: Si el mensaje no tiene el formato esperado
        """
        if not isinstance(data, dict):
            raise MCPInvalidMessageError("El mensaje debe ser un diccionario")
            
        if "type" not in data:
            raise MCPInvalidMessageError("El mensaje debe tener un tipo")
            
        if "session_id" not in data:
            raise MCPInvalidMessageError("El mensaje debe tener un ID de sesión")
            
        # Extraemos type y session_id, el resto es el contenido
        msg_type = data.pop("type")
        session_id = data.pop("session_id")
        
        return cls(msg_type, data, session_id)

class ToolMetadata:
    """
    Metadatos de una herramienta MCP.
    
    Attributes:
        name (str): Nombre de la herramienta
        description (str): Descripción de la herramienta
        params (Dict[str, Dict[str, Any]]): Parámetros de la herramienta
        examples (List[Dict[str, Any]]): Ejemplos de uso
        returns (str): Descripción de lo que devuelve la herramienta
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        params: Optional[Dict[str, Dict[str, Any]]] = None,
        examples: Optional[List[Dict[str, Any]]] = None,
        returns: str = ""
    ):
        """
        Inicializa los metadatos de una herramienta.
        
        Args:
            name: Nombre de la herramienta
            description: Descripción de la herramienta
            params: Parámetros de la herramienta
            examples: Ejemplos de uso
            returns: Descripción de lo que devuelve la herramienta
        """
        self.name = name
        self.description = description
        self.params = params or {}
        self.examples = examples or []
        self.returns = returns
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte los metadatos a un diccionario."""
        return {
            "description": self.description,
            "params": self.params,
            "examples": self.examples,
            "returns": self.returns
        }
    
    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> 'ToolMetadata':
        """
        Crea metadatos a partir de un diccionario.
        
        Args:
            name: Nombre de la herramienta
            data: Diccionario con los metadatos
            
        Returns:
            Instancia de ToolMetadata
        """
        return cls(
            name=name,
            description=data.get("description", ""),
            params=data.get("params", {}),
            examples=data.get("examples", []),
            returns=data.get("returns", "")
        )
    
    @classmethod
    def from_function(cls, name: str, func: Callable) -> 'ToolMetadata':
        """
        Extrae metadatos de una función.
        
        Args:
            name: Nombre de la herramienta
            func: Función de la que extraer metadatos
            
        Returns:
            Instancia de ToolMetadata
        """
        # Extraer descripción de la docstring
        description = inspect.getdoc(func) or ""
        
        # Extraer parámetros de la firma
        params = {}
        sig = inspect.signature(func)
        for param_name, param in sig.parameters.items():
            # Ignoramos parámetros especiales como self, cls, etc.
            if param_name in ["self", "cls", "args", "kwargs"]:
                continue
                
            # Determinamos si es requerido
            required = param.default == inspect.Parameter.empty
            
            # Inferimos el tipo si es posible
            param_type = "string"  # Por defecto
            if param.annotation != inspect.Parameter.empty:
                if param.annotation == str:
                    param_type = "string"
                elif param.annotation == int:
                    param_type = "integer"
                elif param.annotation == float:
                    param_type = "number"
                elif param.annotation == bool:
                    param_type = "boolean"
                elif param.annotation == list or param.annotation == List:
                    param_type = "array"
                elif param.annotation == dict or param.annotation == Dict:
                    param_type = "object"
                
            params[param_name] = {
                "type": param_type,
                "required": required
            }
        
        # Por ahora no extraemos ejemplos automáticamente
        examples = []
        
        # Intentamos extraer información de retorno
        returns = ""
        if sig.return_annotation != inspect.Signature.empty:
            returns = str(sig.return_annotation)
        
        return cls(name, description, params, examples, returns)

class Tool:
    """
    Representa una herramienta MCP.
    
    Attributes:
        name (str): Nombre de la herramienta
        metadata (ToolMetadata): Metadatos de la herramienta
        function (Callable): Función que implementa la herramienta (si es local)
        is_remote (bool): Si la herramienta es remota (en el servidor) o local
    """
    
    def __init__(
        self,
        name: str,
        metadata: ToolMetadata,
        function: Optional[Callable] = None,
        is_remote: bool = True
    ):
        """
        Inicializa una herramienta.
        
        Args:
            name: Nombre de la herramienta
            metadata: Metadatos de la herramienta
            function: Función que implementa la herramienta (si es local)
            is_remote: Si la herramienta es remota (en el servidor) o local
        """
        self.name = name
        self.metadata = metadata
        self.function = function
        self.is_remote = is_remote
    
    def __call__(self, *args, **kwargs) -> Any:
        """
        Ejecuta la herramienta.
        
        Nota: Esta implementación base no hace nada, debe ser sobrescrita
        por las clases derivadas.
        
        Raises:
            NotImplementedError: Siempre, ya que esta es una clase base
        """
        raise NotImplementedError("Las subclases deben implementar __call__")
    
    def help(self) -> str:
        """
        Genera un texto de ayuda para la herramienta.
        
        Returns:
            Texto de ayuda formateado
        """
        help_text = [f"Herramienta: {self.name}"]
        help_text.append("-" * 40)
        
        if self.metadata.description:
            help_text.append(f"Descripción: {self.metadata.description}")
        
        if self.metadata.params:
            help_text.append("\nParámetros:")
            for param_name, param_info in self.metadata.params.items():
                required = " (requerido)" if param_info.get("required", False) else " (opcional)"
                param_type = param_info.get("type", "string")
                param_desc = param_info.get("description", "")
                help_text.append(f"  {param_name}: {param_type}{required}")
                if param_desc:
                    help_text.append(f"    {param_desc}")
        
        if self.metadata.examples:
            help_text.append("\nEjemplos:")
            for i, example in enumerate(self.metadata.examples, 1):
                help_text.append(f"  Ejemplo {i}: {self.name}({', '.join(f'{k}={v!r}' for k, v in example.items())})")
        
        if self.metadata.returns:
            help_text.append(f"\nRetorna: {self.metadata.returns}")
        
        if self.is_remote:
            help_text.append("\nNota: Esta herramienta se ejecuta en el servidor MCP remoto.")
        else:
            help_text.append("\nNota: Esta herramienta se ejecuta localmente (fallback).")
        
        return "\n".join(help_text)

class LocalTool(Tool):
    """
    Herramienta que se ejecuta localmente.
    """
    
    def __init__(
        self,
        name: str,
        function: Callable,
        metadata: Optional[ToolMetadata] = None
    ):
        """
        Inicializa una herramienta local.
        
        Args:
            name: Nombre de la herramienta
            function: Función que implementa la herramienta
            metadata: Metadatos de la herramienta (extraídos de la función si es None)
        """
        # Si no se proporcionan metadatos, los extraemos de la función
        if metadata is None:
            metadata = ToolMetadata.from_function(name, function)
        
        super().__init__(name, metadata, function, is_remote=False)
    
    def __call__(self, **kwargs) -> Any:
        """
        Ejecuta la herramienta localmente.
        
        Args:
            **kwargs: Argumentos para la herramienta
            
        Returns:
            Resultado de la herramienta
            
        Raises:
            MCPToolExecutionError: Si ocurre un error al ejecutar la herramienta
        """
        if not self.function:
            raise MCPToolExecutionError(f"No hay implementación local para la herramienta '{self.name}'")
        
        try:
            return self.function(**kwargs)
        except Exception as e:
            raise MCPToolExecutionError(f"Error al ejecutar la herramienta '{self.name}': {e}")

class RemoteTool(Tool):
    """
    Herramienta que se ejecuta en un servidor MCP remoto.
    """
    
    def __init__(
        self,
        name: str,
        metadata: ToolMetadata,
        client: 'MCPClient'
    ):
        """
        Inicializa una herramienta remota.
        
        Args:
            name: Nombre de la herramienta
            metadata: Metadatos de la herramienta
            client: Cliente MCP para comunicarse con el servidor
        """
        super().__init__(name, metadata, None, is_remote=True)
        self.client = client
    
    def __call__(self, **kwargs) -> Any:
        """
        Ejecuta la herramienta remotamente en el servidor MCP.
        
        Args:
            **kwargs: Argumentos para la herramienta
            
        Returns:
            Resultado de la herramienta
            
        Raises:
            MCPToolExecutionError: Si ocurre un error al ejecutar la herramienta
        """
        # Validamos argumentos según los metadatos
        if self.metadata.params:
            for param_name, param_info in self.metadata.params.items():
                if param_info.get("required", False) and param_name not in kwargs:
                    raise MCPToolExecutionError(f"Falta el parámetro requerido '{param_name}'")
        
        # Ejecutamos la herramienta remotamente
        try:
            message = MCPMessage(
                type="call_tool",
                content={
                    "tool": self.name,
                    "arguments": kwargs
                },
                session_id=self.client.config.session_id
            )
            
            response = self.client.send_message(message)
            
            if isinstance(response, dict) and "text" in response:
                return response["text"]
            return response
            
        except MCPError as e:
            raise MCPToolExecutionError(f"Error al ejecutar la herramienta remota '{self.name}': {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Cliente MCP
# ─────────────────────────────────────────────────────────────────────────────

class MCPClient:
    """
    Cliente para comunicarse con un servidor MCP.
    
    Attributes:
        config (MCPConfig): Configuración del cliente
    """
    
    def __init__(self, config: Optional[MCPConfig] = None):
        """
        Inicializa un cliente MCP.
        
        Args:
            config: Configuración del cliente (usa valores por defecto si es None)
        """
        self.config = config or MCPConfig()
        logger.debug(f"Cliente MCP inicializado con session_id: {self.config.session_id}")
    
    def check_server_status(self) -> bool:
        """
        Verifica si el servidor MCP está disponible.
        
        Returns:
            True si el servidor está disponible, False en caso contrario
        """
        try:
            # Intentamos conectarnos al servidor (socket simple, sin enviar datos)
            with socket.create_connection(
                (self.config.host, self.config.port),
                timeout=min(2, self.config.timeout)
            ) as sock:
                # Si llegamos aquí, la conexión fue exitosa
                logger.debug("Servidor MCP disponible")
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            logger.warning(f"Servidor MCP no disponible en {self.config.host}:{self.config.port}")
            return False
    
    def send_message(self, message: MCPMessage) -> Any:
        """
        Envía un mensaje al servidor MCP.
        
        Args:
            message: Mensaje a enviar
            
        Returns:
            Respuesta del servidor
            
        Raises:
            MCPConnectionError: Si hay un error de conexión con el servidor
            MCPTimeoutError: Si hay un timeout en la conexión
            MCPInvalidMessageError: Si el mensaje o respuesta son inválidos
        """
        # Verificamos si el servidor está disponible
        if not self.check_server_status():
            raise MCPConnectionError(f"Servidor MCP no disponible en {self.config.host}:{self.config.port}")
        
        # Preparamos el mensaje como JSON
        json_data = message.to_json() + "\n"
        
        # Implementamos reintentos
        attempt = 0
        last_error = None
        
        while attempt < self.config.max_retries:
            try:
                # Creamos socket con timeout
                with socket.create_connection(
                    (self.config.host, self.config.port),
                    timeout=self.config.timeout
                ) as sock:
                    # Enviamos datos
                    sock.sendall(json_data.encode("utf-8"))
                    
                    # Recibimos respuesta
                    chunks = []
                    sock.settimeout(self.config.timeout)  # Aseguramos timeout para recepción
                    
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
                        
                        # Verificamos si hay un error en la respuesta
                        if isinstance(response, dict) and "error" in response:
                            error_msg = response.get("error", "Error desconocido")
                            error_code = response.get("code", 500)
                            raise MCPError(f"Error del servidor (código {error_code}): {error_msg}")
                        
                        return response
                    except json.JSONDecodeError as e:
                        # Si falla el JSON, intentamos devolver el texto crudo
                        raw_text = response_data.decode("utf-8", errors="replace")
                        logger.warning(f"Error decodificando JSON de respuesta: {e}")
                        if raw_text.strip():
                            return raw_text
                        raise MCPInvalidMessageError(f"Respuesta inválida del servidor: {e}")
                        
            except socket.timeout:
                last_error = MCPTimeoutError(f"Timeout en conexión con servidor MCP (intento {attempt+1}/{self.config.max_retries})")
                logger.warning(str(last_error))
            except ConnectionRefusedError:
                last_error = MCPConnectionError(f"Conexión rechazada por el servidor MCP (intento {attempt+1}/{self.config.max_retries})")
                logger.warning(str(last_error))
            except Exception as e:
                last_error = MCPError(f"Error en comunicación con servidor MCP: {e} (intento {attempt+1}/{self.config.max_retries})")
                logger.warning(str(last_error))
            
            # Si fallamos, reintentamos con backoff exponencial
            attempt += 1
            if attempt < self.config.max_retries:
                retry_delay = self.config.retry_delay ** attempt  # 2, 4, 8 segundos...
                logger.debug(f"Reintentando en {retry_delay}s (intento {attempt+1}/{self.config.max_retries})")
                time.sleep(retry_delay)
        
        # Si llegamos aquí, fallaron todos los intentos
        if last_error:
            raise last_error
        raise MCPConnectionError(f"No se pudo conectar al servidor MCP después de {self.config.max_retries} intentos")

# ─────────────────────────────────────────────────────────────────────────────
# Registro de herramientas
# ─────────────────────────────────────────────────────────────────────────────

class ToolRegistry:
    """
    Registro local de herramientas, con soporte para descubrimiento automático.
    
    Attributes:
        client (MCPClient): Cliente MCP para comunicarse con el servidor
        tools (Dict[str, Tool]): Diccionario de herramientas registradas
        fallback_tools (Dict[str, LocalTool]): Diccionario de herramientas de fallback
        last_discovery (float): Timestamp del último discovery
        discovery_ttl (int): Tiempo de vida del cache en segundos
        fallback_mode (bool): Si se está usando el modo fallback
    """
    
    def __init__(
        self,
        client: MCPClient,
        discovery_ttl: int = 300
    ):
        """
        Inicializa un registro de herramientas.
        
        Args:
            client: Cliente MCP para comunicarse con el servidor
            discovery_ttl: Tiempo de vida del cache en segundos
        """
        self.client = client
        self.tools: Dict[str, Tool] = {}
        self.fallback_tools: Dict[str, LocalTool] = {}
        self.last_discovery: float = 0
        self.discovery_ttl: int = discovery_ttl
        self.fallback_mode: bool = False
    
    def register_local_tool(self, name: str, function: Callable, metadata: Optional[ToolMetadata] = None) -> LocalTool:
        """
        Registra una herramienta local (fallback).
        
        Args:
            name: Nombre de la herramienta
            function: Función que implementa la herramienta
            metadata: Metadatos de la herramienta (extraídos de la función si es None)
            
        Returns:
            La herramienta registrada
        """
        tool = LocalTool(name, function, metadata)
        self.fallback_tools[name] = tool
        logger.debug(f"Herramienta local '{name}' registrada como fallback")
        return tool
    
    def register_remote_tool(self, name: str, metadata: ToolMetadata) -> RemoteTool:
        """
        Registra una herramienta remota.
        
        Args:
            name: Nombre de la herramienta
            metadata: Metadatos de la herramienta
            
        Returns:
            La herramienta registrada
        """
        tool = RemoteTool(name, metadata, self.client)
        self.tools[name] = tool
        logger.debug(f"Herramienta remota '{name}' registrada")
        return tool
    
    def get_tool(self, name: str) -> Optional[Tool]:
        """
        Obtiene una herramienta por su nombre.
        
        Args:
            name: Nombre de la herramienta
            
        Returns:
            La herramienta, o None si no existe
        """
        if self.fallback_mode and name in self.fallback_tools:
            return self.fallback_tools[name]
        
        return self.tools.get(name)
    
    def list_tools(self) -> List[str]:
        """
        Lista los nombres de todas las herramientas registradas.
        
        Returns:
            Lista de nombres de herramientas
        """
        if self.fallback_mode:
            return list(self.fallback_tools.keys())
        
        return list(self.tools.keys())
    
    def should_refresh(self) -> bool:
        """
        Determina si es necesario actualizar el registro desde el servidor.
        
        Returns:
            True si se debe actualizar, False en caso contrario
        """
        current_time = time.time()
        return current_time - self.last_discovery > self.discovery_ttl
    
    def mark_refreshed(self):
        """Marca el registro como actualizado."""
        self.last_discovery = time.time()
    
    def clear(self):
        """Limpia el registro de herramientas remotas."""
        self.tools = {}
        logger.debug("Registro de herramientas remotas limpiado")
    
    def enable_fallback_mode(self):
        """Habilita el modo fallback con herramientas locales."""
        if not self.fallback_mode:
            self.fallback_mode = True
            logger.warning("Modo fallback activado, usando herramientas locales")
    
    def disable_fallback_mode(self):
        """Deshabilita el modo fallback."""
        if self.fallback_mode:
            self.fallback_mode = False
            logger.info("Modo fallback desactivado, usando herramientas remotas")
    
    def discover(self) -> bool:
        """
        Descubre automáticamente las herramientas disponibles en el servidor MCP.
        
        Returns:
            True si el descubrimiento fue exitoso (o fallback activado), False en caso contrario
        """
        logger.info("Iniciando descubrimiento de herramientas...")
        
        # Si el registro no necesita actualizarse, usamos la caché
        if not self.should_refresh() and self.tools and not self.fallback_mode:
            logger.debug(f"Usando caché de herramientas (TTL: {self.discovery_ttl}s)")
            return True
        
        # Verificamos si el servidor está disponible
        if not self.client.check_server_status():
            logger.warning("Activando modo fallback por servidor no disponible")
            self.enable_fallback_mode()
            return True  # Retornamos True porque activamos fallback
        
        # Solicitamos los metadatos de todas las herramientas
        try:
            message = MCPMessage(
                type="get_all_tools_metadata",
                content={},
                session_id=self.client.config.session_id
            )
            
            response = self.client.send_message(message)
            
            # Verificamos la respuesta
            if not isinstance(response, dict) or "metadata" not in response:
                logger.error(f"Respuesta de discovery inválida: {response}")
                self.enable_fallback_mode()
                return True  # Retornamos True porque activamos fallback
            
            # Desactivamos modo fallback si estaba activado
            if self.fallback_mode:
                self.disable_fallback_mode()
            
            # Limpiamos el registro actual
            self.clear()
            
            # Registramos las herramientas descubiertas
            for tool_name, metadata_dict in response.get("metadata", {}).items():
                metadata = ToolMetadata.from_dict(tool_name, metadata_dict)
                self.register_remote_tool(tool_name, metadata)
            
            # Marcamos el registro como actualizado
            self.mark_refreshed()
            
            logger.info(f"Discovery completado: {len(self.tools)} herramientas descubiertas")
            return True
            
        except MCPError as e:
            logger.error(f"Error en discovery de herramientas: {e}")
            self.enable_fallback_mode()
            return True  # Retornamos True porque activamos fallback

# ─────────────────────────────────────────────────────────────────────────────
# API Dinámica para herramientas
# ─────────────────────────────────────────────────────────────────────────────

class MCPTools:
    """
    Clase que proporciona acceso dinámico a las herramientas MCP.
    
    Attributes:
        registry (ToolRegistry): Registro de herramientas
    """
    
    def __init__(self, registry: ToolRegistry):
        """
        Inicializa la API dinámica de herramientas.
        
        Args:
            registry: Registro de herramientas
        """
        self.registry = registry
        self._initialized = False
    
    def _ensure_initialized(self) -> bool:
        """
        Asegura que la API está inicializada con las herramientas actuales.
        Realiza discovery si es necesario.
        
        Returns:
            True si se inicializó correctamente, False en caso contrario
        """
        if not self._initialized or self.registry.should_refresh():
            # Descubrimos las herramientas disponibles
            success = self.registry.discover()
            if success:
                self._initialized = True
                return True
            return False
        
        return True
    
    def __getattr__(self, name: str) -> Tool:
        """
        Permite acceder a las herramientas como si fueran métodos de la clase.
        Ejemplo: mcp_tools.append_nota(nota="Hola mundo")
        
        Args:
            name: Nombre de la herramienta/método
            
        Returns:
            La herramienta solicitada
            
        Raises:
            MCPToolNotFoundError: Si la herramienta no existe
        """
        # Inicializamos si es necesario
        if not self._ensure_initialized():
            raise MCPError("No se pudo inicializar la API de herramientas MCP")
        
        # Verificamos si existe la herramienta
        tool = self.registry.get_tool(name)
        if tool:
            return tool
        
        # Si no existe, intentamos redescubrir (podría ser una herramienta nueva)
        self.registry.last_discovery = 0  # Forzamos redescubrimiento
        if self._ensure_initialized():
            tool = self.registry.get_tool(name)
            if tool:
                return tool
        
        # Si sigue sin existir, es un error
        available_tools = ", ".join(self.registry.list_tools())
        raise MCPToolNotFoundError(f"No existe la herramienta '{name}'. Herramientas disponibles: {available_tools}")
    
    def list_available_tools(self) -> List[str]:
        """
        Lista las herramientas disponibles.
        
        Returns:
            Lista de nombres de herramientas disponibles
        """
        if not self._ensure_initialized():
            return []
        
        return self.registry.list_tools()
    
    def get_tool_info(self, tool_name: str) -> Optional[Tool]:
        """
        Obtiene información detallada sobre una herramienta.
        
        Args:
            tool_name: Nombre de la herramienta
            
        Returns:
            La herramienta, o None si no existe
        """
        if not self._ensure_initialized():
            return None
        
        return self.registry.get_tool(tool_name)
    
    def show_tool_help(self, tool_name: str = None) -> str:
        """
        Muestra ayuda sobre las herramientas disponibles.
        
        Args:
            tool_name: Nombre específico de una herramienta, o None para mostrar todas
            
        Returns:
            Texto de ayuda formateado
        """
        if not self._ensure_initialized():
            return "No se pudo obtener información de las herramientas"
        
        if tool_name:
            # Mostramos ayuda específica de una herramienta
            tool = self.registry.get_tool(tool_name)
            if not tool:
                return f"No existe la herramienta '{tool_name}'"
            
            return tool.help()
        else:
            # Mostramos lista de todas las herramientas
            tools = self.list_available_tools()
            if not tools:
                return "No hay herramientas disponibles"
            
            help_text = ["Herramientas disponibles:"]
            if self.registry.fallback_mode:
                help_text[0] += " (MODO FALLBACK - Implementación local)"
            help_text.append("-" * 40)
            
            for tool_name in tools:
                tool = self.registry.get_tool(tool_name)
                if tool and tool.metadata.description:
                    description = tool.metadata.description
                else:
                    description = "Sin descripción"
                help_text.append(f"{tool_name}: {description}")
            
            help_text.append("\nPara ver detalles de una herramienta específica, use show_tool_help('nombre_herramienta')")
            
            return "\n".join(help_text)
    
    def is_in_fallback_mode(self) -> bool:
        """
        Indica si se está funcionando en modo fallback.
        
        Returns:
            True si se está usando el modo fallback, False si se está conectando al servidor
        """
        return self.registry.fallback_mode

# ─────────────────────────────────────────────────────────────────────────────
# Agente MCP
# ─────────────────────────────────────────────────────────────────────────────

class MCPAgent:
    """
    Agente que utiliza herramientas MCP.
    
    Attributes:
        client (MCPClient): Cliente MCP
        tools (MCPTools): API dinámica de herramientas
        registry (ToolRegistry): Registro de herramientas
        config (MCPConfig): Configuración del agente
    """
    
    def __init__(
        self,
        config: Optional[MCPConfig] = None,
        fallback_tools: Optional[Dict[str, Callable]] = None
    ):
        """
        Inicializa un agente MCP.
        
        Args:
            config: Configuración del agente (usa valores por defecto si es None)
            fallback_tools: Diccionario de herramientas locales para fallback
        """
        self.config = config or MCPConfig()
        self.client = MCPClient(self.config)
        self.registry = ToolRegistry(self.client)
        self.tools = MCPTools(self.registry)
        
        # Registramos las herramientas de fallback
        if fallback_tools:
            for name, function in fallback_tools.items():
                self.registry.register_local_tool(name, function)
        
        logger.info(f"Agente MCP inicializado con session_id: {self.config.session_id}")
    
    def discover_tools(self) -> bool:
        """
        Descubre las herramientas disponibles.
        
        Returns:
            True si el descubrimiento fue exitoso, False en caso contrario
        """
        return self.registry.discover()
    
    def list_tools(self) -> List[str]:
        """
        Lista las herramientas disponibles.
        
        Returns:
            Lista de nombres de herramientas
        """
        return self.tools.list_available_tools()
    
    def get_tool(self, name: str) -> Tool:
        """
        Obtiene una herramienta por su nombre.
        
        Args:
            name: Nombre de la herramienta
            
        Returns:
            La herramienta
            
        Raises:
            MCPToolNotFoundError: Si la herramienta no existe
        """
        return getattr(self.tools, name)
    
    def execute_tool(self, name: str, **kwargs) -> Any:
        """
        Ejecuta una herramienta por su nombre.
        
        Args:
            name: Nombre de la herramienta
            **kwargs: Argumentos para la herramienta
            
        Returns:
            Resultado de la herramienta
            
        Raises:
            MCPToolNotFoundError: Si la herramienta no existe
            MCPToolExecutionError: Si ocurre un error al ejecutar la herramienta
        """
        tool = self.get_tool(name)
        return tool(**kwargs)
    
    def is_server_available(self) -> bool:
        """
        Verifica si el servidor MCP está disponible.
        
        Returns:
            True si el servidor está disponible, False en caso contrario
        """
        return self.client.check_server_status()
    
    def is_in_fallback_mode(self) -> bool:
        """
        Indica si se está funcionando en modo fallback.
        
        Returns:
            True si se está usando el modo fallback, False si se está conectando al servidor
        """
        return self.registry.fallback_mode

# ─────────────────────────────────────────────────────────────────────────────
# Implementación de herramientas de fallback básicas
# ─────────────────────────────────────────────────────────────────────────────

class FallbackNoteStorage:
    """Almacenamiento local de notas para fallback."""
    
    def __init__(self):
        """Inicializa el almacenamiento."""
        self.notas: Dict[str, List[str]] = {}
    
    def get_session(self, session_id: str) -> List[str]:
        """
        Obtiene o crea una sesión para almacenamiento de notas.
        
        Args:
            session_id: ID de sesión
            
        Returns:
            Lista de notas de la sesión
        """
        if session_id not in self.notas:
            self.notas[session_id] = []
        return self.notas[session_id]

# Singleton para almacenamiento de notas
_fallback_storage = FallbackNoteStorage()

def fallback_append_nota(nota: str, session_id: Optional[str] = None) -> str:
    """
    Implementación de fallback para append_nota.
    
    Args:
        nota: Texto de la nota
        session_id: ID de sesión (usa "default" si es None)
        
    Returns:
        Mensaje de confirmación
    """
    if not nota:
        return "Error: Nota vacía"
    
    session_id = session_id or "default"
    memoria = _fallback_storage.get_session(session_id)
    memoria.append(nota)
    
    return f"Nota registrada localmente: {nota}"

def fallback_leer_notas(session_id: Optional[str] = None) -> str:
    """
    Implementación de fallback para leer_notas.
    
    Args:
        session_id: ID de sesión (usa "default" si es None)
        
    Returns:
        Lista de notas o mensaje indicando que no hay notas
    """
    session_id = session_id or "default"
    memoria = _fallback_storage.get_session(session_id)
    
    if not memoria:
        return "No hay notas registradas localmente."
    
    return "Notas registradas localmente:\n" + "\n".join(f"- {n}" for n in memoria)

# ─────────────────────────────────────────────────────────────────────────────
# Funciones de ayuda
# ─────────────────────────────────────────────────────────────────────────────

def create_mcp_agent(
    host: str = "127.0.0.1",
    port: int = 5050,
    session_id: Optional[str] = None,
    use_fallback: bool = True
) -> MCPAgent:
    """
    Crea un agente MCP con configuración personalizada.
    
    Args:
        host: Host del servidor MCP
        port: Puerto del servidor MCP
        session_id: ID de sesión (generado automáticamente si es None)
        use_fallback: Si se debe usar fallback cuando el servidor no está disponible
        
    Returns:
        Agente MCP configurado
    """
    config = MCPConfig(
        host=host,
        port=port,
        session_id=session_id,
        use_fallback=use_fallback
    )
    
    # Configuramos las herramientas de fallback básicas
    fallback_tools = {
        "append_nota": fallback_append_nota,
        "leer_notas": fallback_leer_notas
    }
    
    return MCPAgent(config, fallback_tools)

# ─────────────────────────────────────────────────────────────────────────────
# Ejemplo de uso
# ─────────────────────────────────────────────────────────────────────────────

def demo():
    """Ejemplo de uso del SDK MCP."""
    print("Iniciando demo del SDK MCP...")
    
    # Creamos un agente MCP
    agent = create_mcp_agent()
    print(f"Agente MCP creado con session_id: {agent.config.session_id}")
    
    # Verificamos la disponibilidad del servidor
    server_available = agent.is_server_available()
    if server_available:
        print("✅ Servidor MCP disponible")
    else:
        print("⚠️ Servidor MCP no disponible, usando modo fallback")
    
    # Descubrimos las herramientas disponibles
    print("\n--- Descubriendo herramientas ---")
    agent.discover_tools()
    tools = agent.list_tools()
    print(f"Herramientas disponibles: {', '.join(tools)}")
    
    # Mostramos ayuda sobre las herramientas
    print("\n--- Información de herramientas ---")
    help_text = agent.tools.show_tool_help()
    print(help_text)
    
    # Ejecutamos la herramienta leer_notas
    try:
        print("\n--- Leyendo notas ---")
        result = agent.execute_tool("leer_notas")
        print(f"Resultado: {result}")
    except MCPError as e:
        print(f"Error: {e}")
    
    # Ejecutamos la herramienta append_nota
    try:
        print("\n--- Agregando nota ---")
        result = agent.execute_tool("append_nota", nota="Nota de prueba desde SDK MCP")
        print(f"Resultado: {result}")
    except MCPError as e:
        print(f"Error: {e}")
    
    # Verificamos que la nota se guardó correctamente
    try:
        print("\n--- Verificando nota ---")
        result = agent.execute_tool("leer_notas")
        print(f"Resultado: {result}")
    except MCPError as e:
        print(f"Error: {e}")
    
    print("\n--- Demo completada ---")

# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada principal
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo()