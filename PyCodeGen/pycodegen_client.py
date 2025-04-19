#!/usr/bin/env python3
"""
Cliente PyCodeGen - Interfaz de línea de comandos para generación de código Python.

Este cliente se comunica con el servidor PyCodeGen a través de sockets y mensajes JSON,
proporcionando una interfaz fácil de usar para generar, analizar, ejecutar y gestionar código Python.
"""

import os
import sys
import argparse
import uuid
import logging
import socket
import json
from typing import Optional, Dict, List, Any
from pathlib import Path

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s - [%(filename)s:%(lineno)d]'
)
logger = logging.getLogger("pycodegen_client")

# ─────────────────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────────────────

PYCODEGEN_SERVER_HOST = os.environ.get("PYCODEGEN_HOST", "127.0.0.1")
PYCODEGEN_SERVER_PORT = int(os.environ.get("PYCODEGEN_PORT", "5056"))
TIMEOUT = 120  # Timeout en segundos para conexiones
CONFIG_FILE = os.path.expanduser("~/.pycodegen_config.json")

# ─────────────────────────────────────────────────────────────────────────────
# Gestión de configuración
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> Dict[str, str]:
    """Carga la configuración desde el archivo ~/.pycodegen_config.json."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Error al cargar configuración: {e}")
    return {}

def save_config(config: Dict[str, str]):
    """Guarda la configuración en el archivo ~/.pycodegen_config.json."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.warning(f"Error al guardar configuración: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Cliente PyCodeGen
# ─────────────────────────────────────────────────────────────────────────────

class PyCodeGenClient:
    """
    Cliente para interactuar con el servidor PyCodeGen.
    
    Attributes:
        project_id: ID del proyecto actual
        session_id: ID de la sesión actual
        host: Host del servidor PyCodeGen
        port: Puerto del servidor PyCodeGen
    """
    
    def __init__(self, project_id: Optional[str] = None, session_id: Optional[str] = None,
                 host: str = PYCODEGEN_SERVER_HOST, port: int = PYCODEGEN_SERVER_PORT):
        """
        Inicializa el cliente PyCodeGen.
        
        Args:
            project_id: ID del proyecto (cargado desde config o generado si es None)
            session_id: ID de la sesión (cargado desde config o generado si es None)
            host: Host del servidor PyCodeGen
            port: Puerto del servidor PyCodeGen
        """
        # Cargar configuración existente
        config = load_config()
        self.project_id = project_id or config.get("project_id") or str(uuid.uuid4())
        self.session_id = session_id or config.get("session_id") or str(uuid.uuid4())
        self.host = host
        self.port = port
        
        # Guardar configuración
        config.update({"project_id": self.project_id, "session_id": self.session_id})
        save_config(config)
        
        logger.info(f"Cliente PyCodeGen inicializado - Proyecto: {self.project_id}, Sesión: {self.session_id}")
        
        # Verificamos la conexión con el servidor
        try:
            tools = self.list_tools()
            logger.info(f"Conectado al servidor PyCodeGen - {len(tools)} herramientas disponibles")
            print(f"✅ Conectado al servidor PyCodeGen en {host}:{port}")
            print(f"Herramientas disponibles: {', '.join(tools)}")
        except Exception as e:
            logger.error(f"Error al inicializar cliente: {e}")
            print(f"❌ Error: No se pudo conectar al servidor PyCodeGen en {host}:{port}: {e}")
    
    def _send_request(self, message: Dict) -> Dict:
        """
        Envía una solicitud al servidor y devuelve la respuesta.
        
        Args:
            message: Mensaje JSON a enviar
        
        Returns:
            Respuesta del servidor como diccionario
        
        Raises:
            ConnectionError: Si falla la conexión
            ValueError: Si la respuesta es inválida
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((self.host, self.port))
                s.sendall((json.dumps(message) + "\n").encode("utf-8"))
                response = s.recv(4096).decode("utf-8")
                return json.loads(response)
        except socket.timeout:
            raise ConnectionError("Tiempo de espera agotado al conectar con el servidor")
        except socket.error as e:
            raise ConnectionError(f"Error de conexión: {e}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Respuesta inválida del servidor: {e}")
    
    def list_tools(self) -> List[str]:
        """
        Lista las herramientas disponibles en el servidor.
        
        Returns:
            Lista de nombres de herramientas
        
        Raises:
            ConnectionError: Si falla la conexión
        """
        message = {"type": "list_tools", "session_id": self.session_id}
        response = self._send_request(message)
        if response.get("type") == "tool_list":
            return response.get("tools", [])
        raise ValueError(f"Error al listar herramientas: {response.get('text', 'Respuesta inválida')}")
    
    def get_tools_metadata(self) -> Dict:
        """
        Obtiene los metadatos de todas las herramientas.
        
        Returns:
            Diccionario con metadatos de las herramientas
        
        Raises:
            ConnectionError: Si falla la conexión
        """
        message = {"type": "get_all_tools_metadata", "session_id": self.session_id}
        response = self._send_request(message)
        if response.get("type") == "all_tools_metadata":
            return response.get("metadata", {})
        raise ValueError(f"Error al obtener metadatos: {response.get('text', 'Respuesta inválida')}")
    
    def generate_code(self, description: str, filename: str = "script.py") -> str:
        """
        Genera código Python basado en una descripción.
        
        Args:
            description: Descripción del código a generar
            filename: Nombre del archivo donde guardar el código
        
        Returns:
            Mensaje con el resultado de la operación
        """
        message = {
            "type": "call_tool",
            "tool": "generate_python_code",
            "session_id": self.session_id,
            "arguments": {
                "description": description,
                "project_id": self.project_id,
                "filename": filename
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def analyze_code(self, filename: str) -> str:
        """
        Analiza un archivo de código Python.
        
        Args:
            filename: Nombre del archivo a analizar
        
        Returns:
            Resultado del análisis
        """
        files = self.list_files()
        if f"- {filename}" not in files and files != f"El proyecto {self.project_id} no tiene archivos Python.":
            files_msg = files if files else "No hay archivos en el proyecto."
            return (f"Error: El archivo {filename} no existe en el proyecto {self.project_id}\n"
                    f"Archivos disponibles:\n{files_msg}")
        
        message = {
            "type": "call_tool",
            "tool": "analyze_python_code",
            "session_id": self.session_id,
            "arguments": {
                "project_id": self.project_id,
                "filename": filename
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def run_code(self, filename: str, args: List[str] = None) -> str:
        """
        Ejecuta un archivo de código Python.
        
        Args:
            filename: Nombre del archivo a ejecutar
            args: Argumentos para pasar al script
        
        Returns:
            Salida de la ejecución
        """
        files = self.list_files()
        if f"- {filename}" not in files and files != f"El proyecto {self.project_id} no tiene archivos Python.":
            files_msg = files if files else "No hay archivos en el proyecto."
            return (f"Error: El archivo {filename} no existe en el proyecto {self.project_id}\n"
                    f"Archivos disponibles:\n{files_msg}")
        
        message = {
            "type": "call_tool",
            "tool": "run_python_code",
            "session_id": self.session_id,
            "arguments": {
                "project_id": self.project_id,
                "filename": filename,
                "args": args or []
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def list_files(self) -> str:
        """
        Lista todos los archivos en el proyecto actual.
        
        Returns:
            Lista de archivos en formato texto
        """
        message = {
            "type": "call_tool",
            "tool": "list_project_files",
            "session_id": self.session_id,
            "arguments": {
                "project_id": self.project_id
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def read_file(self, filename: str) -> str:
        """
        Lee el contenido de un archivo.
        
        Args:
            filename: Nombre del archivo a leer
        
        Returns:
            Contenido del archivo
        """
        files = self.list_files()
        if f"- {filename}" not in files and files != f"El proyecto {self.project_id} no tiene archivos Python.":
            files_msg = files if files else "No hay archivos en el proyecto."
            return (f"Error: El archivo {filename} no existe en el proyecto {self.project_id}\n"
                    f"Archivos disponibles:\n{files_msg}")
        
        message = {
            "type": "call_tool",
            "tool": "read_python_file",
            "session_id": self.session_id,
            "arguments": {
                "project_id": self.project_id,
                "filename": filename
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def fix_code(self, filename: str) -> str:
        """
        Corrige errores en un archivo de código Python.
        
        Args:
            filename: Nombre del archivo a corregir
        
        Returns:
            Resultado de la corrección
        """
        files = self.list_files()
        if f"- {filename}" not in files and files != f"El proyecto {self.project_id} no tiene archivos Python.":
            files_msg = files if files else "No hay archivos en el proyecto."
            return (f"Error: El archivo {filename} no existe en el proyecto {self.project_id}\n"
                    f"Archivos disponibles:\n{files_msg}")
        
        message = {
            "type": "call_tool",
            "tool": "fix_python_code",
            "session_id": self.session_id,
            "arguments": {
                "project_id": self.project_id,
                "filename": filename
            }
        }
        response = self._send_request(message)
        if response.get("type") == "text":
            return response.get("text")
        return f"Error: {response.get('text', 'Respuesta inválida')}"
    
    def set_project_id(self, project_id: str):
        """Cambia el ID del proyecto actual y actualiza la configuración."""
        self.project_id = project_id
        config = load_config()
        config["project_id"] = project_id
        save_config(config)
        logger.info(f"Proyecto cambiado a: {project_id}")

# ─────────────────────────────────────────────────────────────────────────────
# Interfaz de línea de comandos
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    """Parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(description="Cliente para generación de código Python con PyCodeGen")
    
    parser.add_argument("--project", "-p", help="ID del proyecto (cargado desde config si no se especifica)")
    parser.add_argument("--session", "-s", help="ID de la sesión (cargado desde config si no se especifica)")
    parser.add_argument("--host", help=f"Host del servidor PyCodeGen (por defecto: {PYCODEGEN_SERVER_HOST})")
    parser.add_argument("--port", type=int, help=f"Puerto del servidor PyCodeGen (por defecto: {PYCODEGEN_SERVER_PORT})")
    
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")
    
    # Comando: generate
    generate_parser = subparsers.add_parser("generate", help="Genera código Python")
    generate_parser.add_argument("--description", "-d", required=True, help="Descripción del código a generar")
    generate_parser.add_argument("--filename", "-f", default="script.py", help="Nombre del archivo (por defecto: script.py)")
    
    # Comando: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analiza código Python")
    analyze_parser.add_argument("--filename", "-f", required=True, help="Archivo a analizar")
    
    # Comando: run
    run_parser = subparsers.add_parser("run", help="Ejecuta código Python")
    run_parser.add_argument("--filename", "-f", required=True, help="Archivo a ejecutar")
    run_parser.add_argument("args", nargs="*", help="Argumentos para el script")
    
    # Comando: list
    subparsers.add_parser("list", help="Lista archivos en el proyecto")
    
    # Comando: read
    read_parser = subparsers.add_parser("read", help="Lee un archivo")
    read_parser.add_argument("--filename", "-f", required=True, help="Archivo a leer")
    
    # Comando: fix
    fix_parser = subparsers.add_parser("fix", help="Corrige errores en un archivo Python")
    fix_parser.add_argument("--filename", "-f", required=True, help="Archivo a corregir")
    
    # Comando: interactive
    subparsers.add_parser("interactive", help="Modo interactivo")
    
    # Comando: tools
    subparsers.add_parser("tools", help="Lista herramientas disponibles")
    
    # Comando: metadata
    subparsers.add_parser("metadata", help="Muestra metadatos de las herramientas")
    
    return parser.parse_args()

def interactive_mode(client: PyCodeGenClient):
    """Ejecuta el cliente en modo interactivo."""
    print(f"\n=== PyCodeGen - Modo Interactivo (Proyecto: {client.project_id}, Sesión: {client.session_id}) ===")
    print("Escriba 'help' para ver los comandos disponibles o 'exit' para salir.")
    
    while True:
        try:
            command = input("\npycodegen> ").strip()
            
            if not command:
                continue
                
            if command.lower() in ["exit", "quit", "q"]:
                print("Saliendo del modo interactivo.")
                break
                
            if command.lower() in ["help", "?"]:
                print("\nComandos disponibles:")
                print("  generate <filename> - Genera código Python")
                print("  analyze <filename> - Analiza código Python")
                print("  run <filename> [args...] - Ejecuta código Python")
                print("  list - Lista archivos en el proyecto")
                print("  read <filename> - Lee un archivo")
                print("  fix <filename> - Corrige errores en un archivo")
                print("  tools - Lista herramientas disponibles")
                print("  metadata - Muestra metadatos de las herramientas")
                print("  set_project <project_id> - Cambia el ID del proyecto")
                print("  exit - Salir del modo interactivo")
                continue
                
            parts = command.split()
            cmd = parts[0].lower()
            
            if cmd == "generate":
                if len(parts) < 2:
                    print("Error: Debe especificar un nombre de archivo")
                    continue
                    
                filename = parts[1]
                print("Introduzca la descripción del código (termine con una línea vacía):")
                lines = []
                while True:
                    line = input("> ")
                    if not line:
                        break
                    lines.append(line)
                
                description = "\n".join(lines)
                if not description:
                    print("Error: La descripción no puede estar vacía")
                    continue
                
                try:
                    result = client.generate_code(description, filename)
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "analyze":
                if len(parts) < 2:
                    print("Error: Debe especificar un nombre de archivo")
                    continue
                
                try:
                    result = client.analyze_code(parts[1])
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "run":
                if len(parts) < 2:
                    print("Error: Debe especificar un nombre de archivo")
                    continue
                
                try:
                    result = client.run_code(parts[1], parts[2:])
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "list":
                try:
                    result = client.list_files()
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "read":
                if len(parts) < 2:
                    print("Error: Debe especificar un nombre de archivo")
                    continue
                
                try:
                    result = client.read_file(parts[1])
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "fix":
                if len(parts) < 2:
                    print("Error: Debe especificar un nombre de archivo")
                    continue
                
                try:
                    result = client.fix_code(parts[1])
                    print(result)
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "tools":
                try:
                    tools = client.list_tools()
                    print("Herramientas disponibles:")
                    for tool in tools:
                        print(f"- {tool}")
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "metadata":
                try:
                    metadata = client.get_tools_metadata()
                    print("Metadatos de herramientas:")
                    for tool, info in metadata.items():
                        print(f"\n{tool}:")
                        print(f"  Descripción: {info['description']}")
                        print("  Parámetros:")
                        for param, param_info in info['params'].items():
                            print(f"    - {param}: {param_info['description']} (requerido: {param_info['required']})")
                except Exception as e:
                    print(f"Error: {e}")
            
            elif cmd == "set_project":
                if len(parts) < 2:
                    print("Error: Debe especificar un ID de proyecto")
                    continue
                
                try:
                    client.set_project_id(parts[1])
                    print(f"Proyecto cambiado a: {parts[1]}")
                except Exception as e:
                    print(f"Error: {e}")
            
            else:
                print(f"Comando desconocido: {cmd}")
                print("Escriba 'help' para ver los comandos disponibles")
                
        except KeyboardInterrupt:
            print("\nInterrupción detectada. Escriba 'exit' para salir.")
        except Exception as e:
            logger.error(f"Error en modo interactivo: {e}")
            print(f"Error inesperado: {e}")

def main():
    """Función principal del cliente."""
    args = parse_args()
    
    # Configurar cliente
    client = PyCodeGenClient(
        project_id=args.project,
        session_id=args.session,
        host=args.host or PYCODEGEN_SERVER_HOST,
        port=args.port or PYCODEGEN_SERVER_PORT
    )
    
    try:
        if args.command == "generate":
            result = client.generate_code(args.description, args.filename)
            print(result)
        
        elif args.command == "analyze":
            result = client.analyze_code(args.filename)
            print(result)
        
        elif args.command == "run":
            result = client.run_code(args.filename, args.args)
            print(result)
        
        elif args.command == "list":
            result = client.list_files()
            print(result)
        
        elif args.command == "read":
            result = client.read_file(args.filename)
            print(result)
        
        elif args.command == "fix":
            result = client.fix_code(args.filename)
            print(result)
        
        elif args.command == "tools":
            tools = client.list_tools()
            print("Herramientas disponibles:")
            for tool in tools:
                print(f"- {tool}")
        
        elif args.command == "metadata":
            metadata = client.get_tools_metadata()
            print("Metadatos de herramientas:")
            for tool, info in metadata.items():
                print(f"\n{tool}:")
                print(f"  Descripción: {info['description']}")
                print("  Parámetros:")
                for param, param_info in info['params'].items():
                    print(f"    - {param}: {param_info['description']} (requerido: {param_info['required']})")
        
        elif args.command == "interactive":
            interactive_mode(client)
        
        else:
            print("Error: Debe especificar un comando. Use --help para más información.")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error ejecutando comando: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()