#!/usr/bin/env python3
"""
Servidor PyCodeGen - Servidor de sockets para generación y gestión de código Python.

Este servidor utiliza sockets TCP para recibir comandos, procesarlos y devolver respuestas.
Soporta generación de código con LangChain y Ollama, análisis con AST, Ruff y reglas semánticas,
ejecución de código (incluyendo FastAPI), gestión de archivos en proyectos, y corrección automática
de errores.
"""

import os
import sys
import json
import uuid
import socket
import logging
import subprocess
import tempfile
import ast
import re
import textwrap
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

# Dependencias de LangChain
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_ollama import ChatOllama

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s - [%(filename)s:%(lineno)d]',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("pycodegen_server")

# ─────────────────────────────────────────────────────────────────────────────
# Configuración
# ─────────────────────────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 5056
GENERATED_CODE_DIR = "generated_code"
SESSIONS_FILE = os.path.expanduser("~/.mcp_sessions.json")

# Asegurar que el directorio de código generado exista
os.makedirs(GENERATED_CODE_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Gestión de sesiones
# ─────────────────────────────────────────────────────────────────────────────

def load_sessions() -> Dict[str, Dict[str, Any]]:
    """Carga las sesiones desde el archivo de sesiones."""
    try:
        if os.path.exists(SESSIONS_FILE):
            with open(SESSIONS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Error al cargar sesiones: {e}")
    return {}

def save_sessions(sessions: Dict[str, Dict[str, Any]]):
    """Guarda las sesiones en el archivo de sesiones."""
    try:
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)
    except Exception as e:
        logger.warning(f"Error al guardar sesiones: {e}")

def update_session(session_id: str, memoria: List[str], description: str = ""):
    """Actualiza la memoria y descripción de una sesión."""
    sessions = load_sessions()
    sessions[session_id] = {"memoria": memoria, "description": description}
    save_sessions(sessions)

# ─────────────────────────────────────────────────────────────────────────────
# Repositorio de código
# ─────────────────────────────────────────────────────────────────────────────

class CodeRepository:
    """Clase para gestionar el almacenamiento de archivos de código."""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def save_file(self, project_id: str, filename: str, content: str) -> str:
        """
        Guarda un archivo en el directorio del proyecto.
        
        Args:
            project_id: ID del proyecto
            filename: Nombre del archivo
            content: Contenido del archivo
        
        Returns:
            Ruta completa del archivo guardado
        """
        project_dir = os.path.join(self.base_dir, project_id)
        os.makedirs(project_dir, exist_ok=True)
        file_path = os.path.join(project_dir, filename)
        
        with open(file_path, 'w') as f:
            f.write(content)
        
        return os.path.abspath(file_path)
    
    def read_file(self, project_id: str, filename: str) -> str:
        """
        Lee el contenido de un archivo.
        
        Args:
            project_id: ID del proyecto
            filename: Nombre del archivo
        
        Returns:
            Contenido del archivo
        """
        file_path = os.path.join(self.base_dir, project_id, filename)
        if not os.path.exists(file_path):
            return f"Error: El archivo {filename} no existe en el proyecto {project_id}"
        
        with open(file_path, 'r') as f:
            return f.read()
    
    def list_files(self, project_id: str) -> str:
        """
        Lista los archivos en un proyecto.
        
        Args:
            project_id: ID del proyecto
        
        Returns:
            Lista de archivos en formato texto
        """
        project_dir = os.path.join(self.base_dir, project_id)
        if not os.path.exists(project_dir):
            return f"El proyecto {project_id} no tiene archivos Python."
        
        files = [f for f in os.listdir(project_dir) if f.endswith('.py')]
        if not files:
            return f"El proyecto {project_id} no tiene archivos Python."
        
        return "\n".join(f"- {f}" for f in files)
    
    def file_exists(self, project_id: str, filename: str) -> bool:
        """
        Verifica si un archivo existe en el proyecto.
        
        Args:
            project_id: ID del proyecto
            filename: Nombre del archivo
        
        Returns:
            True si el archivo existe, False en caso contrario
        """
        return os.path.exists(os.path.join(self.base_dir, project_id, filename))

# ─────────────────────────────────────────────────────────────────────────────
# Herramientas
# ─────────────────────────────────────────────────────────────────────────────

code_repo = CodeRepository(GENERATED_CODE_DIR)

def generate_python_code(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Genera código Python basado en una descripción en lenguaje natural usando LangChain y Ollama.
    
    Argumentos:
      - description: Descripción de lo que debe hacer el código
      - project_id: Identificador del proyecto
      - filename: Nombre del archivo donde guardar el código
    """
    description = args.get("description", "")
    project_id = args.get("project_id", "default")
    filename = args.get("filename", "script.py")
    
    if not description:
        return "Error: Se requiere una descripción del código a generar"
    
    try:
        # Verificar modelos disponibles
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True, text=True, check=True
        )
        available_models = [line.split()[0] for line in result.stdout.splitlines()[1:]]
        model = "gemma3:latest"
        if model not in available_models:
            return f"Error: El modelo '{model}' no está disponible. Modelos disponibles: {', '.join(available_models)}"
        
        # Configurar LangChain con Ollama
        llm = ChatOllama(
            model=model,
            base_url="http://localhost:11434",
            temperature=0.2,
            num_ctx=4096
        )
        
        # Prompt más estricto para FastAPI/Jinja2
        prompt = ChatPromptTemplate.from_template(
            """Eres un experto en Python y FastAPI. Genera únicamente código Python válido para FastAPI con Jinja2. 
            Usa Jinja2Templates para renderizar plantillas HTML y TemplateResponse para devolver respuestas. 
            NO uses argumentos como template=True en decoradores de FastAPI. 
            Para formularios, usa 'Form(...)' desde 'fastapi'. 
            Sigue estrictamente PEP 8 y PEP 257. Incluye docstrings claros en el módulo y funciones. 
            NO incluyas Markdown, explicaciones, ni texto que no sea código Python ejecutable.
            NO uses eval ni exec. Asegúrate de que el código sea ejecutable con uvicorn para aplicaciones FastAPI.

            Descripción: {description}

            Respuesta (solo código Python ejecutable):
            """
        )
        
        # Crear cadena de LangChain
        chain = prompt | llm | StrOutputParser()
        
        # Generar código
        code = chain.invoke({"description": description})
        
        # Limpiar posibles artefactos de Markdown
        code = re.sub(r'```python\n|```', '', code).strip()
        
        # Validar sintaxis
        try:
            ast.parse(code)
        except SyntaxError as e:
            logger.error(f"Error de sintaxis en código generado: {e}")
            return f"Error: El código generado contiene un error de sintaxis en línea {e.lineno}: {e.msg}"
        
        # Añadir metadatos al código generado
        code = f"""#!/usr/bin/env python3
\"\"\"
{description}

Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
\"\"\"
{code}
"""
        
        # Corregir estilo con Ruff
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
            temp_file.write(code.encode())
            temp_file_path = temp_file.name
        
        try:
            subprocess.run(
                ["ruff", "format", temp_file_path],
                capture_output=True, text=True, check=True
            )
            subprocess.run(
                ["ruff", "check", "--fix", temp_file_path],
                capture_output=True, text=True, check=True
            )
            with open(temp_file_path, "r") as f:
                fixed_code = f.read()
        except subprocess.CalledProcessError as e:
            logger.warning(f"Ruff no pudo corregir el código: {e}")
            fixed_code = code
        finally:
            os.unlink(temp_file_path)
        
        # Guardar código corregido
        file_path = code_repo.save_file(project_id, filename, fixed_code)
        
        # Actualizar memoria
        memoria.append(f"Generado archivo {filename} en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria, description)
        
        return f"Código generado y guardado en {filename}. Ruta completa: {file_path}"
    
    except Exception as e:
        logger.error(f"Error generando código: {e}")
        return f"Error al generar código: {str(e)}"

def analyze_python_code(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Analiza código Python en busca de problemas o mejoras usando AST, linter y reglas específicas de FastAPI/Jinja2.
    
    Argumentos:
      - project_id: Identificador del proyecto
      - filename: Nombre del archivo a analizar
      - description: Descripción original del código (opcional, para validación contextual)
    """
    project_id = args.get("project_id", "default")
    filename = args.get("filename", "")
    description = args.get("description", "")
    
    if not filename:
        return "Error: Se requiere el nombre del archivo a analizar"
    
    if not code_repo.file_exists(project_id, filename):
        return f"Error: El archivo {filename} no existe en el proyecto {project_id}"
    
    file_path = os.path.join(GENERATED_CODE_DIR, project_id, filename)
    project_dir = os.path.join(GENERATED_CODE_DIR, project_id)
    
    try:
        # Leer el archivo
        with open(file_path, 'r') as f:
            code = f.read()
        
        issues = []
        
        # Análisis con AST
        try:
            tree = ast.parse(code)
            # Detectar uso de eval y patrones problemáticos
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id == 'eval':
                        issues.append(f"Advertencia: Uso de eval detectado en línea {node.lineno}")
                # Detectar decoradores de FastAPI con argumentos inválidos
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('get', 'post') and node.func.value.id == 'app':
                        for keyword in node.keywords:
                            if keyword.arg == 'template':
                                issues.append(f"Error: Argumento 'template' no válido en @app.{node.func.attr} en línea {node.lineno}")
                # Detectar uso de request.form
                if isinstance(node, ast.Attribute) and node.attr == 'form':
                    if isinstance(node.value, ast.Name) and node.value.id == 'request':
                        issues.append(f"Error: Uso incorrecto de 'request.form' en línea {node.lineno}. Use 'Form(...)' para formularios")
        
            ast_result = "Análisis AST: Código sintácticamente válido"
            if issues:
                ast_result += "\n" + "\n".join(issues)
        
        except SyntaxError as e:
            ast_result = f"Error de sintaxis en línea {e.lineno}: {e.msg}"
        
        # Análisis con Ruff
        try:
            result = subprocess.run(
                ["ruff", "check", file_path],
                capture_output=True, text=True, check=False
            )
            ruff_result = result.stdout or "Análisis Ruff: No se encontraron problemas"
        except subprocess.CalledProcessError as e:
            ruff_result = f"Error en Ruff: {e.stderr}"
        
        # Validación específica de FastAPI/Jinja2
        fastapi_issues = []
        
        # Verificar importaciones necesarias
        if 'fastapi' in code:
            if 'from fastapi import Form' not in code and 'request.form' in code:
                fastapi_issues.append("Error: Falta importar 'Form' de 'fastapi' para procesar formularios")
            if 'from fastapi.responses import HTMLResponse' not in code and 'response_class=HTMLResponse' in code:
                fastapi_issues.append("Error: Falta importar 'HTMLResponse' de 'fastapi.responses'")
        
        # Verificar estructura de TemplateResponse
        template_response_pattern = r'TemplateResponse\(.*response=.*\)'
        if re.search(template_response_pattern, code):
            fastapi_issues.append("Error: 'TemplateResponse' no acepta el argumento 'response'")
        
        # Verificar existencia de plantillas
        template_dir = os.path.join(project_dir, 'templates')
        template_names = re.findall(r'TemplateResponse\(.*name="([^"]+)"', code)
        for template_name in template_names:
            if not os.path.exists(os.path.join(template_dir, template_name)):
                fastapi_issues.append(f"Error: La plantilla '{template_name}' no existe en el directorio 'templates'")
        
        # Validación contextual con el prompt
        if description:
            if 'template.html' in description and 'template.html' not in code:
                fastapi_issues.append("Advertencia: El prompt especifica 'template.html', pero no se usa en el código")
            if '/formulario' in description and '@app.get("/formulario"' not in code:
                fastapi_issues.append("Error: Falta el endpoint '/formulario' requerido por el prompt")
            if '/submit' in description and '@app.post("/submit"' not in code:
                fastapi_issues.append("Error: Falta el endpoint '/submit' requerido por el prompt")
        
        fastapi_result = "Análisis FastAPI/Jinja2: No se encontraron problemas"
        if fastapi_issues:
            fastapi_result = "Análisis FastAPI/Jinja2:\n" + "\n".join(fastapi_issues)
        
        # Actualizar memoria
        memoria.append(f"Analizado archivo {filename} en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria, description)
        
        return f"{ast_result}\n\n{ruff_result}\n\n{fastapi_result}"
    
    except Exception as e:
        logger.error(f"Error analizando código: {e}")
        return f"Error al analizar código: {str(e)}"

def run_python_code(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Ejecuta un archivo Python y devuelve su salida. Soporta aplicaciones FastAPI con uvicorn.
    
    Argumentos:
      - project_id: Identificador del proyecto
      - filename: Nombre del archivo a ejecutar
      - args: Argumentos para pasar al script (opcional)
    """
    project_id = args.get("project_id", "default")
    filename = args.get("filename", "")
    script_args = args.get("args", [])
    
    if not filename:
        return "Error: Se requiere el nombre del archivo a ejecutar"
    
    if not code_repo.file_exists(project_id, filename):
        return f"Error: El archivo {filename} no existe en el proyecto {project_id}"
    
    file_path = os.path.join(GENERATED_CODE_DIR, project_id, filename)
    
    try:
        # Leer el código para detectar FastAPI
        with open(file_path, 'r') as f:
            code = f.read()
        
        # Determinar si es una aplicación FastAPI
        is_fastapi = 'from fastapi' in code.lower() and 'app = FastAPI()' in code
        
        if is_fastapi:
            # Ejecutar con uvicorn
            module_name = filename[:-3]  # Quitar .py
            cmd = ["uvicorn", f"{module_name}:app", "--port", "8000", "--reload"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(file_path)
            )
            # Esperar brevemente para capturar salida inicial
            try:
                stdout, stderr = process.communicate(timeout=5)
                output = stdout or ""
                if stderr:
                    output += f"\nErrores:\n{stderr}"
            except subprocess.TimeoutExpired:
                output = "Servidor FastAPI iniciado en http://127.0.0.1:8000 (ejecutándose en segundo plano)"
                process.terminate()
        else:
            # Ejecutar como script normal
            cmd = ["python3", file_path] + script_args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout
            if result.stderr:
                output += f"\nErrores:\n{result.stderr}"
        
        # Actualizar memoria
        memoria.append(f"Ejecutado archivo {filename} en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria)
        
        return output or "Código ejecutado exitosamente, sin salida."
    
    except subprocess.TimeoutExpired:
        return "Error: La ejecución del código excedió el tiempo límite"
    except Exception as e:
        logger.error(f"Error ejecutando código: {e}")
        return f"Error al ejecutar código: {str(e)}"

def list_project_files(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Lista todos los archivos en un proyecto.
    
    Argumentos:
      - project_id: Identificador del proyecto
    """
    project_id = args.get("project_id", "default")
    
    try:
        result = code_repo.list_files(project_id)
        
        # Actualizar memoria
        memoria.append(f"Listados archivos en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria)
        
        return result
    
    except Exception as e:
        logger.error(f"Error listando archivos: {e}")
        return f"Error al listar archivos: {str(e)}"

def read_python_file(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Lee el contenido de un archivo Python.
    
    Argumentos:
      - project_id: Identificador del proyecto
      - filename: Nombre del archivo a leer
    """
    project_id = args.get("project_id", "default")
    filename = args.get("filename", "")
    
    if not filename:
        return "Error: Se requiere el nombre del archivo a leer"
    
    try:
        result = code_repo.read_file(project_id, filename)
        
        # Actualizar memoria
        memoria.append(f"Leído archivo {filename} en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria)
        
        return result
    
    except Exception as e:
        logger.error(f"Error leyendo archivo: {e}")
        return f"Error al leer archivo: {str(e)}"

def fix_python_code(args: Dict[str, Any], memoria: List[str]) -> str:
    """
    Corrige errores en un archivo Python existente, incluyendo sintaxis, estilo y errores semánticos de FastAPI.
    
    Argumentos:
      - project_id: Identificador del proyecto
      - filename: Nombre del archivo a corregir
    """
    project_id = args.get("project_id", "default")
    filename = args.get("filename", "")
    
    if not filename:
        return "Error: Se requiere el nombre del archivo a corregir"
    
    if not code_repo.file_exists(project_id, filename):
        return f"Error: El archivo {filename} no existe en el proyecto {project_id}"
    
    file_path = os.path.join(GENERATED_CODE_DIR, project_id, filename)
    
    try:
        # Leer el archivo
        with open(file_path, 'r') as f:
            code = f.read()
        
        original_code = code
        corrections = []
        
        # Paso 1: Limpiar artefactos de Markdown
        code = re.sub(r'```python\n|```', '', code).strip()
        if code != original_code:
            corrections.append("Eliminados bloques de Markdown residuales")
        
        # Paso 2: Corregir errores específicos de FastAPI
        if '@app.get("/formulario", template=True)' in code:
            code = code.replace(
                '@app.get("/formulario", template=True)',
                '@app.get("/formulario", response_class=HTMLResponse)'
            )
            corrections.append("Reemplazado 'template=True' con 'response_class=HTMLResponse' en @app.get")
        
        if 'request.form.get' in code:
            # Añadir importación de Form si no existe
            if 'from fastapi import Form' not in code:
                code = code.replace(
                    'from fastapi import FastAPI, Request',
                    'from fastapi import FastAPI, Request, Form'
                )
                corrections.append("Añadida importación de 'Form' desde 'fastapi'")
            # Reemplazar request.form.get con Form(...)
            code = re.sub(
                r'(\w+) = request\.form\.get\("\1"\)',
                r'\1: str = Form(...)',
                code
            )
            corrections.append("Reemplazado 'request.form.get' con 'Form(...)' para formularios")
        
        if 'TemplateResponse(response=TemplateResponse' in code:
            code = re.sub(
                r'TemplateResponse\(response=TemplateResponse\(name="([^"]+)", context=([^)]+)\)\)',
                r'TemplateResponse(name="\1", context=\2, request=request)',
                code
            )
            corrections.append("Corregida estructura de TemplateResponse")
        
        # Paso 3: Validar y corregir sintaxis
        try:
            ast.parse(code)
        except SyntaxError as e:
            corrections.append(f"Error de sintaxis detectado en línea {e.lineno}: {e.msg}")
            lines = code.splitlines()
            if "invalid syntax" in str(e) and "```" in code:
                code = '\n'.join(line for line in lines if not line.strip().startswith('```'))
                corrections.append("Eliminados bloques de Markdown residuales adicionales")
            elif "unexpected EOF" in str(e):
                if code.count('"') % 2 == 1 or code.count("'") % 2 == 1:
                    code += '"'
                    corrections.append("Añadida comilla faltante al final")
                elif code.count('(') > code.count(')'):
                    code += ')'
                    corrections.append("Añadido paréntesis de cierre faltante")
        
        # Paso 4: Reformatear docstring para corregir D212, D400, D415, E501
        lines = code.splitlines()
        if lines and '"""' in lines[1]:
            docstring_lines = []
            in_docstring = False
            for i, line in enumerate(lines):
                if line.strip() == '"""' and not in_docstring:
                    in_docstring = True
                    docstring_lines.append(i)
                elif line.strip() == '"""' and in_docstring:
                    in_docstring = False
                    docstring_lines.append(i)
            
            if len(docstring_lines) >= 2:
                start, end = docstring_lines[0], docstring_lines[1]
                docstring_content = lines[start+1:end]
                docstring_content = [line for line in docstring_content if line.strip()]
                if docstring_content:
                    first_line = docstring_content[0].strip()
                    if not first_line.endswith('.'):
                        first_line += '.'
                    wrapped_lines = textwrap.wrap(first_line, width=88, subsequent_indent='    ')
                    docstring_content[0] = wrapped_lines[0]
                    if len(wrapped_lines) > 1:
                        docstring_content[1:1] = wrapped_lines[1:]
                    new_docstring = ['"""'] + docstring_content + ['"""']
                    lines[start:end+1] = new_docstring
                    corrections.append("Reformateado docstring para corregir D212, D400, D415, E501")
        
        code = '\n'.join(lines)
        
        # Paso 5: Corregir estilo con Ruff
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
            temp_file.write(code.encode())
            temp_file_path = temp_file.name
        
        try:
            subprocess.run(
                ["ruff", "format", temp_file_path],
                capture_output=True, text=True, check=True
            )
            result = subprocess.run(
                ["ruff", "check", "--fix", temp_file_path],
                capture_output=True, text=True, check=True
            )
            with open(temp_file_path, "r") as f:
                fixed_code = f.read()
            if result.stdout or result.stderr:
                corrections.append("Aplicadas correcciones de estilo con Ruff")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Ruff no pudo corregir el código: {e}")
            fixed_code = code
        finally:
            os.unlink(temp_file_path)
        
        # Paso 6: Validar sintaxis final
        try:
            ast.parse(fixed_code)
        except SyntaxError as e:
            return (f"Error: No se pudo corregir el archivo {filename}. "
                    f"Persiste error de sintaxis en línea {e.lineno}: {e.msg}\n"
                    f"Correcciones intentadas:\n" + "\n".join(corrections) if corrections else "Ninguna")
        
        # Paso 7: Guardar código corregido
        if fixed_code != original_code:
            file_path = code_repo.save_file(project_id, filename, fixed_code)
            corrections.append(f"Archivo corregido guardado en {file_path}")
        else:
            corrections.append("No se requirieron correcciones")
        
        # Actualizar memoria
        memoria.append(f"Corregido archivo {filename} en proyecto {project_id}")
        update_session(args.get("session_id", "default"), memoria)
        
        return "Correcciones aplicadas:\n" + "\n".join(corrections)
    
    except Exception as e:
        logger.error(f"Error corrigiendo código: {e}")
        return f"Error al corregir código: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# Definición de herramientas
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = {
    "generate_python_code": {
        "description": (
            "Genera código Python basado en una descripción en lenguaje natural usando LangChain y Ollama.\n\n"
            "Argumentos:\n"
            "  - description: Descripción de lo que debe hacer el código\n"
            "  - project_id: Identificador del proyecto\n"
            "  - filename: Nombre del archivo donde guardar el código"
        ),
        "params": {
            "description": {"description": "Descripción de lo que debe hacer el código", "required": True},
            "project_id": {"description": "Identificador del proyecto", "required": True},
            "filename": {"description": "Nombre del archivo donde guardar el código", "required": True}
        },
        "function": generate_python_code
    },
    "analyze_python_code": {
        "description": (
            "Analiza código Python en busca de problemas o mejoras usando AST, linter y reglas específicas.\n\n"
            "Argumentos:\n"
            "  - project_id: Identificador del proyecto\n"
            "  - filename: Nombre del archivo a analizar\n"
            "  - description: Descripción original del código (opcional)"
        ),
        "params": {
            "project_id": {"description": "Identificador del proyecto", "required": True},
            "filename": {"description": "Nombre del archivo a analizar", "required": True},
            "description": {"description": "Descripción original del código", "required": False}
        },
        "function": analyze_python_code
    },
    "run_python_code": {
        "description": (
            "Ejecuta un archivo Python y devuelve su salida. Soporta aplicaciones FastAPI con uvicorn.\n\n"
            "Argumentos:\n"
            "  - project_id: Identificador del proyecto\n"
            "  - filename: Nombre del archivo a ejecutar\n"
            "  - args: Argumentos para pasar al script (opcional)"
        ),
        "params": {
            "project_id": {"description": "Identificador del proyecto", "required": True},
            "filename": {"description": "Nombre del archivo a ejecutar", "required": True},
            "args": {"description": "Argumentos para pasar al script (opcional)", "required": False}
        },
        "function": run_python_code
    },
    "list_project_files": {
        "description": (
            "Lista todos los archivos en un proyecto.\n\n"
            "Argumentos:\n"
            "  - project_id: Identificador del proyecto"
        ),
        "params": {
            "project_id": {"description": "Identificador del proyecto", "required": True}
        },
        "function": list_project_files
    },
    "read_python_file": {
        "description": (
            "Lee el contenido de un archivo Python.\n\n"
            "Argumentos:\n"
            "  - project_id: Identificador del proyecto\n"
            "  - filename: Nombre del archivo a leer"
        ),
        "params": {
            "project_id": {"description": "Identificador del proyecto", "required": True},
            "filename": {"description": "Nombre del archivo a leer", "required": True}
        },
        "function": read_python_file
    },
    "fix_python_code": {
        "description": (
            "Corrige errores en un archivo Python existente, incluyendo sintaxis, estilo y errores semánticos.\n\n"
            "Argumentos:\n"
            "  - project_id: Identificador del proyecto\n"
            "  - filename: Nombre del archivo a corregir"
        ),
        "params": {
            "project_id": {"description": "Identificador del proyecto", "required": True},
            "filename": {"description": "Nombre del archivo a corregir", "required": True}
        },
        "function": fix_python_code
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Servidor de sockets
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(client_socket: socket.socket, address: tuple):
    """
    Maneja una conexión de cliente.
    
    Args:
        client_socket: Socket del cliente
        address: Dirección del cliente
    """
    logger.info(f"Nueva conexión desde {address}")
    
    try:
        data = client_socket.recv(4096).decode("utf-8").strip()
        if not data:
            logger.warning("No se recibieron datos")
            return
        
        message = json.loads(data)
        message_type = message.get("type")
        session_id = message.get("session_id", "default")
        
        # Cargar memoria de la sesión
        sessions = load_sessions()
        session_data = sessions.get(session_id, {"memoria": [], "description": ""})
        memoria = session_data["memoria"]
        
        response = {}
        
        if message_type == "list_tools":
            response = {
                "type": "tool_list",
                "tools": list(TOOLS.keys())
            }
        
        elif message_type == "get_all_tools_metadata":
            response = {
                "type": "all_tools_metadata",
                "metadata": {
                    name: {
                        "description": tool["description"],
                        "params": tool["params"]
                    } for name, tool in TOOLS.items()
                }
            }
        
        elif message_type == "call_tool":
            tool_name = message.get("tool")
            args = message.get("arguments", {})
            
            if tool_name not in TOOLS:
                response = {
                    "type": "text",
                    "text": f"Error: Herramienta {tool_name} no encontrada"
                }
            else:
                try:
                    result = TOOLS[tool_name]["function"](args, memoria)
                    response = {
                        "type": "text",
                        "text": result
                    }
                except Exception as e:
                    logger.error(f"Error ejecutando herramienta {tool_name}: {e}")
                    response = {
                        "type": "text",
                        "text": f"Error ejecutando herramienta {tool_name}: {str(e)}"
                    }
        
        else:
            response = {
                "type": "text",
                "text": f"Error: Tipo de mensaje desconocido: {message_type}"
            }
        
        # Enviar respuesta
        client_socket.send((json.dumps(response) + "\n").encode("utf-8"))
    
    except json.JSONDecodeError:
        logger.error("Error decodificando mensaje JSON")
        client_socket.send(json.dumps({
            "type": "text",
            "text": "Error: Mensaje JSON inválido"
        }).encode("utf-8"))
    except Exception as e:
        logger.error(f"Error manejando cliente: {e}")
        client_socket.send(json.dumps({
            "type": "text",
            "text": f"Error: {str(e)}"
        }).encode("utf-8"))
    finally:
        client_socket.close()

def main():
    """Función principal del servidor."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"Servidor iniciado en {HOST}:{PORT}")
        
        while True:
            client_socket, address = server_socket.accept()
            handle_client(client_socket, address)
    
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario")
    except Exception as e:
        logger.error(f"Error en el servidor: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()