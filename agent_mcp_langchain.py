#!/usr/bin/env python3
import socket
import json
import uuid
import warnings
from typing import Dict, List, Any

# Suprimimos warnings de depreciación
warnings.filterwarnings("ignore", category=DeprecationWarning)

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
# Definición de herramientas MCP
# ─────────────────────────────────────────────────────────────────────────────

def leer_notas() -> str:
    """Lee todas las notas académicas registradas en esta sesión."""
    msg = {
        "type": "call_tool",
        "tool": "leer_notas",
        "arguments": {},
        "session_id": SESSION_ID
    }
    with socket.create_connection(("127.0.0.1", 5050)) as s:
        s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        response = s.recv(4096)
        return json.loads(response.decode("utf-8")).get("text", "No hay notas registradas.")

def append_nota(nota: str) -> str:
    """Agrega una nota textual al registro académico."""
    msg = {
        "type": "call_tool",
        "tool": "append_nota",
        "arguments": {"nota": nota},
        "session_id": SESSION_ID
    }
    with socket.create_connection(("127.0.0.1", 5050)) as s:
        s.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        response = s.recv(4096)
        return json.loads(response.decode("utf-8")).get("text", "Nota agregada con éxito.")

# ─────────────────────────────────────────────────────────────────────────────
# Ejecución secuencial simplificada
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 1. Primero leemos las notas existentes
    print("\n--- Paso 1: Leyendo notas existentes ---")
    result_leer = leer_notas()
    print(f"🔍 Resultado: {result_leer}")
    
    # 2. Generamos una nueva nota
    print("\n--- Paso 2: Generando nueva nota ---")
    system_prompt = """
    Eres un asistente académico que trabaja exclusivamente en español.
    Genera una nota académica informativa sobre LangChain y su integración con MCP.
    La nota debe ser concisa (máximo 3 frases), clara y en español.
    """
    
    # Llamamos al modelo de forma simplificada
    nueva_nota = llm.invoke(system_prompt)
    # Aseguramos que el resultado sea siempre un string, independientemente del tipo retornado
    if hasattr(nueva_nota, 'content'):
        nueva_nota = nueva_nota.content
    
    print(f"📝 Nota generada: {nueva_nota}")
    
    # 3. Guardamos la nueva nota
    print("\n--- Paso 3: Guardando nota ---")
    result_append = append_nota(nueva_nota)
    print(f"✅ Resultado: {result_append}")
    
    print("\n--- Proceso completado ---")