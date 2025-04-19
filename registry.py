# registry.py

# ─────────────────────────────────────────────────────────────────────────────
# Registro de herramientas, prompts y recursos del protocolo MCP
# ─────────────────────────────────────────────────────────────────────────────

from typing import Callable

# Repositorios internos
_tools: dict[str, Callable] = {}
_prompts: dict[str, Callable] = {}

# ─────────────────────────────────────────────────────────────────────────────
# Registro de Tools
# ─────────────────────────────────────────────────────────────────────────────

def register_tool(name: str, func: Callable):
    if name in _tools:
        raise ValueError(f"Tool '{name}' ya está registrada.")
    _tools[name] = func

def get_tool(name: str) -> Callable | None:
    return _tools.get(name)

def list_tools() -> list[str]:
    return list(_tools.keys())

# ─────────────────────────────────────────────────────────────────────────────
# Registro de Prompts
# ─────────────────────────────────────────────────────────────────────────────

def register_prompt(name: str, func: Callable):
    if name in _prompts:
        raise ValueError(f"Prompt '{name}' ya está registrado.")
    _prompts[name] = func

def get_prompt(name: str) -> Callable | None:
    return _prompts.get(name)

def list_prompts() -> list[str]:
    return list(_prompts.keys())

# ─────────────────────────────────────────────────────────────────────────────
# Inicialización (se cargan todas las entidades MCP disponibles)
# ─────────────────────────────────────────────────────────────────────────────

def init_registry():
    from tools.basic import append_nota, leer_notas
    from prompts.educativo import inicia_clase

    register_tool("append_nota", append_nota)
    register_tool("leer_notas", leer_notas)

    register_prompt("inicia-clase", inicia_clase)

# ─────────────────────────────────────────────────────────────────────────────
# Diagnóstico y depuración
# ─────────────────────────────────────────────────────────────────────────────

def debug_registry():
    return {
        "tools": list_tools(),
        "prompts": list_prompts()
    }
