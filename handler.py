# handler.py

from registry import get_tool, get_prompt, list_tools, list_prompts

# Base de datos en memoria: notas por sesión
notas_por_sesion: dict[str, list[str]] = {}

def get_sesion(session_id: str) -> list[str]:
    if session_id not in notas_por_sesion:
        notas_por_sesion[session_id] = []
    return notas_por_sesion[session_id]

def handle_message(message: dict) -> dict:
    tipo = message.get("type")
    session_id = message.get("session_id", "default")  # por defecto "default"

    if tipo == "call_tool":
        name = message.get("tool")
        args = message.get("arguments", {})
        tool = get_tool(name)
        if not tool:
            return {
                "type": "error",
                "text": f"Herramienta no encontrada: {name}"
            }

        memoria = get_sesion(session_id)
        try:
            resultado = tool(args, memoria)
            return {
                "type": "text",
                "text": resultado
            }
        except Exception as e:
            return {
                "type": "error",
                "text": f"Error al ejecutar la herramienta: {str(e)}"
            }

    elif tipo == "get_prompt":
        name = message.get("prompt")
        prompt = get_prompt(name)
        if not prompt:
            return {
                "type": "error",
                "text": f"Prompt no encontrado: {name}"
            }
        return {
            "type": "text",
            "text": prompt()
        }

    elif tipo == "list_tools":
        return {
            "type": "tool_list",
            "tools": list_tools()
        }

    elif tipo == "list_prompts":
        return {
            "type": "prompt_list",
            "prompts": list_prompts()
        }

    else:
        return {
            "type": "error",
            "text": f"Tipo de mensaje desconocido: {tipo}"
        }
