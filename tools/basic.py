# tools/basic.py

def append_nota(args, memoria: list[str]) -> str:
    """
    Agrega una nueva nota textual a la sesión actual.
    Argumentos esperados:
      - nota: str
    """
    nota = args.get("nota")
    if not nota:
        return "Falta el argumento obligatorio: 'nota'."
    memoria.append(nota)
    return f"Nota registrada: {nota}"

def leer_notas(args, memoria: list[str]) -> str:
    """
    Devuelve todas las notas registradas en la sesión actual.
    """
    if not memoria:
        return "No hay notas registradas aún en esta sesión."
    return "Notas registradas:\n" + "\n".join(f"- {n}" for n in memoria)
