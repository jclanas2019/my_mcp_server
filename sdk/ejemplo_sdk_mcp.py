#!/usr/bin/env python3
"""
Ejemplo de uso del SDK MCP para crear un agente personalizado que utiliza
herramientas descubiertas dinámicamente del servidor MCP.
"""

import logging
import sys
from typing import Optional

# Importamos el SDK MCP
from mcp_sdk import (
    create_mcp_agent,
    MCPError,
    MCPToolNotFoundError,
    MCPConnectionError,
    MCPTimeoutError,
    MCPConfig  # Importamos MCPConfig para configuración personalizada
)

# Configuración opcional de logging
logging.basicConfig(level=logging.INFO)

# ─────────────────────────────────────────────────────────────────────────────
# Ejemplo: Agente básico con discovery automático
# ─────────────────────────────────────────────────────────────────────────────

def ejemplo_basico():
    """Ejemplo de uso básico del SDK MCP."""
    print("=== Ejemplo básico de agente MCP ===")
    
    # Creamos un agente con valores por defecto
    agent = create_mcp_agent()
    print(f"Agente creado con ID: {agent.config.session_id}")
    
    # Verificamos disponibilidad del servidor
    if agent.is_server_available():
        print("✅ Servidor MCP disponible")
    else:
        print("⚠️ Servidor MCP no disponible, usando modo fallback")
    
    # Descubrimos herramientas
    try:
        agent.discover_tools()
        tools = agent.list_tools()
        print(f"Herramientas disponibles: {', '.join(tools)}")
    except MCPError as e:
        print(f"Error en descubrimiento: {e}")
        return
    
    # Usamos la herramienta leer_notas
    try:
        result = agent.execute_tool("leer_notas")
        print(f"Notas actuales: {result}")
    except MCPError as e:
        print(f"Error leyendo notas: {e}")
    
    # Agregamos una nota nueva
    try:
        nota = "Esta es una nota creada mediante el SDK MCP"
        result = agent.execute_tool("append_nota", nota=nota)
        print(f"Resultado: {result}")
    except MCPError as e:
        print(f"Error agregando nota: {e}")
    
    # Verificamos que la nota se guardó
    try:
        result = agent.execute_tool("leer_notas")
        print(f"Notas actuales: {result}")
    except MCPError as e:
        print(f"Error leyendo notas: {e}")
    
    print("Ejemplo básico completado.")

# ─────────────────────────────────────────────────────────────────────────────
# Ejemplo: Flujo de trabajo académico con manejo de errores
# ─────────────────────────────────────────────────────────────────────────────

def flujo_academico():
    """Ejemplo de flujo de trabajo académico con manejo de errores."""
    print("\n=== Flujo de trabajo académico ===")
    
    # Configuramos un agente con timeout más corto para pruebas
    config = MCPConfig(timeout=5)  # Creamos configuración con timeout personalizado
    agent = create_mcp_agent()
    agent.config = config  # Asignamos la configuración al agente
    
    print(f"Agente académico creado con ID: {agent.config.session_id}")
    
    # Descubrimos herramientas con manejo de error
    try:
        agent.discover_tools()
    except MCPConnectionError:
        print("⚠️ No se pudo conectar al servidor, usando modo fallback")
    except MCPTimeoutError:
        print("⚠️ Timeout al conectar con el servidor, usando modo fallback")
    except MCPError as e:
        print(f"⚠️ Error general: {e}")
        return
    
    # Mostramos información detallada de una herramienta
    print("\nDetalles de la herramienta append_nota:")
    try:
        help_text = agent.tools.show_tool_help("append_nota")
        print(help_text)
    except MCPToolNotFoundError:
        print("❌ Herramienta no encontrada")
    
    # Definimos algunas notas académicas para agregar
    notas_academicas = [
        "LangChain proporciona componentes para trabajar con LLMs",
        "La arquitectura de agente-herramienta permite la automatización de tareas",
        "El discovery automático facilita la extensibilidad de los sistemas"
    ]
    
    # Agregamos las notas una por una con manejo de errores
    print("\nAgregando notas académicas:")
    for i, nota in enumerate(notas_academicas, 1):
        try:
            resultado = agent.execute_tool("append_nota", nota=nota)
            print(f"✅ Nota {i} agregada: {resultado}")
        except MCPError as e:
            print(f"❌ Error al agregar nota {i}: {e}")
    
    # Finalmente leemos todas las notas
    print("\nResumen de notas académicas:")
    try:
        resultado = agent.execute_tool("leer_notas")
        print(resultado)
    except MCPError as e:
        print(f"❌ Error al leer notas: {e}")
    
    print("Flujo académico completado.")

# ─────────────────────────────────────────────────────────────────────────────
# Ejemplo: Herramientas como objetos directos
# ─────────────────────────────────────────────────────────────────────────────

def herramientas_como_objetos():
    """Ejemplo de uso de herramientas como objetos directos."""
    print("\n=== Herramientas como objetos ===")
    
    # Creamos un agente
    agent = create_mcp_agent()
    
    # Aseguramos que las herramientas están descubiertas
    agent.discover_tools()
    
    # Accedemos directamente a las herramientas como atributos
    try:
        # Obtenemos referencias a las herramientas
        append_nota = agent.tools.append_nota
        leer_notas = agent.tools.leer_notas
        
        # Las herramientas son objetos callable
        print("Tipo de append_nota:", type(append_nota))
        
        # Mostramos la documentación de la herramienta
        print("\nDocumentación de append_nota:")
        print(append_nota.help())
        
        # Usamos las herramientas directamente
        print("\nUtilizando herramientas como objetos:")
        
        # Leemos notas actuales
        resultado = leer_notas()
        print(f"Notas antes: {resultado}")
        
        # Agregamos una nueva nota
        resultado = append_nota(nota="Nota creada usando herramientas como objetos")
        print(f"Resultado: {resultado}")
        
        # Verificamos el cambio
        resultado = leer_notas()
        print(f"Notas después: {resultado}")
        
    except AttributeError as e:
        print(f"❌ Error accediendo a herramientas: {e}")
    except MCPError as e:
        print(f"❌ Error de MCP: {e}")
    
    print("Ejemplo de herramientas como objetos completado.")

# ─────────────────────────────────────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Función principal para ejecutar ejemplos."""
    print("Ejemplos de uso del SDK MCP\n")
    
    # Si se especifica un ejemplo, ejecutamos solo ese
    if len(sys.argv) > 1:
        ejemplo = sys.argv[1].lower()
        if ejemplo == "basico":
            ejemplo_basico()
        elif ejemplo == "academico":
            flujo_academico()
        elif ejemplo == "objetos":
            herramientas_como_objetos()
        else:
            print(f"Ejemplo desconocido: {ejemplo}")
            print("Ejemplos disponibles: basico, academico, objetos")
        return
    
    # Si no se especifica, ejecutamos todos
    ejemplo_basico()
    flujo_academico()
    herramientas_como_objetos()

if __name__ == "__main__":
    main()