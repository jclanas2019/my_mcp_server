# MCP SDK - Model Communication Protocol

El SDK de MCP proporciona una interfaz elegante y robusta para interactuar con servidores MCP, permitiendo a los desarrolladores crear agentes inteligentes que descubren y utilizan herramientas de forma dinámica.

## Características principales

- **Discovery automático de herramientas**: Descubre dinámicamente las herramientas disponibles en el servidor MCP sin necesidad de codificarlas explícitamente.
- **API dinámica e intuitiva**: Accede a las herramientas como si fueran métodos nativos de tu agente (`agent.tools.append_nota()`).
- **Modo fallback integrado**: Funciona incluso cuando el servidor no está disponible, usando implementaciones locales.
- **Manejo robusto de errores**: Reintentos automáticos, timeouts configurables y errores específicos para cada situación.
- **Documentación integrada**: Consulta metadatos, parámetros y ejemplos de uso de las herramientas directamente desde el código.

## Instalación

```bash
# Próximamente disponible en PyPI
pip install mcp-sdk

# Mientras tanto, puedes copiar mcp_sdk.py a tu proyecto
```

## Uso básico

```python
from mcp_sdk import create_mcp_agent, MCPError

# Crear un agente con configuración por defecto
agent = create_mcp_agent()

# Descubrir herramientas disponibles
agent.discover_tools()
tools = agent.list_tools()
print(f"Herramientas disponibles: {', '.join(tools)}")

# Usar una herramienta
try:
    result = agent.execute_tool("leer_notas")
    print(f"Resultado: {result}")
    
    # Agregar una nota
    agent.execute_tool("append_nota", nota="Esto es una prueba")
except MCPError as e:
    print(f"Error: {e}")
```

## Acceso directo a herramientas

```python
# Las herramientas se pueden usar como objetos directamente
append_nota = agent.tools.append_nota
leer_notas = agent.tools.leer_notas

# Usar herramientas directamente
leer_notas()  # Leer notas actuales
append_nota(nota="Nueva nota")  # Agregar nota
```

## Gestión de errores

```python
from mcp_sdk import (
    MCPError,
    MCPConnectionError,
    MCPTimeoutError,
    MCPToolNotFoundError,
    MCPToolExecutionError
)

try:
    agent.execute_tool("herramienta_inexistente")
except MCPToolNotFoundError as e:
    print(f"La herramienta no existe: {e}")
except MCPConnectionError as e:
    print(f"Error de conexión: {e}")
except MCPTimeoutError as e:
    print(f"Timeout: {e}")
except MCPToolExecutionError as e:
    print(f"Error ejecutando la herramienta: {e}")
except MCPError as e:
    print(f"Error genérico: {e}")
```

## Configuración personalizada

```python
from mcp_sdk import MCPConfig, MCPAgent

# Configuración personalizada
config = MCPConfig(
    host="192.168.1.100",
    port=8080,
    timeout=15,
    max_retries=5,
    retry_delay=1,
    log_level=logging.DEBUG,
    session_id="mi-sesion-personalizada",
    use_fallback=True
)

# Crear agente con configuración personalizada
agent = MCPAgent(config)
```

## Herramientas de fallback personalizadas

```python
from mcp_sdk import create_mcp_agent

# Definir funciones de fallback personalizadas
def mi_append_nota(nota, **kwargs):
    """Mi implementación personalizada de append_nota."""
    print(f"Guardando nota: {nota}")
    return "Nota guardada (simulación)"

def mi_leer_notas(**kwargs):
    """Mi implementación personalizada de leer_notas."""
    return "No hay notas (simulación)"

# Crear agente con herramientas de fallback personalizadas
fallback_tools = {
    "append_nota": mi_append_nota,
    "leer_notas": mi_leer_notas
}

agent = create_mcp_agent(fallback_tools=fallback_tools)
```

## Componentes principales

- **MCPAgent**: Clase principal para interactuar con el servidor MCP y usar herramientas.
- **MCPClient**: Maneja la comunicación con el servidor MCP.
- **MCPTools**: Proporciona acceso dinámico a las herramientas descubiertas.
- **ToolRegistry**: Gestiona el registro y descubrimiento de herramientas.
- **Tool, RemoteTool, LocalTool**: Representan herramientas para usar con el agente.

## Ejemplo completo

```python
from mcp_sdk import create_mcp_agent, MCPError

def main():
    # Crear agente
    agent = create_mcp_agent()
    print(f"Agente inicializado con session_id: {agent.config.session_id}")
    
    # Verificar disponibilidad del servidor
    if agent.is_server_available():
        print("Servidor MCP disponible")
    else:
        print("Servidor MCP no disponible, usando modo fallback")
    
    # Mostrar información de herramientas
    agent.discover_tools()
    help_text = agent.tools.show_tool_help()
    print(help_text)
    
    # Flujo de trabajo de ejemplo
    try:
        # Leer notas existentes
        result = agent.execute_tool("leer_notas")
        print(f"Notas existentes: {result}")
        
        # Agregar nota
        nota = "Ejemplo de nota creada con MCP SDK"
        result = agent.execute_tool("append_nota", nota=nota)
        print(f"Resultado: {result}")
        
        # Verificar
        result = agent.execute_tool("leer_notas")
        print(f"Notas actualizadas: {result}")
    except MCPError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## Integración con LLMs

```python
from mcp_sdk import create_mcp_agent
from langchain_ollama import OllamaLLM

# Crear agente MCP
agent = create_mcp_agent()
agent.discover_tools()

# Inicializar LLM
llm = OllamaLLM(model="gemma3:1b")

# Generar contenido con el LLM
prompt = """
Genera una nota académica breve sobre LangChain.
La nota debe ser concisa y clara.
"""
generated_content = llm.invoke(prompt)

# Procesar la respuesta según su tipo
if hasattr(generated_content, 'content'):
    nota = generated_content.content
else:
    nota = str(generated_content)

# Guardar la nota generada usando el agente MCP
result = agent.execute_tool("append_nota", nota=nota)
print(f"Nota guardada: {result}")

# Leer todas las notas
all_notes = agent.execute_tool("leer_notas")
print(f"Todas las notas: {all_notes}")
```

## Extendiendo el SDK

### Añadir una herramienta local

```python
from mcp_sdk import LocalTool, ToolMetadata, create_mcp_agent

# Definir función para la herramienta
def calcular_promedio(numeros, **kwargs):
    """
    Calcula el promedio de una lista de números.
    
    Args:
        numeros: Lista de números
    
    Returns:
        El promedio calculado
    """
    if not numeros:
        return "Error: Lista vacía"
    return sum(numeros) / len(numeros)

# Crear metadatos para la herramienta
metadata = ToolMetadata(
    name="calcular_promedio",
    description="Calcula el promedio de una lista de números",
    params={
        "numeros": {
            "type": "array",
            "description": "Lista de números",
            "required": True
        }
    },
    examples=[
        {"numeros": [1, 2, 3, 4, 5]}
    ],
    returns="El promedio calculado como número decimal"
)

# Crear agente
agent = create_mcp_agent()

# Registrar la herramienta local
agent.registry.register_local_tool(
    name="calcular_promedio",
    function=calcular_promedio,
    metadata=metadata
)

# Usar la herramienta
resultado = agent.execute_tool("calcular_promedio", numeros=[10, 20, 30, 40])
print(f"El promedio es: {resultado}")
```

## Contribuir

Las contribuciones son bienvenidas. Para contribuir:

1. Haz fork del repositorio
2. Crea una rama para tu feature (`git checkout -b feature/amazing-feature`)
3. Haz commit de tus cambios (`git commit -m 'Add amazing feature'`)
4. Empuja a la rama (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Para preguntas o soporte, contacta a [jc@lab-ai.org](mailto:jc@lab-ai.org).
