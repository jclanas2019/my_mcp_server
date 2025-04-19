# MCP Server - Sistema Seguro de Comunicación para Agentes LLM

## Descripción

MCP (Model Communication Protocol) es un sistema cliente-servidor TCP que facilita la comunicación entre agentes de IA y servicios de almacenamiento. Esta arquitectura permite a los agentes LLM (Large Language Models) ejecutar herramientas, compartir información y mantener contexto a través de sesiones, todo con un enfoque prioritario en la seguridad.

## Características principales

- **Arquitectura cliente-servidor**: Comunicación TCP para agentes distribuidos
- **Registro de herramientas y prompts**: Sistema modular y extensible
- **Seguridad mejorada**: Validación de sesiones, sanitización de datos y prevención de ataques
- **Soporte para agentes LLM**: Integración con LangChain y modelos locales (Ollama)
- **Comunicación asíncrona**: Manejo multihilo para múltiples conexiones simultáneas
- **Logging detallado**: Registro completo de actividades para auditoría y depuración

## Estructura del proyecto

```
my_mcp_server/
├── main.py                    # Servidor TCP principal
├── main_seguro.py             # Versión segura del servidor
├── handler.py                 # Manejador de mensajes y herramientas
├── registry.py                # Registro de herramientas y prompts
├── tools/                     # Implementaciones de herramientas
│   └── basic.py               # Herramientas básicas (notas)
├── prompts/                   # Prompts y templates
│   └── educativo.py           # Prompts educativos
├── agents/                    # Implementaciones de agentes
│   ├── agent_mcp_langchain.py       # Agente básico con LangChain
│   ├── agent_mcp_educativo.py       # Agente educativo con pipeline
│   └── agent_mcp_educativo_seguro.py # Agente educativo con seguridad
├── logs/                      # Directorio para logs
│   └── mcp_server_*.log       # Archivos de log por fecha
└── test_mcp_client.py         # Cliente de prueba
```

## Requisitos

- Python 3.10 o superior
- LangChain (para los agentes)
- Ollama (para modelos locales)
- Biblioteca estándar de Python

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/usuario/my_mcp_server.git
   cd my_mcp_server
   ```

2. Instala las dependencias:
   ```bash
   pip install langchain langchain-ollama 
   ```

3. Asegúrate de tener Ollama instalado y el modelo `gemma3:1b` disponible:
   ```bash
   ollama pull gemma3:1b
   ```

## Uso

### Iniciar el servidor

Para iniciar el servidor estándar:
```bash
python main.py
```

Para iniciar el servidor con medidas de seguridad mejoradas:
```bash
python main_seguro.py
```

### Ejecutar un agente cliente

Agente básico:
```bash
python agents/agent_mcp_langchain.py
```

Agente educativo:
```bash
python agents/agent_mcp_educativo.py
```

Agente educativo con seguridad:
```bash
python agents/agent_mcp_educativo_seguro.py
```

### Probar con el cliente de prueba

```bash
python test_mcp_client.py
```

## Medidas de seguridad implementadas

- **Validación de sesiones**: IDs de sesión firmados con HMAC-SHA256
- **Sanitización de entradas**: Filtrado de patrones maliciosos y contenido peligroso
- **Límites de tamaño**: Prevención de ataques DoS y desbordamientos de buffer
- **Rate limiting**: Protección contra abuso por dirección IP
- **Gestión segura de errores**: Captura y manejo adecuado de excepciones
- **Timeouts**: Prevención de conexiones zombies
- **Logging de seguridad**: Registro de eventos para auditoría
- **Validación estricta de JSON**: Prevención de inyecciones

## Herramientas disponibles

- `leer_notas`: Lee todas las notas registradas en la sesión actual
- `append_nota`: Agrega una nueva nota a la sesión actual

## Personalización

### Agregar nuevas herramientas

1. Crea un nuevo archivo en el directorio `tools/`
2. Define funciones que acepten `(args, memoria)` como parámetros
3. Registra las herramientas en `registry.py`

### Agregar nuevos prompts

1. Crea o modifica archivos en el directorio `prompts/`
2. Define templates o funciones generadoras de prompts
3. Registra los prompts en `registry.py`

## Contribuir

Las contribuciones son bienvenidas. Por favor, sigue estos pasos:

1. Haz fork del repositorio
2. Crea una rama (`git checkout -b feature/nueva-caracteristica`)
3. Haz commit de tus cambios (`git commit -am 'Añadir nueva característica'`)
4. Haz push a la rama (`git push origin feature/nueva-caracteristica`)
5. Crea un Pull Request

## Licencia

[MIT](LICENSE)

## Contacto

Para preguntas o soporte, contacta a [tu-email@ejemplo.com](mailto:tu-email@ejemplo.com)
