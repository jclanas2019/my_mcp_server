#!/usr/bin/env python3
"""
Crear un programa Python que use FastAPI y Jinja2 para mostrar un formulario web (GET /formulario) con los campos rut, nombre, edad, dirección, y procesar los datos enviados (POST /submit) mostrando los datos recibidos. Usar Jinja2Templates para renderizar un archivo template.html ubicado en un directorio templates. Incluir docstrings y seguir PEP 8.

Generated at: 2025-04-19 18:08:55
"""

from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
import uvicorn

app = FastAPI()
templates = Jinja2Templates(directory="templates")


def mostrar_formulario():
    """
    Renderiza el formulario HTML para la recopilación de datos.
    """
    return templates.TemplateResponse(
        "formulario.html", context={"title": "Formulario de Datos"}
    )


def procesar_formulario(request: Request):
    """
    Procesa los datos del formulario y los devuelve como respuesta.
    """
    rut = Form("rut")
    nombre = Form("nombre")
    edad = Form("edad")
    direccion = Form("direccion")

    context = {
        "rut": rut.value,
        "nombre": nombre.value,
        "edad": edad.value,
        "direccion": direccion.value,
        "title": "Datos Recibidos",
    }
    return templates.TemplateResponse("respuesta.html", context=context)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
