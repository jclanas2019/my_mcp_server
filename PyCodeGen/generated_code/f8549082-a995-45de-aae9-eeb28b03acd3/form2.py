#!/usr/bin/env python3
"""
Crear un programa Python que use FastAPI y Jinja2 para mostrar un formulario web (GET /formulario) con los campos rut, nombre, edad, dirección, y procesar los datos enviados (POST /submit) mostrando los datos recibidos. Usar Jinja2Templates para renderizar un archivo template.html ubicado en un directorio templates. Incluir docstrings y seguir PEP 8.

Generated at: 2025-04-19 18:03:54
"""

from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
import uvicorn

app = FastAPI()
templates = Jinja2Templates(directory="templates")


def run_app():
    """
    Ejecuta la aplicación FastAPI con Uvicorn.
    """
    uvicorn.run(app, host="0.0.0.0", port=8000)


@app.get("/formulario", response_class=templates.ResponseClass)
async def formulario(request: Request):
    """
    Muestra el formulario HTML para recopilar datos del usuario.
    """
    return templates.TemplateResponse(
        template="formulario.html", context={"title": "Formulario de Datos"}
    )


@app.post("/submit", response_class=templates.ResponseClass)
async def submit(
    rut: str = Form(...),
    nombre: str = Form(...),
    edad: str = Form(...),
    direccion: str = Form(...),
):
    """
    Procesa los datos enviados desde el formulario y los muestra.
    """
    return templates.TemplateResponse(
        template="resultado.html",
        context={
            "rut": rut,
            "nombre": nombre,
            "edad": edad,
            "direccion": direccion,
            "title": "Datos Recibidos",
        },
    )


if __name__ == "__main__":
    run_app()
