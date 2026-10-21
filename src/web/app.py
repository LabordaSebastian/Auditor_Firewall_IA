"""Aplicación FastAPI del dashboard web (MEJ-05)."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.web.routes import router

WEB_DIR = Path(__file__).resolve().parent


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cisco AI Firewall Auditor - Dashboard",
        description="Dashboard interactivo con Digital Twin Batfish",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "templates" / "index.html")

    return app


app = create_app()
