"""Endpoints REST del dashboard (MEJ-05 / RF-07, RF-08, RF-09)."""
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from src.batfish_analyzer import BatfishUnavailableError
from src.pdf_generator import build_pdf
from src.web.service import SessionNotFound, service

router = APIRouter(prefix="/api")

MAX_CONFIG_BYTES = 2 * 1024 * 1024


class TracerouteRequest(BaseModel):
    zona_origen: str
    src_ip: str = Field(..., max_length=45)
    dst_ip: str = Field(..., max_length=45)
    protocolo: str = Field("TCP", pattern="^(TCP|UDP|ICMP|tcp|udp|icmp)$")
    puerto: Optional[int] = Field(None, ge=1, le=65535)


class DiffRequest(BaseModel):
    plan: str = Field("A", pattern="^[ABab]$")


def _session(session_id: str):
    try:
        return service.get(session_id)
    except SessionNotFound:
        raise HTTPException(404, "Sesión no encontrada. Ejecuta una auditoría primero.")


def _batfish_guard(fn):
    try:
        return fn()
    except BatfishUnavailableError as exc:
        raise HTTPException(503, f"Batfish no disponible: {exc}. Ejecuta 'docker compose up -d'.")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/status")
def status():
    return service.status()


@router.get("/demos")
def demos():
    return service.list_demos()


@router.post("/audit")
async def audit(
    archivo: UploadFile = File(...),
    sanitize: bool = Form(True),
    use_ai: bool = Form(True),
):
    content = await archivo.read(MAX_CONFIG_BYTES + 1)
    if len(content) > MAX_CONFIG_BYTES:
        raise HTTPException(413, "El archivo supera 2 MB.")
    try:
        raw = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "El archivo debe estar codificado en UTF-8.")
    name = (archivo.filename or "config.cfg").split("/")[-1].split("\\")[-1]
    session = _batfish_guard(lambda: service.run_audit(raw, name, sanitize=sanitize, use_ai=use_ai))
    return service.summary(session)


@router.post("/demo/{sample_id}")
def demo(sample_id: str, sanitize: bool = True):
    try:
        path = service.demo_path(sample_id)
    except FileNotFoundError:
        raise HTTPException(404, "Demo inexistente.")
    session = _batfish_guard(
        lambda: service.run_audit(path.read_text(encoding="utf-8"), path.name, sanitize=sanitize, prefer_cache=True)
    )
    return service.summary(session)


@router.get("/session/{session_id}")
def get_session(session_id: str):
    return service.summary(_session(session_id))


@router.get("/session/{session_id}/sanitization")
def sanitization(session_id: str):
    return service.sanitization_view(_session(session_id))


@router.get("/session/{session_id}/shadowing")
def shadowing(session_id: str):
    return {"reglas": service.shadowing(_session(session_id))}


@router.get("/session/{session_id}/exposure")
def exposure(session_id: str):
    s = _session(session_id)
    return _batfish_guard(lambda: service.exposure(s))


@router.get("/session/{session_id}/isolation")
def isolation(session_id: str):
    s = _session(session_id)
    return _batfish_guard(lambda: service.isolation(s))


@router.post("/session/{session_id}/traceroute")
def traceroute(session_id: str, req: TracerouteRequest):
    s = _session(session_id)
    return _batfish_guard(
        lambda: service.traceroute(s, req.zona_origen, req.src_ip, req.dst_ip, req.protocolo, req.puerto)
    )


@router.post("/session/{session_id}/diff")
def diff(session_id: str, req: DiffRequest):
    s = _session(session_id)
    return _batfish_guard(lambda: service.digital_twin_diff(s, req.plan))


@router.get("/session/{session_id}/pdf")
def pdf(session_id: str):
    s = _session(session_id)
    if not s.report:
        raise HTTPException(409, "No hay reporte de IA para exportar a PDF.")
    return Response(
        build_pdf(s.report, s.topology), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="auditoria_{s.base_name}.pdf"'},
    )


@router.get("/session/{session_id}/markdown")
def markdown(session_id: str):
    s = _session(session_id)
    try:
        body = service.build_markdown(s)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return PlainTextResponse(body, headers={"Content-Disposition": f'attachment; filename="auditoria_{s.base_name}.md"'})


@router.get("/session/{session_id}/cli/{kind}")
def cli(session_id: str, kind: str):
    if kind not in {"remediacion", "rollback"}:
        raise HTTPException(404, "Tipo de script inválido.")
    s = _session(session_id)
    try:
        scripts = service.build_cli(s)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return PlainTextResponse(
        scripts[kind], headers={"Content-Disposition": f'attachment; filename="{kind}_{s.base_name}.cli"'}
    )
