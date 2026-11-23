"""Validación end-to-end del laboratorio Packet Tracer (RF-15): reutiliza el script reproducible de la carpeta
`validacion_laboratorio_packet_tracer/` para que forme parte de la suite de pruebas."""
import importlib.util
from pathlib import Path

import pytest

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError

SCRIPT = Path(__file__).resolve().parents[1] / "validacion_laboratorio_packet_tracer" / "ejecutar_validacion.py"


def test_packet_tracer_lab_validation_passes_end_to_end():
    try:
        BatfishAnalyzer().connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo.")
    spec = importlib.util.spec_from_file_location("ejecutar_validacion", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.run_validation()
    failed = [f"{c.id}: esperado {c.esperado} · obtenido {c.obtenido}" for c in result["checks"] if not c.ok]
    assert not failed, "\n".join(failed)
    assert result["score_antes"] < 40 and result["score_despues"] >= 90
