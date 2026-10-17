import pytest
from pathlib import Path
from src.local_math_fallback import LocalMathFallbackAnalyzer


def test_local_math_fallback_detects_shadowing():
    cfg_path = Path("snapshots/lab_cisco_vuln/configs/fw-borde-ios.cfg")
    content = cfg_path.read_text(encoding="utf-8")

    findings = LocalMathFallbackAnalyzer.analyze_acls(content)

    assert len(findings) > 0
    # Debe detectar al menos una regla redundante o shadowed
    types = [f.tipo for f in findings]
    assert "REDUNDANT" in types or "CRITICAL_SHADOWING" in types

    # Verificar que encuentra la línea duplicada
    redundants = [f for f in findings if f.tipo == "REDUNDANT"]
    assert len(redundants) >= 1
