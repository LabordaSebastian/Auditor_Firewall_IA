"""Pruebas de la vista previa pre-flight (RF-10): guías demo, endpoints y control de sintaxis."""
import pytest
from fastapi.testclient import TestClient

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.web.app import app
from src.web.demo_guides import DEMO_GUIDES, get_demo_guide, guide_lines
from src.web.service import DEMO_DIR, service
from tests.conftest import IOS_CONFIG


@pytest.fixture
def client():
    service.sessions.clear()
    return TestClient(app)


class FakeAnalyzer:
    def __init__(self, problemas=None):
        self.problemas = problemas or []

    def check_syntax(self, cfg, fname):
        return self.problemas


@pytest.fixture
def no_audit(monkeypatch):
    """El preview jamás debe disparar la auditoría completa (Batfish formal + Gemini)."""
    def boom(*a, **k):
        raise AssertionError("El preview no debe ejecutar run_audit")
    monkeypatch.setattr(service, "run_audit", boom)


# ------------------------------------------------------------------ guías demo
@pytest.mark.parametrize("sample_id", sorted(DEMO_GUIDES))
def test_guide_lines_point_inside_demo_file(sample_id):
    """Cada línea citada en la guía debe existir en el .cfg real (evita deriva guía/archivo)."""
    total = len(service.demo_path(sample_id).read_text(encoding="utf-8").splitlines())
    for vuln in get_demo_guide(sample_id)["vulnerabilidades"]:
        assert vuln["lineas"] and all(1 <= n <= total for n in vuln["lineas"]), vuln["titulo"]


def test_guide_anchor_lines_match_expected_content():
    ios = service.demo_path("ios").read_text(encoding="utf-8").splitlines()
    assert "eq 23" in ios[46 - 1] and "deny tcp any host 172.16.10.50" in ios[44 - 1]
    asa = service.demo_path("asa").read_text(encoding="utf-8").splitlines()
    assert "3306" in asa[40 - 1] and "eq 22" in asa[42 - 1]


def test_guide_lines_keeps_highest_severity():
    guide = {"vulnerabilidades": [{"severidad": "BAJA", "lineas": [5, 6]}, {"severidad": "CRITICA", "lineas": [6]}]}
    assert guide_lines(guide) == {5: "BAJA", 6: "CRITICA"}
    assert guide_lines(None) == {}
    assert get_demo_guide("inexistente") is None


# ------------------------------------------------------------------ endpoints
def test_preview_upload_returns_radiography_without_auditing(client, monkeypatch, no_audit):
    monkeypatch.setattr(service, "_analyzer", lambda: FakeAnalyzer())
    r = client.post("/api/preview", files={"archivo": ("r-test.cfg", IOS_CONFIG.encode())})
    assert r.status_code == 200
    d = r.json()
    assert d["hostname"] == "R-TEST" and d["dialecto"].startswith("Cisco IOS")
    assert len(d["interfaces"]) == 3 and "ACL_WAN_IN" in d["acls_activas"]
    assert d["guia"] is None and d["demo_id"] is None
    assert d["sintaxis"] == {"disponible": True, "problemas": [], "error": None}
    assert d["config_original"] == IOS_CONFIG
    assert d["sanitizacion"]["ips"] >= 1 and d["sanitizacion"]["secretos"] == 1


def test_preview_sanitized_view_never_contains_secret_or_public_ip(client, monkeypatch, no_audit):
    monkeypatch.setattr(service, "_analyzer", lambda: FakeAnalyzer())
    d = client.post("/api/preview", files={"archivo": ("r-test.cfg", IOS_CONFIG.encode())}).json()
    assert "supersecretvalue" not in d["config_sanitizada"]
    assert "200.45.112.18" not in d["config_sanitizada"]
    assert "supersecretvalue" in d["config_original"]  # el original es el archivo del propio usuario


def test_preview_demo_includes_guide_and_highlights(client, monkeypatch, no_audit):
    monkeypatch.setattr(service, "_analyzer", lambda: FakeAnalyzer())
    d = client.get("/api/demo/ios/preview").json()
    assert d["demo_id"] == "ios" and d["guia"]["vulnerabilidades"]
    assert d["lineas_resaltadas"]["46"] == "CRITICA"
    assert d["total_lineas"] == len((DEMO_DIR / "fw-borde-ios.cfg").read_text(encoding="utf-8").splitlines())
    assert client.get("/api/demo/noexiste/preview").status_code == 404


def test_preview_reports_syntax_issues(client, monkeypatch, no_audit):
    issue = {"tipo": "Parse warning", "detalle": "This syntax is unrecognized", "linea_texto": "foo bar", "lineas": [4]}
    monkeypatch.setattr(service, "_analyzer", lambda: FakeAnalyzer([issue]))
    d = client.post("/api/preview", files={"archivo": ("x.cfg", IOS_CONFIG.encode())}).json()
    assert d["sintaxis"]["problemas"] == [issue]


def test_preview_degrades_gracefully_when_batfish_is_down(client, monkeypatch, no_audit):
    def boom():
        raise BatfishUnavailableError("sin conexión")
    monkeypatch.setattr(service, "_analyzer", boom)
    r = client.post("/api/preview", files={"archivo": ("x.cfg", IOS_CONFIG.encode())})
    assert r.status_code == 200
    s = r.json()["sintaxis"]
    assert s["disponible"] is False and "sin conexión" in s["error"]


def test_preview_rejects_bad_files(client):
    big = client.post("/api/preview", files={"archivo": ("x.cfg", b"a" * (2 * 1024 * 1024 + 10))})
    assert big.status_code == 413
    binary = client.post("/api/preview", files={"archivo": ("x.cfg", b"\xff\xfe\x00\x80")})
    assert binary.status_code == 400


def test_index_has_preview_container(client):
    html = client.get("/").text
    assert 'id="previewView"' in html and 'id="pickerView"' in html


# ------------------------------------------------------------------ Batfish real (initIssues)
def test_check_syntax_detects_unrecognized_line_with_batfish():
    analyzer = BatfishAnalyzer()
    try:
        analyzer.connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo en este momento.")
    cfg = "hostname X\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n comando-inventado foo bar\n"
    issues = analyzer.check_syntax(cfg, "bad.cfg", network_name="test_net")
    assert any(i["lineas"] == [4] and "comando-inventado" in i["linea_texto"] for i in issues)
    clean = analyzer.check_syntax("hostname X\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n", "ok.cfg", network_name="test_net")
    assert clean == []
