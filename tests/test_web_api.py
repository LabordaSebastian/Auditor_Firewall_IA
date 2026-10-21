import pytest
from fastapi.testclient import TestClient

from src.batfish_analyzer import BatfishUnavailableError
from src.sanitizer import ConfigSanitizer
from src.topology_extractor import CiscoTopologyExtractor
from src.web.app import app
from src.web.graph import build_graph, build_zones
from src.web.service import AuditSession, service
from tests.conftest import IOS_CONFIG


def _make_session(report, sid="sess1") -> AuditSession:
    san, lookup = ConfigSanitizer().sanitize(IOS_CONFIG)
    topo = CiscoTopologyExtractor(san).extract_topology()
    s = AuditSession(
        id=sid, filename="r-test.cfg", base_name="r-test", sanitize=True, raw_config=IOS_CONFIG, sanitized_config=san,
        lookup_map=lookup, topology=topo, math_findings=[], report=report, report_source="gemini" if report else "none",
        ai_error=None, graph=service._deep_desanitize(build_graph(topo, {}), lookup), zones=build_zones(topo),
    )
    service.sessions[sid] = s
    return s


@pytest.fixture
def client():
    service.sessions.clear()
    return TestClient(app)


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Cisco AI Firewall Auditor" in r.text
    assert client.get("/static/css/styles.css").status_code == 200
    assert client.get("/static/js/app.js").status_code == 200


def test_unknown_session_404(client):
    assert client.get("/api/session/nope/sanitization").status_code == 404


def test_status_reports_batfish_down(client, monkeypatch):
    def boom():
        raise BatfishUnavailableError("sin conexión")
    monkeypatch.setattr(service, "_analyzer", boom)
    data = client.get("/api/status").json()
    assert data["batfish"]["ok"] is False and "gemini" in data


def test_sanitization_endpoint_never_leaks_secret(client, sample_report):
    _make_session(sample_report)
    body = client.get("/api/session/sess1/sanitization").json()
    assert body["activa"] is True and body["total_secretos"] == 1
    assert "supersecretvalue" not in str(body)


def test_exports_desanitized(client, sample_report):
    _make_session(sample_report)
    pdf = client.get("/api/session/sess1/pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    md = client.get("/api/session/sess1/markdown")
    assert md.status_code == 200 and "R-TEST" in md.text
    rem = client.get("/api/session/sess1/cli/remediacion")
    assert rem.status_code == 200 and "configure terminal" in rem.text
    assert client.get("/api/session/sess1/cli/otro").status_code == 404


def test_exports_conflict_without_ai_report(client):
    _make_session(None)
    assert client.get("/api/session/sess1/pdf").status_code == 409
    assert client.get("/api/session/sess1/cli/rollback").status_code == 409
    assert client.post("/api/session/sess1/diff", json={"plan": "A"}).status_code == 400


def test_traceroute_validation_and_desanitization(client, sample_report, monkeypatch):
    s = _make_session(sample_report)
    bad = client.post("/api/session/sess1/traceroute", json={"zona_origen": "WAN", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocolo": "GRE"})
    assert bad.status_code == 422

    synth = next(iter(s.lookup_map["ip_mappings"]))
    real = s.lookup_map["ip_mappings"][synth]
    captured = {}

    class FakeAnalyzer:
        def simulate_packet(self, cfg, fname, iface, src, dst, proto, port):
            captured.update(dst=dst, iface=iface)
            return {"permitido": False, "disposicion": "DENIED_IN", "hops": [], "regla": f"deny host {synth}", "filtro_decisivo": None}

    monkeypatch.setattr(service, "_analyzer", lambda: FakeAnalyzer())
    ok = client.post("/api/session/sess1/traceroute", json={"zona_origen": "WAN", "src_ip": "8.8.8.8", "dst_ip": real, "protocolo": "TCP", "puerto": 23})
    assert ok.status_code == 200
    assert captured["dst"] == synth                    # entrada re-sanitizada hacia Batfish
    assert real in ok.json()["regla"]                  # salida de-sanitizada hacia el usuario
    unknown = client.post("/api/session/sess1/traceroute", json={"zona_origen": "NOPE", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocolo": "TCP", "puerto": 80})
    assert unknown.status_code == 400


def test_audit_upload_rejects_bad_files(client):
    big = client.post("/api/audit", files={"archivo": ("x.cfg", b"a" * (2 * 1024 * 1024 + 10))})
    assert big.status_code == 413
    binary = client.post("/api/audit", files={"archivo": ("x.cfg", b"\xff\xfe\x00\x80")})
    assert binary.status_code == 400


def test_audit_batfish_down_returns_503(client, monkeypatch):
    def boom(*a, **k):
        raise BatfishUnavailableError("down")
    monkeypatch.setattr(service, "run_audit", boom)
    r = client.post("/api/audit", files={"archivo": ("x.cfg", IOS_CONFIG.encode())})
    assert r.status_code == 503 and "docker compose" in r.json()["detail"]
