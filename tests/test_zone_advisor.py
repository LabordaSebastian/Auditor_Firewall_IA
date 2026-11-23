"""Pruebas del Criterio Arquitectónico de Zonas, Consultor de Excepciones (Plan C) y Motor Determinístico (RF-16)."""
import pytest
from fastapi.testclient import TestClient

from src.deterministic_advisor import DeterministicFirewallAdvisor, enrich_report_zone_context
from src.models import HallazgoMatematico
from src.sanitizer import ConfigSanitizer
from src.topology_extractor import CiscoTopologyExtractor
from src.web.app import app
from src.web.service import service
from tests.conftest import IOS_CONFIG
from tests.test_reachability import _make_session


@pytest.fixture
def client():
    service.sessions.clear()
    return TestClient(app)


def test_deterministic_advisor_generates_complete_report_without_gemini():
    """Cuando Gemini está apagado o sin API key, el motor determinístico genera el reporte completo."""
    cfg = IOS_CONFIG + "\nip access-list extended ACL_LAN_IN\n 20 permit ip any any\n"
    san, _ = ConfigSanitizer().sanitize(cfg)
    topo = CiscoTopologyExtractor(san).extract_topology()
    math = [
        HallazgoMatematico(
            tipo="CRITICAL_SHADOWING", filtro_nombre="ACL_WAN_IN",
            linea_afectada="20 deny tcp any host 172.16.10.50 eq 443", indice_linea=1,
            linea_bloqueadora="10 permit tcp any 172.16.10.0 0.0.0.255 eq 443", indice_bloqueadora=0,
            descripcion="Verificado por Batfish: Regla critical_shadowing en ACL_WAN_IN.",
        )
    ]
    report = DeterministicFirewallAdvisor().analyze(san, topo, math)
    assert report.resumen.total_hallazgos >= 3
    assert 0 <= report.resumen.score_seguridad_actual < report.resumen.score_seguridad_proyectado <= 100
    for h in report.hallazgos:
        assert h.sentido_flujo_zonas and h.sentido_flujo_zonas != "N/D"
        assert h.criterio_arquitectonico_ia
        assert h.plan_a_recomendado.comandos_cli_implementacion


def test_zone_context_distinguishes_outbound_lan_any_from_inbound_wan(sample_report):
    """El enriquecedor contextual diferencia salida LAN->WAN (destino any válido) de entrada WAN->DMZ."""
    cfg = """hostname R-ZONAS
interface GigabitEthernet0/0
 description WAN-INTERNET
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
interface GigabitEthernet0/1
 description LAN-USUARIOS
 ip address 192.168.1.1 255.255.255.0
 ip access-group ACL_LAN_IN in
"""
    topo = CiscoTopologyExtractor(cfg).extract_topology()
    rep = sample_report.model_copy(deep=True)
    h_wan = rep.hallazgos[0]
    h_lan = h_wan.model_copy(deep=True)
    h_lan.id_hallazgo = "FW-LAN-01"
    h_lan.acl_o_componente = "ACL_LAN_IN"
    h_lan.categoria_problema = "Permisividad Excesiva"
    h_lan.linea_o_regla_afectada = "20 permit ip any any"
    rep.hallazgos = [h_wan, h_lan]

    enrich_report_zone_context(rep, topo)
    assert "Entrada Perimetral" in h_wan.sentido_flujo_zonas
    assert h_wan.veredicto_flexibilidad_any == "RIESGO_INJUSTIFICADO"
    assert "Salida desde Zona Segura" in h_lan.sentido_flujo_zonas
    assert h_lan.veredicto_flexibilidad_any == "EQUILIBRIO_PRAGMATICO"
    assert "DESTINO" in h_lan.criterio_arquitectonico_ia and "192.168.1.0/24" in h_lan.criterio_arquitectonico_ia


def test_consult_exception_endpoint_generates_plan_c_and_desanitizes(client, sample_report, monkeypatch):
    """El consultor de excepciones evalúa la justificación del usuario y devuelve un Plan C con controles compensatorios."""
    s = _make_session("exc1")
    h_lan = sample_report.hallazgos[0].model_copy(deep=True)
    h_lan.id_hallazgo = "FW-LAN-01"
    h_lan.acl_o_componente = "ACL_LAN_IN"
    h_lan.linea_o_regla_afectada = "20 permit ip any any"
    rep = sample_report.model_copy(deep=True)
    rep.hallazgos = [sample_report.hallazgos[0], h_lan]
    s.report, s.report_source = rep, "deterministico"

    # Forzar motor determinístico (sin llamada de red a Gemini)
    monkeypatch.setattr("src.gemini_advisor.GeminiFirewallAdvisor.consult_exception",
                        lambda self, f, t, j: DeterministicFirewallAdvisor().consult_exception(f, t, j))

    r = client.post("/api/session/exc1/advisor/exception", json={
        "id_hallazgo": "FW-LAN-01",
        "justificacion": "Es salida de zona segura LAN a Internet: necesitamos libertad de destino any para navegar.",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["veredicto_arquitecto"] == "EXCEPCION_VALIDA"
    assert len(d["controles_compensatorios"]) >= 2
    assert any("any eq 443" in c for c in d["plan_c_adaptado"]["comandos_cli_implementacion"])
    assert any("eq 445" in c for c in d["plan_c_adaptado"]["comandos_cli_implementacion"])

    # Validación de errores
    assert client.post("/api/session/exc1/advisor/exception", json={"id_hallazgo": "NOPE", "justificacion": "salida internet"}).status_code == 400
    assert client.post("/api/session/exc1/advisor/exception", json={"id_hallazgo": "FW-001", "justificacion": "a"}).status_code == 422


def test_gemini_fallback_rotates_on_503_and_formats_friendly_error(sample_report, monkeypatch):
    """Ante 503 UNAVAILABLE en el modelo primario, rota a modelos alternativos; si todos fallan, el mensaje es claro."""
    from types import SimpleNamespace
    from src.gemini_advisor import GeminiFirewallAdvisor

    calls = []

    class FakeModels:
        def generate_content(self, model, contents, config):
            calls.append(model)
            if len(calls) == 1:
                raise RuntimeError("503 UNAVAILABLE. This model is currently experiencing high demand.")
            return SimpleNamespace(text=sample_report.model_dump_json())

    monkeypatch.setattr("src.gemini_advisor.time.sleep", lambda _s: None)
    adv = GeminiFirewallAdvisor(api_key="fake-key", model_name="gemini-3.5-flash-lite")
    adv.client = SimpleNamespace(models=FakeModels())
    topo = CiscoTopologyExtractor(IOS_CONFIG).extract_topology()
    rep = adv.analyze(IOS_CONFIG, topo, [])
    assert len(calls) == 2 and calls[0] == "gemini-3.5-flash-lite" and calls[1] != calls[0]
    assert rep.resumen.hostname_detectado == sample_report.resumen.hostname_detectado

    # Si todos los modelos devuelven 503, el servicio degrada al motor determinístico con mensaje amigable
    monkeypatch.setattr(GeminiFirewallAdvisor, "analyze",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("503 UNAVAILABLE")))
    monkeypatch.setattr("src.web.service.GEMINI_API_KEY", "fake-key")
    _, source, err = service._build_report(IOS_CONFIG, topo, [], {"ip_mappings": {}, "secret_mappings": {}},
                                          "no_cache_503_test", use_ai=True, prefer_cache=False)
    assert source == "deterministico"
    assert "HTTP 503" in err and "RuntimeError" not in err
