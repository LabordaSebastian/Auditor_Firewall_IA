"""Pruebas de la Fase 2 (RF-11): Digital Twin robusto (fix ASA nameif) y reachability simbólica."""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pybatfish.exception import BatfishException

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.sanitizer import ConfigSanitizer
from src.topology_extractor import CiscoTopologyExtractor
from src.web.app import app
from src.web.graph import build_graph, build_zones
from src.web.service import DEMO_DIR, AuditService, AuditSession, service
from tests.conftest import IOS_CONFIG


def _make_session(sid: str = "sess2", config: str = IOS_CONFIG, filename: str = "r-test.cfg") -> AuditSession:
    san, lookup = ConfigSanitizer().sanitize(config, source_filename=filename)
    topo = CiscoTopologyExtractor(san).extract_topology()
    s = AuditSession(
        id=sid, filename=filename, base_name=filename.rsplit(".", 1)[0], sanitize=True, raw_config=config,
        sanitized_config=san, lookup_map=lookup, topology=topo, math_findings=[], report=None, report_source="none",
        ai_error=None, graph=service._deep_desanitize(build_graph(topo, {}), lookup), zones=build_zones(topo),
    )
    service.sessions[sid] = s
    return s


@pytest.fixture
def client():
    service.sessions.clear()
    return TestClient(app)


# ------------------------------------------------------------------ unidades puras
def test_parse_ports_accepts_lists_and_ranges():
    assert AuditService.parse_ports("22, 80-90;443,22") == ["22", "80-90", "443"]
    assert AuditService.parse_ports("") == [] and AuditService.parse_ports(None) == []


@pytest.mark.parametrize("bad", ["abc", "0", "70000", "90-80", "22-", ",".join(str(p) for p in range(1, 13))])
def test_parse_ports_rejects_invalid(bad):
    with pytest.raises(ValueError):
        AuditService.parse_ports(bad)


def test_split_interface_handles_text_and_objects():
    assert BatfishAnalyzer._split_interface("asa-fw[outside]") == ("asa-fw", "outside")
    assert BatfishAnalyzer._split_interface(SimpleNamespace(hostname="r1", interface="Gi0/0")) == ("r1", "Gi0/0")


def test_rule_text_translates_implicit_deny():
    assert "implícito" in BatfishAnalyzer._rule_text("no-match")
    assert BatfishAnalyzer._rule_text("10 permit ip any any") == "10 permit ip any any"
    assert BatfishAnalyzer._rule_text("") is None


ASA_INDEX = [
    {"nodo": "asa-fw", "interfaz": "outside", "ip": "192.0.2.10"},
    {"nodo": "asa-fw", "interfaz": "inside", "ip": "192.168.100.1"},
]


def test_resolve_location_maps_asa_nameif_by_ip(monkeypatch):
    """Regresión del 500 en ASA: GigabitEthernet0/0 debe resolverse a 'outside' por su IP."""
    a = BatfishAnalyzer()
    monkeypatch.setattr(a, "_interface_index", lambda snap: ASA_INDEX)
    assert a.resolve_location("s", "GigabitEthernet0/0", "192.0.2.10") == ("asa-fw", "outside")
    assert a.resolve_location("s", "INSIDE") == ("asa-fw", "inside")  # coincidencia exacta sin distinguir mayúsculas
    assert a._start_location("s", "Gi0/9", "192.168.100.1")[1] == "@enter(asa-fw[inside])"
    with pytest.raises(ValueError, match="no reconoce"):
        a.resolve_location("s", "GigabitEthernet0/5", "10.9.9.9")


def _step(action, detail):
    return SimpleNamespace(action=action, detail=detail)


def test_decisive_filter_ignores_synthetic_permits_and_stops_on_deny():
    trace = SimpleNamespace(hops=[SimpleNamespace(node="asa-fw", steps=[
        _step("RECEIVED", "outside"),
        _step("PERMITTED", "ACL_OUTSIDE_IN (POST_TRANSFORMATION_INGRESS_FILTER)"),
        _step("PERMITTED", "~COMBINED_OUTGOING_ACL~dmz~ (PRE_TRANSFORMATION_EGRESS_FILTER)"),
    ])])
    hops, dec = BatfishAnalyzer._decisive_filter(trace)
    assert dec == {"filtro": "ACL_OUTSIDE_IN", "accion": "PERMITTED", "direccion": "ENTRADA"}
    assert len(hops) == 1 and len(hops[0]["pasos"]) == 3

    denied = SimpleNamespace(hops=[SimpleNamespace(node="r1", steps=[
        _step("DENIED", "ACL_WAN_IN (INGRESS_FILTER)"), _step("PERMITTED", "OTRA (EGRESS_FILTER)"),
    ])])
    assert BatfishAnalyzer._decisive_filter(denied)[1]["accion"] == "DENIED"


# ------------------------------------------------------------------ API con Batfish simulado
class FakeAnalyzer:
    def __init__(self):
        self.calls = []

    def symbolic_reachability(self, cfg, fname, iface, ip, dests, src_ips=None, protocol=None, port_specs=None):
        self.calls.append(dict(iface=iface, ip=ip, dests=dests, src_ips=src_ips, protocol=protocol, ports=port_specs))
        return {"origen": "x", "total_consultas": len(dests), "alcanzables": 1, "resultados": [
            {"destino": d["etiqueta"], "destino_ips": d["ips"], "alcanzable": True,
             "flujo": {"texto": f"-> {d['ips']}"}, "disposicion": "ACCEPTED", "filtro_decisivo": None} for d in dests]}

    def test_filter(self, cfg, fname, acl, src, dst, proto, port):
        self.calls.append(dict(acl=acl, src=src, dst=dst))
        return {"acl": acl, "accion": "PERMIT", "permitido": True, "regla": f"30 permit tcp any host {dst} eq 23", "flujo": None}

    def network_model(self, cfg, fname):
        self.calls.append("model")
        return {"rutas": [], "enlaces_l3": [], "interfaces": [], "total_rutas": 0, "total_enlaces": 0}


@pytest.fixture
def fake(monkeypatch):
    f = FakeAnalyzer()
    monkeypatch.setattr(service, "_analyzer", lambda: f)
    return f


def test_reachability_all_zones_from_wan(client, fake):
    s = _make_session()
    r = client.post("/api/session/sess2/reachability", json={"zona_origen": "WAN", "destino": "*", "protocolo": "TCP", "puertos": "22,23"})
    assert r.status_code == 200
    call = fake.calls[0]
    assert {d["etiqueta"] for d in call["dests"]} == {z["nombre"] for z in s.zones} - {"WAN"}
    assert call["src_ips"] is None and call["ports"] == ["22", "23"]           # WAN: cualquier origen
    assert call["ip"] == next(z["ip"] for z in s.zones if z["nombre"] == "WAN")  # IP para resolver nameif


def test_reachability_custom_destination_is_resanitized(client, fake):
    s = _make_session()
    synth, real = next(iter(s.lookup_map["ip_mappings"].items()))
    r = client.post("/api/session/sess2/reachability", json={"zona_origen": "LAN", "destino": real, "protocolo": "ANY"})
    assert r.status_code == 200
    call = fake.calls[0]
    assert call["dests"][0]["ips"] == f"{synth}/32"                 # hacia Batfish viaja la IP sintética
    assert call["protocol"] is None and call["ports"] == []
    assert call["src_ips"] == next(z["subred"] for z in s.zones if z["nombre"] == "LAN")
    assert real in r.json()["resultados"][0]["destino_ips"]          # al usuario vuelve la IP real


@pytest.mark.parametrize("payload,code", [
    ({"zona_origen": "WAN", "destino": "no-es-ip", "protocolo": "TCP"}, 400),
    ({"zona_origen": "NOPE", "destino": "*", "protocolo": "TCP"}, 400),
    ({"zona_origen": "WAN", "destino": "*", "protocolo": "TCP", "puertos": "99999"}, 400),
    ({"zona_origen": "WAN", "destino": "*", "protocolo": "GRE"}, 422),
])
def test_reachability_validation(client, fake, payload, code):
    _make_session()
    assert client.post("/api/session/sess2/reachability", json=payload).status_code == code
    assert not fake.calls


def test_testfilter_validates_acl_and_desanitizes(client, fake):
    s = _make_session()
    synth, real = next(iter(s.lookup_map["ip_mappings"].items()))
    bad = client.post("/api/session/sess2/testfilter", json={"acl": "NO_EXISTE", "src_ip": "8.8.8.8", "dst_ip": real})
    assert bad.status_code == 400
    ok = client.post("/api/session/sess2/testfilter", json={"acl": "ACL_WAN_IN", "src_ip": "8.8.8.8", "dst_ip": real, "puerto": 23})
    assert ok.status_code == 200
    assert fake.calls[-1]["dst"] == synth and real in ok.json()["regla"]


def test_network_model_is_cached(client, fake):
    _make_session()
    assert client.get("/api/session/sess2/model").status_code == 200
    assert client.get("/api/session/sess2/model").status_code == 200
    assert fake.calls.count("model") == 1


def test_summary_exposes_acl_names(client):
    _make_session()
    assert "ACL_WAN_IN" in client.get("/api/session/sess2").json()["acls"]


def test_batfish_query_errors_become_502_not_500(client, monkeypatch):
    _make_session()

    class Broken:
        def simulate_packet(self, *a, **k):
            raise BatfishException("Work terminated abnormally\nCaused by: java.lang.IllegalArgumentException: "
                                   "Found no active locations matching @enter(fw[Gi0/0])")
    monkeypatch.setattr(service, "_analyzer", lambda: Broken())
    r = TestClient(app, raise_server_exceptions=False).post(
        "/api/session/sess2/traceroute", json={"zona_origen": "WAN", "src_ip": "8.8.8.8", "dst_ip": "172.16.10.5", "protocolo": "TCP", "puerto": 22})
    assert r.status_code == 502 and "Found no active locations" in r.json()["detail"]


# ------------------------------------------------------------------ integración real con Batfish (ASA)
@pytest.fixture
def batfish():
    a = BatfishAnalyzer()
    try:
        a.connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo en este momento.")
    return a


def test_asa_digital_twin_end_to_end(client, batfish):
    """Regresión: en la demo ASA el traceroute, la matriz y la reachability deben resolver las interfaces nameif."""
    raw = (DEMO_DIR / "fw-borde-asa.cfg").read_text(encoding="utf-8")
    s = _make_session("asa1", raw, "fw-borde-asa.cfg")
    dmz = next(z for z in s.zones if z["zona"] == "DMZ")
    tr = client.post("/api/session/asa1/traceroute", json={"zona_origen": "WAN", "src_ip": "8.8.8.8", "dst_ip": "172.16.50.10", "protocolo": "TCP", "puerto": 3306})
    assert tr.status_code == 200, tr.text
    assert tr.json()["permitido"] is True and tr.json()["filtro_decisivo"]["filtro"] == "ACL_OUTSIDE_IN"

    iso = client.get("/api/session/asa1/isolation").json()["celdas"]
    assert all(c["estado"] != "DESCONOCIDO" for c in iso)
    assert next(c for c in iso if c["origen"] == "WAN" and c["destino"] == dmz["nombre"])["estado"] == "FUGA"

    rc = client.post("/api/session/asa1/reachability", json={"zona_origen": "WAN", "destino": "*", "protocolo": "TCP", "puertos": "3306"}).json()
    by_dst = {r["destino"]: r["alcanzable"] for r in rc["resultados"]}
    assert by_dst[dmz["nombre"]] is True and by_dst["LAN"] is False

    model = client.get("/api/session/asa1/model").json()
    assert {i["interfaz"] for i in model["interfaces"]} == {"outside", "inside", "dmz"}
    assert model["total_rutas"] > 0 and model["total_enlaces"] == 0

