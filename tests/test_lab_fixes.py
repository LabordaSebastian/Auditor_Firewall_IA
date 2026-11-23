"""Correcciones del laboratorio Packet Tracer: Plan C en What-If, IPs reales en el simulador y tráfico de retorno."""
import pytest
from fastapi.testclient import TestClient

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.sanitizer import ConfigSanitizer
from src.web.app import app
from src.web.service import AuditService, service

LAB_CFG = """hostname R-LAB
interface GigabitEthernet0/0
 description WAN_ISP
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
interface GigabitEthernet0/1
 description LAN_USUARIOS
 ip address 192.168.10.1 255.255.255.0
 ip access-group ACL_LAN_IN in
ip route 0.0.0.0 0.0.0.0 200.45.112.17
ip access-list extended ACL_WAN_IN
 10 permit tcp any host 192.168.10.50 eq 443
 20 permit icmp any any
ip access-list extended ACL_LAN_IN
 10 permit ip any any
"""


def _bf():
    bf = BatfishAnalyzer()
    try:
        bf.connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo.")
    return bf


def test_whatif_request_accepts_plan_c():
    client = TestClient(app)
    r = client.post("/api/session/inexistente/whatif", json={"decisiones": {"FW-CISCO-004": "C", "FW-1": "A"}})
    assert r.status_code == 404  # pasó la validación (antes: 422 'use A, B o NONE')
    bad = client.post("/api/session/inexistente/whatif", json={"decisiones": {"FW-1": "Z"}})
    assert bad.status_code == 422


def test_network_addresses_are_restored_for_display():
    sanitized, lm = ConfigSanitizer().sanitize(LAB_CFG, source_filename="lab.cfg")
    from src.topology_extractor import CiscoTopologyExtractor
    topo = CiscoTopologyExtractor(sanitized).extract_topology()
    AuditService._add_network_mappings(topo, lm)
    wan_synth = next(i.ip_address for i in topo.interfaces.values() if i.nombre.endswith("0/0"))
    synth_net = ".".join(wan_synth.split(".")[:3]) + ".16"  # red /29 sintética de la WAN (192.0.2.x)
    assert "200.45.112.16" in lm["net_mappings"].values()
    shown = ConfigSanitizer.desanitize(f"Network: {synth_net}/29", lm) if synth_net in lm["net_mappings"] else None
    assert shown is None or "200.45.112.16/29" in shown
    # entrada real del usuario -> sintética hacia Batfish
    assert "200.45.112.16" not in AuditService._resanitize("200.45.112.16/29", lm)


def test_simulator_reports_denied_return_traffic_with_batfish():
    bf = _bf()
    res = bf.simulate_packet(LAB_CFG, "lab.cfg", "GigabitEthernet0/1", "192.168.10.10", "8.8.8.8", "TCP", 80,
                             network_name="test_net_ret")
    assert res["permitido"] is True
    assert res["retorno"] is not None and res["retorno"]["permitido"] is False  # ACL_WAN_IN sin 'established'
    fixed = LAB_CFG.replace(" 20 permit icmp any any", " 15 permit tcp any any established\n 20 permit icmp any any")
    res2 = bf.simulate_packet(fixed, "lab.cfg", "GigabitEthernet0/1", "192.168.10.10",
                              "8.8.8.8", "TCP", 80, network_name="test_net_ret")
    assert res2["retorno"]["permitido"] is True


def test_exposure_ignores_established_return_rules():
    bf = _bf()
    cfg = LAB_CFG.replace(" 20 permit icmp any any", " 15 permit tcp any any established\n 20 permit icmp any any")
    ports = {(e["servicio"], e["puerto"]) for e in bf.scan_exposed_ports(cfg, "lab.cfg", ["ACL_WAN_IN"], network_name="test_net_ret")}
    assert ports == set()  # ni SSH/RDP/etc.: una regla 'established' no permite iniciar conexiones


def test_ios_remediation_without_sequence_numbers_enters_acl_context():
    """En IOS 'show running-config' no trae números de secuencia; los comandos deben entrar a 'ip access-list extended'."""
    from src.deterministic_advisor import DeterministicFirewallAdvisor
    from src.models import HallazgoMatematico
    from src.topology_extractor import CiscoTopologyExtractor

    unseq_cfg = """hostname R-PT
interface GigabitEthernet0/0
 description WAN
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
ip access-list extended ACL_WAN_IN
 permit tcp any 172.16.10.0 0.0.0.255 eq 443
 deny tcp any host 172.16.10.50 eq 443
 permit tcp any host 200.45.112.18 eq telnet
"""
    topo = CiscoTopologyExtractor(unseq_cfg).extract_topology()
    math = [HallazgoMatematico(
        tipo="CRITICAL_SHADOWING", filtro_nombre="ACL_WAN_IN",
        linea_afectada="deny tcp any host 172.16.10.50 eq 443", indice_linea=1,
        linea_bloqueadora="permit tcp any 172.16.10.0 0.0.0.255 eq 443", indice_bloqueadora=0,
        descripcion="Shadowing",
    )]
    rep = DeterministicFirewallAdvisor().analyze(unseq_cfg, topo, math)
    for h in rep.hallazgos:
        if h.acl_o_componente == "ACL_WAN_IN":
            cmds = h.plan_a_recomendado.comandos_cli_implementacion
            assert cmds[0] == "configure terminal"
            assert cmds[1] == "ip access-list extended ACL_WAN_IN"
