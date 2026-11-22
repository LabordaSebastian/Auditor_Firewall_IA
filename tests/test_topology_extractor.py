from pathlib import Path
from fastapi.testclient import TestClient

from src.topology_extractor import CiscoTopologyExtractor
from src.web.app import app
from src.web.service import service
from tests.test_reachability import _make_session


def test_topology_extractor_ios():
    cfg_path = Path("snapshots/lab_cisco_vuln/configs/fw-borde-ios.cfg")
    assert cfg_path.exists()
    content = cfg_path.read_text(encoding="utf-8")

    extractor = CiscoTopologyExtractor(content)
    topo = extractor.extract_topology()

    assert topo.hostname == "R-BORDE-CORP"
    assert topo.dialecto == "Cisco IOS / IOS-XE"
    assert "GigabitEthernet0/0" in topo.interfaces
    assert topo.interfaces["GigabitEthernet0/0"].acl_in == "ACL_WAN_IN"
    assert "ACL_WAN_IN" in topo.acls_activas
    assert "ACL_LAN_IN" in topo.acls_activas
    assert "ACL_LEGACY_MIGRACION_2022" in topo.acls_huerfanas
    assert topo.vty_transport_input is not None
    # MEJ-02: la regla 50 en ACL_WAN_IN tiene (0 matches) y remark del ticket INC-2023-8821
    assert len(topo.reglas_zombi) == 1
    z = topo.reglas_zombi[0]
    assert z.acl_nombre == "ACL_WAN_IN" and z.secuencia == "50" and z.hit_count == 0
    assert "INC-2023-8821" in (z.comentario or "") and "NULO" in z.riesgo_depuracion


def test_topology_extractor_asa():
    cfg_path = Path("snapshots/lab_cisco_vuln/configs/fw-borde-asa.cfg")
    assert cfg_path.exists()
    content = cfg_path.read_text(encoding="utf-8")

    extractor = CiscoTopologyExtractor(content)
    topo = extractor.extract_topology()

    assert topo.hostname == "ASA-PERIMETRAL-CORP"
    assert topo.dialecto == "Cisco ASA"
    assert "ACL_TEST_ORPHAN" in topo.acls_huerfanas
    assert len(topo.reglas_zombi) == 1
    z = topo.reglas_zombi[0]
    assert z.acl_nombre == "ACL_OUTSIDE_IN" and z.hit_count == 0 and "8080" in z.texto_crudo
    assert "(hitcnt=0)" not in z.texto_crudo


def test_extract_zombie_rules_and_strip_hitcnt_formats():
    sample = """hostname ASA-TEST
access-list ACL_OUT line 1 remark Regla legacy migracion 2022
access-list ACL_OUT line 2 extended permit tcp any host 172.16.1.10 eq 8443 (hitcnt=0) 0x8a1bc230
access-list ACL_OUT line 3 extended permit tcp any host 172.16.1.10 eq 443 (hitcnt=452) 0x9911aa22
ip access-list extended ACL_IOS
 10 permit tcp any any eq 80 (120 matches)
 20 deny tcp any any eq 23 (0 matches)
"""
    ext = CiscoTopologyExtractor(sample)
    zombies, total = ext.extract_zombie_rules("Cisco ASA")
    assert total == 4 and len(zombies) == 2
    assert zombies[0].acl_nombre == "ACL_OUT" and zombies[0].secuencia == "2"
    assert "migracion 2022" in (zombies[0].comentario or "") and "NULO" in zombies[0].riesgo_depuracion
    assert zombies[1].acl_nombre == "ACL_IOS" and zombies[1].secuencia == "20" and "BAJO" in zombies[1].riesgo_depuracion

    cleaned = CiscoTopologyExtractor.strip_hitcnt(sample)
    assert "hitcnt" not in cleaned and "matches" not in cleaned and "0x8a1bc230" not in cleaned
    assert "access-list ACL_OUT extended permit tcp any host 172.16.1.10 eq 8443" in cleaned


def test_zombies_api_endpoint_desanitizes():
    service.sessions.clear()
    cfg = """hostname R-ZOMBI
interface GigabitEthernet0/0
 description WAN
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
ip access-list extended ACL_WAN_IN
 10 remark Ticket vencido 2023
 20 permit tcp any host 200.45.112.18 eq 3389 (0 matches)
"""
    _make_session("z1", cfg, "r-zombi.cfg")
    c = TestClient(app)
    r = c.get("/api/session/z1/zombies")
    assert r.status_code == 200
    data = r.json()
    assert data["total_con_hitcnt"] == 1 and len(data["reglas"]) == 1
    assert "200.45.112.18" in data["reglas"][0]["texto_crudo"]


def test_normalize_cli_paste_supports_show_access_lists_and_bare_aces():
    """Al copiar y pegar directo de la CLI (show access-lists o ACEs sueltas), se normaliza para Batfish y el extractor."""
    pasted_ios = """R-LAB-PT#show access-lists
Extended IP access list ACL_BORDE
    10 permit tcp any 172.16.10.0 0.0.0.255 eq 443 (25 matches)
    20 deny tcp any host 172.16.10.50 eq 443 (0 matches)
Standard IP access list ACL_MGMT
    10 permit 192.168.1.0, wildcard bits 0.0.0.255
"""
    topo = CiscoTopologyExtractor(pasted_ios).extract_topology()
    assert topo.hostname == "R-LAB-PT"
    assert set(topo.acls_activas) == {"ACL_BORDE", "ACL_MGMT"}
    assert topo.acls_huerfanas == []
    assert len(topo.reglas_zombi) == 1 and topo.reglas_zombi[0].secuencia == "20"

    # ACEs sueltas sin cabecera 'ip access-list'
    bare = "10 permit tcp any any eq 80\n20 deny ip any any log\n"
    topo_bare = CiscoTopologyExtractor(bare).extract_topology()
    assert topo_bare.hostname == "FIREWALL-CLI-PASTE"
    assert "ACL_CLI_PEGADA" in topo_bare.acls_activas


def test_strip_hitcnt_adapts_asa_typed_service_object_group_for_batfish():
    """Adapta object-group service <GRP> tcp + port-object eq ... a service-object 1:1 para Batfish."""
    asa_snippet = (
        "object-group service GRP_WEB_PORTS tcp\n"
        " port-object eq www\n"
        " port-object eq https\n"
        "!\n"
        "access-list ACL_OUTSIDE_IN extended permit tcp any object OBJ_SRV_WEB object-group GRP_WEB_PORTS\n"
    )
    adapted = CiscoTopologyExtractor.strip_hitcnt(asa_snippet)
    assert len(adapted.splitlines()) == len(asa_snippet.splitlines())
    assert "object-group service GRP_WEB_PORTS\n" in adapted
    assert "service-object tcp destination eq www" in adapted
    assert "access-list ACL_OUTSIDE_IN extended permit object-group GRP_WEB_PORTS any object OBJ_SRV_WEB" in adapted
