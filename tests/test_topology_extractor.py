import pytest
from pathlib import Path
from src.topology_extractor import CiscoTopologyExtractor


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


def test_topology_extractor_asa():
    cfg_path = Path("snapshots/lab_cisco_vuln/configs/fw-borde-asa.cfg")
    assert cfg_path.exists()
    content = cfg_path.read_text(encoding="utf-8")

    extractor = CiscoTopologyExtractor(content)
    topo = extractor.extract_topology()

    assert topo.hostname == "ASA-PERIMETRAL-CORP"
    assert topo.dialecto == "Cisco ASA"
    assert "ACL_TEST_ORPHAN" in topo.acls_huerfanas
