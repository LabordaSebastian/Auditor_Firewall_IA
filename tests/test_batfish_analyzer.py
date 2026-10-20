import pytest
from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.models import HallazgoMatematico


def test_batfish_analyzer_connection_or_handled_error():
    analyzer = BatfishAnalyzer()
    try:
        analyzer.connect()
        assert analyzer.session is not None
    except BatfishUnavailableError as e:
        pytest.skip(f"Batfish no disponible en este entorno: {e}")


def test_batfish_analyzes_shadowed_acl():
    analyzer = BatfishAnalyzer()
    try:
        analyzer.connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo en este momento.")

    cisco_cfg = """!
hostname R-TEST
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip access-group ACL_TEST in
!
ip access-list extended ACL_TEST
 10 permit tcp any 172.16.10.0 0.0.0.255 eq 443
 20 deny tcp any host 172.16.10.50 eq 443
 30 permit ip any any
!
end
"""
    findings = analyzer.analyze_snapshot(cisco_cfg, config_filename="test_router.cfg", network_name="test_net")
    assert isinstance(findings, list)
    assert len(findings) > 0
    # Comprobar que detecta la regla inalcanzable (línea 20)
    unreachable_actions = [f.tipo for f in findings]
    assert any(t in {"SHADOWED", "CRITICAL_SHADOWING", "REDUNDANT"} for t in unreachable_actions)
