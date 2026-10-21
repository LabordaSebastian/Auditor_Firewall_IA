from src.models import ContextoInterfaz
from src.topology_extractor import CiscoTopologyExtractor
from src.web.graph import build_graph, build_zones, classify_zone, interface_subnet
from tests.conftest import IOS_CONFIG


def test_classify_zone_by_description_and_security_level():
    assert classify_zone(ContextoInterfaz(nombre="g0", descripcion="WAN-INTERNET")) == "WAN"
    assert classify_zone(ContextoInterfaz(nombre="g1", descripcion="DMZ-SERVIDORES")) == "DMZ"
    assert classify_zone(ContextoInterfaz(nombre="g2", descripcion="nameif: inside", security_level=100)) == "LAN"
    assert classify_zone(ContextoInterfaz(nombre="g3", descripcion="nameif: x", security_level=0)) == "WAN"
    assert classify_zone(ContextoInterfaz(nombre="g4", ip_address="8.8.4.4")) == "WAN"


def test_subnet_and_graph_from_real_extractor():
    topo = CiscoTopologyExtractor(IOS_CONFIG).extract_topology()
    zones = {z["zona"]: z for z in build_zones(topo)}
    assert zones["LAN"]["subred"] == "192.168.1.0/24"
    assert zones["DMZ"]["subred"] == "172.16.10.0/24"
    assert zones["WAN"]["subred"] == "200.45.112.16/29"

    graph = build_graph(topo, {"ACL_WAN_IN": 2})
    ids = {n["id"] for n in graph["nodos"]}
    assert {"R-TEST", "WAN", "LAN", "DMZ", "Internet"} <= ids
    wan = next(n for n in graph["nodos"] if n["id"] == "WAN")
    assert wan["hallazgos"] == 2
    assert interface_subnet(ContextoInterfaz(nombre="x", ip_address="10.0.0.5")) is None
