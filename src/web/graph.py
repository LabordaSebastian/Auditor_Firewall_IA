"""Construcción del grafo topológico y clasificación de zonas de seguridad (MEJ-05)."""
import ipaddress
from typing import Any, Dict, List, Optional

from src.models import ContextoInterfaz, ContextoTopologia

TRUST = {"WAN": 0, "DMZ": 1, "LAN": 2, "GESTION": 3}

_KEYWORDS = [
    ("GESTION", ("mgmt", "management", "gesti", "oob")),
    ("DMZ", ("dmz",)),
    ("WAN", ("wan", "internet", "outside", "isp", "fibra")),
    ("LAN", ("lan", "inside", "interna", "usuarios", "corp")),
]


def classify_zone(iface: ContextoInterfaz) -> str:
    """Deduce la zona de seguridad por descripción/nameif, security-level o tipo de IP."""
    text = (iface.descripcion or "").lower()
    for zone, words in _KEYWORDS:
        if any(w in text for w in words):
            return zone
    if iface.security_level is not None:
        if iface.security_level == 0:
            return "WAN"
        return "LAN" if iface.security_level >= 100 else "DMZ"
    if iface.ip_address:
        try:
            if ipaddress.IPv4Address(iface.ip_address).is_global:
                return "WAN"
        except ValueError:
            pass
    return "LAN"


def interface_subnet(iface: ContextoInterfaz) -> Optional[str]:
    if not iface.ip_address or not iface.mascara:
        return None
    try:
        return str(ipaddress.ip_interface(f"{iface.ip_address}/{iface.mascara}").network)
    except ValueError:
        return None


def build_zones(topology: ContextoTopologia) -> List[Dict[str, Any]]:
    """Zonas con interfaz + subred (una por interfaz con IP) para consultas Batfish."""
    zones: List[Dict[str, Any]] = []
    used: Dict[str, int] = {}
    for name, iface in topology.interfaces.items():
        subnet = interface_subnet(iface)
        if not subnet:
            continue
        zone = classify_zone(iface)
        used[zone] = used.get(zone, 0) + 1
        label = zone if used[zone] == 1 else f"{zone}-{used[zone]}"
        zones.append({
            "nombre": label, "zona": zone, "interfaz": name, "subred": subnet,
            "confianza": TRUST[zone], "ip": iface.ip_address,
        })
    return zones


def build_graph(topology: ContextoTopologia, findings_by_acl: Dict[str, int]) -> Dict[str, Any]:
    """Grafo de nodos/enlaces: Internet ↔ Firewall ↔ zonas (una por interfaz)."""
    zones = build_zones(topology)
    fw_id = topology.hostname
    nodes: List[Dict[str, Any]] = [{
        "id": fw_id, "label": fw_id, "tipo": "firewall",
        "detalle": {
            "Hostname": topology.hostname,
            "Dialecto": topology.dialecto,
            "Interfaces": len(topology.interfaces),
            "ACLs activas": ", ".join(topology.acls_activas) or "Ninguna",
            "ACLs huérfanas": ", ".join(topology.acls_huerfanas) or "Ninguna",
            "VTY access-class": topology.vty_access_class or "Ninguna",
            "VTY transport": topology.vty_transport_input or "No configurado",
        },
    }]
    links: List[Dict[str, Any]] = []
    has_wan = False

    for z in zones:
        iface = topology.interfaces[z["interfaz"]]
        acls = [a for a in (iface.acl_in, iface.acl_out) if a]
        hallazgos = sum(findings_by_acl.get(a, 0) for a in acls)
        nodes.append({
            "id": z["nombre"], "label": z["nombre"], "tipo": z["zona"],
            "detalle": {
                "Zona": z["zona"], "Interfaz": z["interfaz"], "Descripción": iface.descripcion or "N/D",
                "IP": iface.ip_address, "Subred": z["subred"],
                "Security-level": iface.security_level if iface.security_level is not None else "N/D",
                "ACL entrada": iface.acl_in or "-", "ACL salida": iface.acl_out or "-",
                "Hallazgos en sus ACLs": hallazgos,
            },
            "hallazgos": hallazgos,
        })
        links.append({
            "source": fw_id, "target": z["nombre"], "interfaz": z["interfaz"], "subred": z["subred"],
            "acl_in": iface.acl_in, "acl_out": iface.acl_out,
        })
        has_wan = has_wan or z["zona"] == "WAN"

    if has_wan:
        nodes.append({"id": "Internet", "label": "Internet", "tipo": "internet",
                      "detalle": {"Descripción": "Red externa no confiable", "Origen simulado": "Cualquier IP pública"}})
        for z in zones:
            if z["zona"] == "WAN":
                links.append({"source": z["nombre"], "target": "Internet", "interfaz": "", "subred": "0.0.0.0/0",
                              "acl_in": None, "acl_out": None})
    return {"nodos": nodes, "enlaces": links, "zonas": zones}
