import re
from typing import Dict, List, Optional, Set, Tuple
from ciscoconfparse2 import CiscoConfParse
from src.models import ContextoTopologia, ContextoInterfaz, ReglaACL


class CiscoTopologyExtractor:
    """
    Extractor de topología y contexto para configuraciones Cisco IOS, IOS-XE y ASA.
    Identifica interfaces, ACLs aplicadas, ACLs huérfanas y configuración de gestión.
    """

    def __init__(self, config_text: str):
        self.config_text = config_text
        self.lines = [line.strip() for line in config_text.splitlines() if line.strip()]
        self.parse = CiscoConfParse(config_text.splitlines(), syntax='ios')

    def detect_dialect(self) -> str:
        """Determina si la configuración corresponde a Cisco ASA o Cisco IOS/IOS-XE."""
        for line in self.lines[:30]:
            lower = line.lower()
            if "asa version" in lower or ": saved" in lower or "nameif" in lower:
                return "Cisco ASA"
            if "ios" in lower or "version 15" in lower or "version 16" in lower or "version 17" in lower:
                return "Cisco IOS / IOS-XE"
        # Verificación heurística
        if any("security-level" in l for l in self.lines) or any("nameif" in l for l in self.lines):
            return "Cisco ASA"
        return "Cisco IOS / IOS-XE"

    def extract_hostname(self) -> str:
        """Extrae el hostname del dispositivo."""
        for line in self.lines:
            match = re.match(r"^hostname\s+(\S+)", line, re.IGNORECASE)
            if match:
                return match.group(1)
        return "DISPOSITIVO-CISCO"

    def extract_interfaces(self, dialect: str) -> Dict[str, ContextoInterfaz]:
        """Extrae interfaces, IPs, descripciones y ACLs asociadas."""
        interfaces: Dict[str, ContextoInterfaz] = {}

        if dialect == "Cisco ASA":
            # Parser específico ASA
            curr_iface = None
            for line in self.lines:
                match_iface = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
                if match_iface:
                    curr_iface = match_iface.group(1)
                    interfaces[curr_iface] = ContextoInterfaz(nombre=curr_iface)
                    continue

                if curr_iface and not line.startswith("!"):
                    # nameif
                    m_name = re.match(r"^\s*nameif\s+(\S+)", line, re.IGNORECASE)
                    if m_name:
                        interfaces[curr_iface].descripcion = f"nameif: {m_name.group(1)}"
                    # security-level
                    m_sec = re.match(r"^\s*security-level\s+(\d+)", line, re.IGNORECASE)
                    if m_sec:
                        interfaces[curr_iface].security_level = int(m_sec.group(1))
                    # ip address
                    m_ip = re.match(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?", line, re.IGNORECASE)
                    if m_ip:
                        interfaces[curr_iface].ip_address = m_ip.group(1)
                        interfaces[curr_iface].mascara = m_ip.group(2)

            # En ASA, access-group se asocia por nombre de interfaz: access-group ACL in interface outside
            for line in self.lines:
                m_ag = re.match(r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", line, re.IGNORECASE)
                if m_ag:
                    acl_name, direction, iface_name = m_ag.group(1), m_ag.group(2).lower(), m_ag.group(3)
                    # Encontrar la interfaz por nameif o por nombre
                    for if_obj in interfaces.values():
                        if if_obj.descripcion and iface_name in if_obj.descripcion:
                            if direction == "in":
                                if_obj.acl_in = acl_name
                            else:
                                if_obj.acl_out = acl_name
        else:
            # Parser Cisco IOS / IOS-XE
            iface_objs = self.parse.find_objects(r"^interface\s+")
            for iface in iface_objs:
                name = iface.text.split()[1]
                ctx = ContextoInterfaz(nombre=name)

                for child in iface.children:
                    ctext = child.text.strip()
                    m_desc = re.match(r"^description\s+(.*)", ctext, re.IGNORECASE)
                    if m_desc:
                        ctx.descripcion = m_desc.group(1)
                    m_ip = re.match(r"^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?", ctext, re.IGNORECASE)
                    if m_ip:
                        ctx.ip_address = m_ip.group(1)
                        ctx.mascara = m_ip.group(2)
                    m_acl_in = re.match(r"^ip\s+access-group\s+(\S+)\s+in", ctext, re.IGNORECASE)
                    if m_acl_in:
                        ctx.acl_in = m_acl_in.group(1)
                    m_acl_out = re.match(r"^ip\s+access-group\s+(\S+)\s+out", ctext, re.IGNORECASE)
                    if m_acl_out:
                        ctx.acl_out = m_acl_out.group(1)

                interfaces[name] = ctx

        return interfaces

    def extract_acls_and_orphans(self, interfaces: Dict[str, ContextoInterfaz], dialect: str) -> Tuple[List[str], List[str]]:
        """Identifica ACLs activas y ACLs huérfanas."""
        declared_acls: Set[str] = set()
        active_acls: Set[str] = set()

        if dialect == "Cisco ASA":
            for line in self.lines:
                m = re.match(r"^access-list\s+(\S+)", line, re.IGNORECASE)
                if m:
                    declared_acls.add(m.group(1))
                m_ag = re.match(r"^access-group\s+(\S+)", line, re.IGNORECASE)
                if m_ag:
                    active_acls.add(m_ag.group(1))
        else:
            # IOS
            for line in self.lines:
                m_ext = re.match(r"^ip\s+access-list\s+(?:extended|standard)\s+(\S+)", line, re.IGNORECASE)
                if m_ext:
                    declared_acls.add(m_ext.group(1))
                m_num = re.match(r"^access-list\s+(\d+)", line, re.IGNORECASE)
                if m_num:
                    declared_acls.add(m_num.group(1))

            # Revisar las aplicadas a interfaces
            for iface in interfaces.values():
                if iface.acl_in:
                    active_acls.add(iface.acl_in)
                if iface.acl_out:
                    active_acls.add(iface.acl_out)

            # Revisar las aplicadas a line vty
            for line in self.lines:
                m_vty = re.match(r"^\s*access-class\s+(\S+)", line, re.IGNORECASE)
                if m_vty:
                    active_acls.add(m_vty.group(1))

        orphan_acls = list(declared_acls - active_acls)
        return sorted(list(active_acls)), sorted(orphan_acls)

    def extract_vty_security(self) -> Tuple[Optional[str], Optional[str]]:
        """Extrae la configuración de seguridad en líneas VTY."""
        vty_access_class = None
        transport_input = None

        vty_objs = self.parse.find_objects(r"^line\s+vty")
        for vty in vty_objs:
            for child in vty.children:
                ctext = child.text.strip()
                m_ac = re.match(r"^access-class\s+(\S+)", ctext, re.IGNORECASE)
                if m_ac:
                    vty_access_class = m_ac.group(1)
                m_ti = re.match(r"^transport\s+input\s+(.*)", ctext, re.IGNORECASE)
                if m_ti:
                    transport_input = m_ti.group(1)

        return vty_access_class, transport_input

    def extract_topology(self) -> ContextoTopologia:
        """Genera el modelo consolidado de ContextoTopologia."""
        dialect = self.detect_dialect()
        hostname = self.extract_hostname()
        interfaces = self.extract_interfaces(dialect)
        active_acls, orphan_acls = self.extract_acls_and_orphans(interfaces, dialect)
        vty_ac, vty_ti = self.extract_vty_security()

        return ContextoTopologia(
            hostname=hostname,
            dialecto=dialect,
            interfaces=interfaces,
            acls_activas=active_acls,
            acls_huerfanas=orphan_acls,
            vty_access_class=vty_ac,
            vty_transport_input=vty_ti,
            total_lineas_config=len(self.lines),
        )
