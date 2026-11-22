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

    # Patrones de contadores de tráfico en Cisco IOS / IOS-XE / ASA (MEJ-02)
    _HITCNT_PATTERNS = (
        re.compile(r"\(\s*hitcnt\s*=\s*(\d+)\s*\)(?:\s+0x[0-9a-fA-F]+)?", re.IGNORECASE),
        re.compile(r"\bhitcnt\s*=\s*(\d+)\b(?:\s+0x[0-9a-fA-F]+)?", re.IGNORECASE),
        re.compile(r"\(\s*(\d+)\s+match(?:es)?\s*\)", re.IGNORECASE),
    )

    @classmethod
    def strip_hitcnt(cls, config_text: str) -> str:
        """
        Limpia anotaciones de contadores (`(hitcnt=N) 0x...`, `(N matches)`) y `line N` de salidas
        `show access-lists` para que el parser formal de Batfish procese las ACLs como running-config.
        """
        cleaned_lines: List[str] = []
        for raw_line in config_text.splitlines():
            line = raw_line
            for pat in cls._HITCNT_PATTERNS:
                line = pat.sub("", line)
            line = re.sub(r"^(\s*access-list\s+\S+)\s+line\s+\d+\s+", r"\1 ", line, flags=re.IGNORECASE)
            cleaned_lines.append(line.rstrip())
        return "\n".join(cleaned_lines) + ("\n" if config_text.endswith("\n") else "")

    @classmethod
    def _parse_hit_count(cls, line: str) -> Optional[int]:
        for pat in cls._HITCNT_PATTERNS:
            m = pat.search(line)
            if m:
                return int(m.group(1))
        return None

    def extract_zombie_rules(self, dialect: str) -> Tuple[List[ReglaACL], int]:
        """
        Detecta reglas zombi/inactivas con contador de tráfico en cero (`hitcnt=0` o `(0 matches)`)
        asociando comentarios `remark` o tickets previos para proponer su depuración con riesgo
        operativo NULO o BAJO (optimización de memoria TCAM).
        """
        zombies: List[ReglaACL] = []
        total_with_hits = 0
        current_acl: Optional[str] = None
        last_remark: Optional[str] = None

        for idx, raw_line in enumerate(self.config_text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            # Comentario con '!' que documenta regla temporal o ticket (en IOS o ASA)
            if stripped.startswith("!"):
                comment_body = stripped.lstrip("! ").strip()
                if any(w in comment_body.lower() for w in ("temporal", "ticket", "vencid", "olvid", "expir", "legacy", "zombi")):
                    last_remark = comment_body
                continue

            # Inicio de bloque ACL nombrada en IOS
            m_ios_acl = re.match(r"^ip\s+access-list\s+(?:extended|standard)\s+(\S+)", stripped, re.IGNORECASE)
            if m_ios_acl:
                current_acl = m_ios_acl.group(1)
                last_remark = None
                continue

            # Salida de bloque en IOS si empieza comando global no indentado distinto de access-list
            if not raw_line.startswith((" ", "\t")) and not stripped.lower().startswith("access-list"):
                if re.match(r"^(?:interface|line|router|snmp-server|end)\b", stripped, re.IGNORECASE):
                    current_acl = None
                    last_remark = None

            # Remark en IOS (dentro de bloque) o en ASA (`access-list X remark ...`)
            m_asa_rem = re.match(r"^access-list\s+(\S+)\s+(?:line\s+\d+\s+)?remark\s+(.*)", stripped, re.IGNORECASE)
            if m_asa_rem:
                current_acl = m_asa_rem.group(1)
                last_remark = m_asa_rem.group(2).strip()
                continue
            m_ios_rem = re.match(r"^(?:(\d+)\s+)?remark\s+(.*)", stripped, re.IGNORECASE)
            if m_ios_rem and current_acl:
                last_remark = m_ios_rem.group(2).strip()
                continue

            hits = self._parse_hit_count(stripped)
            if hits is None:
                # Si pasó una regla normal sin hitcnt=0, limpiamos remark salvo que sea del mismo bloque inmediato
                if re.search(r"\b(permit|deny)\b", stripped, re.IGNORECASE):
                    last_remark = None
                continue

            # Evaluar si es una ACE (permit / deny)
            acl_name = current_acl or "ACL_GLOBAL"
            seq: Optional[str] = None
            action: Optional[str] = None
            proto: Optional[str] = None

            m_asa_ace = re.match(
                r"^access-list\s+(\S+)\s+(?:line\s+(\d+)\s+)?(?:extended|standard)?\s*(permit|deny)\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            m_ios_ace = re.match(r"^(?:(\d+)\s+)?(permit|deny)\s+(\S+)", stripped, re.IGNORECASE)

            if m_asa_ace:
                acl_name = m_asa_ace.group(1)
                seq = m_asa_ace.group(2)
                action = m_asa_ace.group(3).lower()
                proto = m_asa_ace.group(4).lower()
            elif m_ios_ace:
                seq = m_ios_ace.group(1)
                action = m_ios_ace.group(2).lower()
                proto = m_ios_ace.group(3).lower()

            if not action:
                continue

            total_with_hits += 1
            if hits == 0:
                clean_rule = self.strip_hitcnt(stripped).strip()
                riesgo = (
                    "NULO (Regla inactiva hitcnt=0 con comentario/ticket asociado; depuración segura de TCAM)"
                    if last_remark
                    else "BAJO (0 coincidencias de tráfico registradas; candidata a limpieza de TCAM)"
                )
                zombies.append(
                    ReglaACL(
                        acl_nombre=acl_name,
                        secuencia=seq,
                        numero_linea=idx,
                        texto_crudo=clean_rule,
                        accion=action,
                        protocolo=proto,
                        comentario=last_remark,
                        hit_count=0,
                        riesgo_depuracion=riesgo,
                    )
                )
            last_remark = None

        return zombies, total_with_hits

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
        zombies, total_hits = self.extract_zombie_rules(dialect)
        vty_ac, vty_ti = self.extract_vty_security()

        return ContextoTopologia(
            hostname=hostname,
            dialecto=dialect,
            interfaces=interfaces,
            acls_activas=active_acls,
            acls_huerfanas=orphan_acls,
            reglas_zombi=zombies,
            total_reglas_con_hitcnt=total_hits,
            vty_access_class=vty_ac,
            vty_transport_input=vty_ti,
            total_lineas_config=len(self.lines),
        )
