import re
import ipaddress
from typing import List, Optional, Tuple, Dict, Any
from src.models import HallazgoMatematico


class ParsedACE:
    def __init__(self, raw: str, index: int, action: str, proto: str, src: str, dst: str, dst_port: Optional[str] = None):
        self.raw = raw
        self.index = index
        self.action = action.lower()  # permit / deny
        self.proto = proto.lower()
        self.src = src
        self.dst = dst
        self.dst_port = dst_port

    def matches_flow(self, other: "ParsedACE") -> Tuple[bool, str]:
        """
        Compara si esta regla cubre completamente el espacio de flujo de 'other'.
        Retorna (is_shadowing, motivo).
        """
        # Comparación de protocolo
        if self.proto != "ip" and other.proto != "ip" and self.proto != other.proto:
            return False, ""

        # Comparación de puertos
        if self.dst_port and other.dst_port and self.dst_port != other.dst_port:
            return False, ""
        if self.dst_port and not other.dst_port:
            # self es más específica en puerto que other
            return False, ""

        # Comparación de IPs destino
        dst_covered = self._ip_covers(self.dst, other.dst)
        src_covered = self._ip_covers(self.src, other.src)

        if dst_covered and src_covered:
            if self.action == other.action:
                return True, "REDUNDANT"
            else:
                return True, "CRITICAL_SHADOWING" if self.action == "permit" else "SHADOWED"

        return False, ""

    def _ip_covers(self, spec1: str, spec2: str) -> bool:
        if spec1 == "any":
            return True
        if spec2 == "any" and spec1 != "any":
            return False
        if spec1 == spec2:
            return True

        # Intento de cálculo con ipaddress
        try:
            net1 = self._parse_network(spec1)
            net2 = self._parse_network(spec2)
            if net1 and net2:
                return net2.subnet_of(net1)
        except Exception:
            pass
        return False

    def _parse_network(self, ip_spec: str) -> Optional[ipaddress.IPv4Network]:
        # Formatos: "host 1.2.3.4", "1.2.3.4 0.0.0.255", "1.2.3.4 255.255.255.0", "1.2.3.4"
        parts = ip_spec.split()
        if len(parts) == 2 and parts[0] == "host":
            return ipaddress.IPv4Network(f"{parts[1]}/32")
        elif len(parts) == 2:
            ip, mask_or_wildcard = parts[0], parts[1]
            try:
                # Comprobar si es wildcard Cisco (ej: 0.0.0.255)
                wildcard_octets = [int(o) for o in mask_or_wildcard.split(".")]
                mask_octets = [255 - o for o in wildcard_octets]
                mask_str = ".".join(str(o) for o in mask_octets)
                return ipaddress.IPv4Network(f"{ip}/{mask_str}", strict=False)
            except Exception:
                try:
                    return ipaddress.IPv4Network(f"{ip}/{mask_or_wildcard}", strict=False)
                except Exception:
                    return None
        elif len(parts) == 1:
            try:
                return ipaddress.IPv4Network(f"{parts[0]}/32")
            except Exception:
                return None
        return None


class LocalMathFallbackAnalyzer:
    """
    Analizador matemático determinístico ligero en Python puro.
    Utiliza álgebra booleana y subredes para detectar reglas solapadas y redundantes
    cuando Batfish / Docker no está disponible.
    """

    @staticmethod
    def parse_acl_lines(config_text: str) -> Dict[str, List[ParsedACE]]:
        acls: Dict[str, List[ParsedACE]] = {}
        current_acl = None
        current_lines = []

        for line in config_text.splitlines():
            line_str = line.strip()
            # Cisco IOS: ip access-list extended <NAME>
            m_header = re.match(r"^ip\s+access-list\s+(?:extended|standard)\s+(\S+)", line_str, re.IGNORECASE)
            if m_header:
                current_acl = m_header.group(1)
                acls[current_acl] = []
                continue

            # Cisco ASA: access-list <NAME> extended ...
            m_asa = re.match(r"^access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(.*)", line_str, re.IGNORECASE)
            if m_asa:
                acl_name = m_asa.group(1)
                if acl_name not in acls:
                    acls[acl_name] = []
                parsed = LocalMathFallbackAnalyzer._parse_single_ace(line_str, len(acls[acl_name]) + 1)
                if parsed:
                    acls[acl_name].append(parsed)
                continue

            if current_acl:
                # Comentarios y remarks dentro de la ACL se ignoran sin cerrar el bloque
                if line_str.startswith("!") and len(line_str) > 1 and not line_str.startswith("! "):
                    pass
                if line_str.startswith("remark ") or (line_str.startswith("!") and len(line_str) > 2):
                    continue

                # Fin del bloque de ACL
                if line_str == "!" or line_str.startswith("interface ") or line_str.startswith("line ") or line_str.startswith("snmp-server") or line_str.startswith("ip "):
                    if not line_str.startswith("ip access-list"):
                        current_acl = None
                        continue

                # Línea de ACE (ej: 10 permit tcp any any eq 80)
                parsed = LocalMathFallbackAnalyzer._parse_single_ace(line_str, len(acls[current_acl]) + 1)
                if parsed:
                    acls[current_acl].append(parsed)

        return acls

    @staticmethod
    def _parse_single_ace(line: str, idx: int) -> Optional[ParsedACE]:
        tokens = line.split()
        if not tokens:
            return None
        # Remover sequence number opcional al inicio
        if tokens[0].isdigit():
            tokens = tokens[1:]
        if not tokens:
            return None

        # Descartar 'access-list <NAME> extended'
        if tokens[0].lower() == "access-list" and len(tokens) > 2:
            tokens = tokens[2:]
            if tokens and tokens[0].lower() == "extended":
                tokens = tokens[1:]

        if not tokens or tokens[0].lower() not in {"permit", "deny"}:
            return None

        action = tokens[0].lower()
        if len(tokens) < 4:
            return None

        proto = tokens[1].lower()
        remainder = " ".join(tokens[2:])

        # Extracción heurística de src, dst, port
        port = None
        if " eq " in remainder:
            parts = remainder.split(" eq ")
            remainder = parts[0]
            port = parts[1].strip().split()[0]

        # Separar origen y destino
        parts = remainder.split()
        if "any" in parts and len(parts) == 2 and parts[0] == "any" and parts[1] == "any":
            src, dst = "any", "any"
        elif "any" in remainder:
            # Dividir en base a keywords comunes
            src = "any" if parts[0] == "any" else " ".join(parts[:2])
            dst = "any" if parts[-1] == "any" else " ".join(parts[-2:])
        else:
            src = parts[0]
            dst = parts[-1]

        return ParsedACE(raw=line, index=idx, action=action, proto=proto, src=src, dst=dst, dst_port=port)

    @classmethod
    def analyze_acls(cls, config_text: str) -> List[HallazgoMatematico]:
        """Analiza todas las ACLs y detecta colisiones/shadowing entre reglas."""
        findings: List[HallazgoMatematico] = []
        acls = cls.parse_acl_lines(config_text)

        for acl_name, aces in acls.items():
            for i in range(len(aces)):
                for j in range(i + 1, len(aces)):
                    rule_a = aces[i]  # Regla superior
                    rule_b = aces[j]  # Regla inferior

                    # Chequear si son idénticas (Redundancia directa)
                    if rule_a.raw.strip() == rule_b.raw.strip():
                        findings.append(
                            HallazgoMatematico(
                                tipo="REDUNDANT",
                                filtro_nombre=acl_name,
                                linea_afectada=rule_b.raw,
                                indice_linea=rule_b.index,
                                linea_bloqueadora=rule_a.raw,
                                indice_bloqueadora=rule_a.index,
                                descripcion=f"Línea duplicada idéntica a la regla superior en posición {rule_a.index}.",
                            )
                        )
                        continue

                    # Chequear solapamiento
                    is_shadowing, motivo = rule_a.matches_flow(rule_b)
                    if is_shadowing:
                        if motivo == "CRITICAL_SHADOWING":
                            findings.append(
                                HallazgoMatematico(
                                    tipo="CRITICAL_SHADOWING",
                                    filtro_nombre=acl_name,
                                    linea_afectada=rule_b.raw,
                                    indice_linea=rule_b.index,
                                    linea_bloqueadora=rule_a.raw,
                                    indice_bloqueadora=rule_a.index,
                                    descripcion=(
                                        f"Regla permisiva superior en posición {rule_a.index} ({rule_a.raw}) "
                                        f"anula por completo la regla de bloqueo inferior ({rule_b.raw}). "
                                        f"La regla de denegación NUNCA será alcanzada."
                                    ),
                                )
                            )
                        elif motivo == "REDUNDANT":
                            findings.append(
                                HallazgoMatematico(
                                    tipo="REDUNDANT",
                                    filtro_nombre=acl_name,
                                    linea_afectada=rule_b.raw,
                                    indice_linea=rule_b.index,
                                    linea_bloqueadora=rule_a.raw,
                                    indice_bloqueadora=rule_a.index,
                                    descripcion=f"Regla redundante. Su tráfico ya está permitido por la regla superior {rule_a.index}.",
                                )
                            )
                        else:
                            findings.append(
                                HallazgoMatematico(
                                    tipo="SHADOWED",
                                    filtro_nombre=acl_name,
                                    linea_afectada=rule_b.raw,
                                    indice_linea=rule_b.index,
                                    linea_bloqueadora=rule_a.raw,
                                    indice_bloqueadora=rule_a.index,
                                    descripcion=f"Regla solapada por la regla superior en posición {rule_a.index}.",
                                )
                            )
        return findings
