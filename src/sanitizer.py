import re
import json
import ipaddress
from pathlib import Path
from typing import Tuple, Dict, Any, List


class ConfigSanitizer:
    """
    Sanitizador reversible para configuraciones de routers y firewalls Cisco.
    Enmascara IPs públicas utilizando bloques RFC 5737 y oculta secretos/contraseñas.
    """

    RFC5737_POOLS = [
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("203.0.113.0/24"),
    ]

    # Regex para extraer direcciones IPv4
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # Patrones para secretos de Cisco
    SECRET_PATTERNS = [
        (re.compile(r"(enable\s+secret(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "SECRET"),
        (re.compile(r"(enable\s+password(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "PASSWORD"),
        (re.compile(r"(username\s+\S+\s+(?:secret|password)(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "USER_SECRET"),
        (re.compile(r"(snmp-server\s+community\s+)(\S+)", re.IGNORECASE), "SNMP_COMMUNITY"),
        (re.compile(r"(tacacs-server\s+key(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "TACACS_KEY"),
        (re.compile(r"(radius-server\s+key(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "RADIUS_KEY"),
        (re.compile(r"(pre-shared-key(?:\s+\d+)?\s+)(\S+)", re.IGNORECASE), "PSK_KEY"),
        (re.compile(r"(crypto\s+isakmp\s+key\s+)(\S+)", re.IGNORECASE), "ISAKMP_KEY"),
    ]

    def __init__(self):
        self.ip_pool_index = 0
        self.host_index = 10  # Comenzamos en .10 para evitar IPs de gateway comunes (.1)

    def _next_synthetic_ip(self) -> str:
        current_net = self.RFC5737_POOLS[self.ip_pool_index]
        synthetic_ip = str(current_net[self.host_index])
        self.host_index += 1
        if self.host_index >= 250:
            self.host_index = 10
            self.ip_pool_index = (self.ip_pool_index + 1) % len(self.RFC5737_POOLS)
        return synthetic_ip

    def is_public_ip(self, ip_str: str) -> bool:
        """Verifica si una IP es pública (no RFC 1918, no loopback, no multicast, no broadcast)."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # Ignorar máscaras comunes (255.255.x.x o 0.0.0.0 o 255.255.255.255)
            if ip_str in {"0.0.0.0", "255.255.255.255", "255.255.255.0", "255.255.0.0", "255.0.0.0"}:
                return False
            if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
                return False
            return True
        except ValueError:
            return False

    def sanitize(self, raw_config: str, source_filename: str = "config.cfg") -> Tuple[str, Dict[str, Any]]:
        """
        Sanitiza el contenido crudo:
        1. Mapea IPs públicas a RFC 5737 determinísticamente.
        2. Oculta contraseñas y secretos Cisco.
        Retorna (texto_sanitizado, lookup_map).
        """
        ip_mappings: Dict[str, str] = {}  # synthetic_ip -> real_ip
        reverse_ip_map: Dict[str, str] = {}  # real_ip -> synthetic_ip
        secret_mappings: Dict[str, str] = {}  # redacted_token -> real_secret

        sanitized_lines = []
        secret_counter = 1

        for line in raw_config.splitlines():
            current_line = line

            # 1. Ofuscación de secretos
            for pattern, sec_type in self.SECRET_PATTERNS:
                match = pattern.search(current_line)
                if match:
                    prefix = match.group(1)
                    secret_val = match.group(2)
                    redacted_token = f"<REDACTED_{sec_type}_{secret_counter}>"
                    secret_counter += 1
                    secret_mappings[redacted_token] = secret_val
                    current_line = pattern.sub(f"{prefix}{redacted_token}", current_line)

            # 2. Reemplazo de IPs públicas
            potential_ips = self.IPV4_PATTERN.findall(current_line)
            for ip_candidate in potential_ips:
                if self.is_public_ip(ip_candidate):
                    if ip_candidate not in reverse_ip_map:
                        synth_ip = self._next_synthetic_ip()
                        reverse_ip_map[ip_candidate] = synth_ip
                        ip_mappings[synth_ip] = ip_candidate
                    current_line = re.sub(r"\b" + re.escape(ip_candidate) + r"\b", reverse_ip_map[ip_candidate], current_line)

            sanitized_lines.append(current_line)

        sanitized_text = "\n".join(sanitized_lines)
        lookup_map = {
            "metadata": {
                "source_file": source_filename,
                "sanitization_version": "1.0",
                "total_public_ips_masked": len(ip_mappings),
                "total_secrets_masked": len(secret_mappings),
            },
            "ip_mappings": ip_mappings,
            "secret_mappings": secret_mappings,
        }
        return sanitized_text, lookup_map

    @staticmethod
    def desanitize(text: str, lookup_map: Dict[str, Any]) -> str:
        """Restaura los valores reales (IPs y secretos) usando el lookup_map."""
        result = text

        # Restaurar secretos
        secret_mappings = lookup_map.get("secret_mappings", {})
        for token, original_secret in secret_mappings.items():
            result = result.replace(token, original_secret)

        # Restaurar IPs sintéticas a IPs públicas reales
        ip_mappings = lookup_map.get("ip_mappings", {})
        for synth_ip, real_ip in ip_mappings.items():
            result = re.sub(r"\b" + re.escape(synth_ip) + r"\b", real_ip, result)

        return result

    @staticmethod
    def save_lookup_map(lookup_map: Dict[str, Any], filepath: Path) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(lookup_map, f, indent=2, ensure_ascii=False)

    @staticmethod
    def load_lookup_map(filepath: Path) -> Dict[str, Any]:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
