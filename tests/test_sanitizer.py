import pytest
from src.sanitizer import ConfigSanitizer


def test_sanitizer_preserves_private_ips_and_masks_public():
    sanitizer = ConfigSanitizer()
    raw_config = """
    interface GigabitEthernet0/0
     description WAN-Link
     ip address 200.45.112.18 255.255.255.248
    !
    interface GigabitEthernet0/1
     description LAN-Internal
     ip address 192.168.1.1 255.255.255.0
    !
    ip access-list extended ACL_IN
     10 permit ip 10.0.0.0 0.255.255.255 172.16.0.0 0.0.255.255
     20 permit tcp host 181.30.22.100 host 192.168.1.50 eq 80
    """

    sanitized, lookup = sanitizer.sanitize(raw_config)

    # Las IPs privadas RFC 1918 deben permanecer intactas
    assert "192.168.1.1" in sanitized
    assert "10.0.0.0" in sanitized
    assert "172.16.0.0" in sanitized
    assert "192.168.1.50" in sanitized

    # Las IPs públicas no deben estar en el texto sanitizado
    assert "200.45.112.18" not in sanitized
    assert "181.30.22.100" not in sanitized

    # Deben haberse mapeado a RFC 5737
    assert any(synth.startswith("192.0.2.") or synth.startswith("198.51.100.") or synth.startswith("203.0.113.")
               for synth in lookup["ip_mappings"].keys())

    # De-sanitización debe restaurar el texto exacto
    restored = ConfigSanitizer.desanitize(sanitized, lookup)
    assert "200.45.112.18" in restored
    assert "181.30.22.100" in restored


def test_sanitizer_obfuscates_secrets():
    sanitizer = ConfigSanitizer()
    raw = """
    enable secret 5 $1$mERr$hx5rJ7wL9pU3kL2m1o4q.
    enable password MySuperSecretPass
    snmp-server community PrivateCommunity2024 RO
    """
    sanitized, lookup = sanitizer.sanitize(raw)

    assert "$1$mERr$hx5rJ7wL9pU3kL2m1o4q." not in sanitized
    assert "MySuperSecretPass" not in sanitized
    assert "PrivateCommunity2024" not in sanitized

    assert "<REDACTED_SECRET" in sanitized
    assert "<REDACTED_PASSWORD" in sanitized
    assert "<REDACTED_SNMP_COMMUNITY" in sanitized

    restored = ConfigSanitizer.desanitize(sanitized, lookup)
    assert "$1$mERr$hx5rJ7wL9pU3kL2m1o4q." in restored
    assert "MySuperSecretPass" in restored
    assert "PrivateCommunity2024" in restored
