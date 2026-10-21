from src.sanitizer import ConfigSanitizer
from tests.conftest import IOS_CONFIG


def test_sanitization_view_masks_secrets_and_lists_ips():
    san, lookup = ConfigSanitizer().sanitize(IOS_CONFIG)
    view = ConfigSanitizer.build_sanitization_view(IOS_CONFIG, san, lookup)

    assert view["total_ips"] == 1 and view["total_secretos"] == 1
    assert view["lineas_modificadas"] >= 3
    ip_row = next(r for r in view["reemplazos"] if r["categoria"] == "ip")
    assert ip_row["original"] == "200.45.112.18" and ip_row["ocurrencias"] == 2

    secret_row = next(r for r in view["reemplazos"] if r["categoria"] == "secreto")
    assert "supersecretvalue" not in str(view) and "$1$abcd$supersecretvalue" not in str(view)
    assert secret_row["reemplazo"].startswith("<REDACTED_")


def test_sanitization_view_empty_when_nothing_to_mask():
    cfg = "hostname X\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
    san, lookup = ConfigSanitizer().sanitize(cfg)
    view = ConfigSanitizer.build_sanitization_view(cfg, san, lookup)
    assert view["reemplazos"] == [] and view["diff"] == []
