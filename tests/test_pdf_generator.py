import json
from pathlib import Path

from src.models import ContextoInterfaz, ContextoTopologia, DesgloseReglaVisual, ReporteAuditoriaFirewall
from src.pdf_generator import build_pdf


def test_pdf_is_valid_and_handles_unicode(sample_report, sample_topology):
    data = build_pdf(sample_report, sample_topology)
    assert data.startswith(b"%PDF")
    assert len(data) > 5000
    assert data.rstrip().endswith(b"%%EOF")


def test_pdf_renders_tables_long_rules_and_multiple_findings(sample_report):
    """Regresión RF-13.3: tablas de colisión, interfaces y reglas largas sin desborde ni error."""
    h1 = sample_report.hallazgos[0].model_copy(deep=True)
    h1.desglose_visual = [
        DesgloseReglaVisual(
            rol="Regla Superior (Bloqueadora)", secuencia="10", accion="PERMIT", protocolo="ip",
            origen="any", destino="172.16.50.0 255.255.255.0", puerto="cualquiera",
            estado_flujo="Captura todo el tráfico y anula reglas posteriores",
        ),
        DesgloseReglaVisual(
            rol="Regla Inferior (Oculta/Tapada)", secuencia="20", accion="DENY", protocolo="tcp",
            origen="any", destino="host 172.16.50.10", puerto="eq 3306",
            estado_flujo="Inalcanzable (Shadowed por línea 10)",
        ),
    ]
    h2 = h1.model_copy(deep=True)
    h2.id_hallazgo = "FW-002"
    h2.linea_o_regla_afectada = (
        "access-list ACL_OUTSIDE_IN extended permit tcp any object OBJ_SRV_WEB object-group GRP_WEB_PORTS log"
    )
    report = sample_report.model_copy(deep=True)
    report.hallazgos = [h1, h2]
    report.resumen.total_hallazgos = 2

    topo = ContextoTopologia(
        hostname="ASA-PERIMETRAL-CORP",
        dialecto="Cisco ASA",
        total_lineas_config=68,
        acls_activas=["ACL_OUTSIDE_IN"],
        acls_huerfanas=["ACL_TEST_ORPHAN"],
        vty_access_class="ACL_MGMT_VTY",
        vty_transport_input="ssh",
        interfaces={
            "GigabitEthernet0/0": ContextoInterfaz(
                nombre="GigabitEthernet0/0", descripcion="outside", ip_address="192.0.2.10",
                mascara="255.255.255.240", acl_in="ACL_OUTSIDE_IN", security_level=0,
            ),
            "GigabitEthernet0/2": ContextoInterfaz(
                nombre="GigabitEthernet0/2", descripcion="dmz", ip_address="172.16.50.1",
                mascara="255.255.255.0", security_level=50,
            ),
        },
    )
    data = build_pdf(report, topo)
    assert data.startswith(b"%PDF") and len(data) > 7000 and data.rstrip().endswith(b"%%EOF")


def test_pdf_generator_excludes_remediation_plans_and_cli_commands():
    """El reporte ejecutivo PDF es informativo: no debe incluir Plan A/B ni comandos CLI."""
    src_text = Path("src/pdf_generator.py").read_text(encoding="utf-8")
    assert "plan_a_recomendado" not in src_text and "plan_b_conservador" not in src_text
    assert "comandos_cli_implementacion" not in src_text and "comandos_cli_rollback" not in src_text
