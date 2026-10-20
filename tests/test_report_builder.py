import pytest
from pathlib import Path
import tempfile
from src.models import (
    ReporteAuditoriaFirewall,
    ResumenEjecutivo,
    HallazgoFirewall,
    SeveridadEnum,
    NivelImpactoEnum,
    OpcionDecision,
    ContextoTopologia,
    DesgloseReglaVisual,
)
from src.report_builder import ReportBuilder


def test_report_builder_desanitizes_and_generates_files():
    temp_dir = Path(tempfile.mkdtemp())
    builder = ReportBuilder(temp_dir)

    synthetic_ip = "198.51.100.10"
    real_ip = "200.45.112.18"

    resumen = ResumenEjecutivo(
        hostname_detectado="TEST-ROUTER",
        dialecto_cisco="Cisco IOS",
        score_seguridad_actual=40,
        score_seguridad_proyectado=90,
        total_hallazgos=1,
        resumen_gerencial="Riesgo crítico por Telnet expuesto.",
        orden_prioridad_implementacion=["FW-001"],
    )

    hallazgo = HallazgoFirewall(
        id_hallazgo="FW-001",
        acl_o_componente="ACL_WAN_IN",
        linea_o_regla_afectada=f"permit tcp any host {synthetic_ip} eq 23",
        severidad=SeveridadEnum.CRITICA,
        categoria_problema="Exposición WAN",
        confirmado_por_batfish=True,
        desglose_visual=[
            DesgloseReglaVisual(
                rol="Regla Única",
                secuencia="10",
                accion="PERMIT",
                protocolo="tcp",
                origen="any",
                destino=f"host {synthetic_ip}",
                puerto="eq 23",
                estado_flujo="Expuesto a WAN",
            )
        ],
        punto_critico_error=f"Puerto Telnet 23 abierto hacia {synthetic_ip}",
        controles_normativos=["CIS-IOS-1.1.1"],
        diagnostico_tecnico=f"Telnet abierto en {synthetic_ip}",
        como_mejora_la_red="Cierra acceso en texto plano",
        nivel_impacto_operativo=NivelImpactoEnum.BAJO,
        analisis_blast_radius="Solo afecta acceso Telnet legacy",
        plan_a_recomendado=OpcionDecision(
            nombre_plan="Plan A",
            descripcion_accion="Eliminar regla",
            efecto_en_red="Bloqueo inmediato",
            comandos_cli_implementacion=[f"no permit tcp any host {synthetic_ip} eq 23"],
            comandos_cli_rollback=[f"permit tcp any host {synthetic_ip} eq 23"],
        ),
        plan_b_conservador=OpcionDecision(
            nombre_plan="Plan B",
            descripcion_accion="Agregar log",
            efecto_en_red="Auditar hits",
            comandos_cli_implementacion=[f"permit tcp any host {synthetic_ip} eq 23 log"],
            comandos_cli_rollback=[f"permit tcp any host {synthetic_ip} eq 23"],
        ),
    )

    report = ReporteAuditoriaFirewall(resumen=resumen, hallazgos=[hallazgo])
    topology = ContextoTopologia(hostname="TEST-ROUTER", dialecto="Cisco IOS")
    lookup_map = {
        "ip_mappings": {synthetic_ip: real_ip},
        "secret_mappings": {},
    }

    paths = builder.generate_all(report, topology, lookup_map, base_name="test_fw")

    assert paths["markdown"].exists()
    assert paths["json"].exists()
    assert paths["remediation_cli"].exists()
    assert paths["rollback_cli"].exists()

    md_content = paths["markdown"].read_text(encoding="utf-8")
    assert real_ip in md_content
    assert synthetic_ip not in md_content

    cli_content = paths["remediation_cli"].read_text(encoding="utf-8")
    assert real_ip in cli_content
    assert synthetic_ip not in cli_content
