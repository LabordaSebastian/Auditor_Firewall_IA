"""Fixtures compartidas para las pruebas del dashboard (MEJ-05)."""
import pytest

from src.models import (
    ContextoTopologia, DesgloseReglaVisual, HallazgoFirewall, NivelImpactoEnum, OpcionDecision,
    ReporteAuditoriaFirewall, ResumenEjecutivo, SeveridadEnum,
)

IOS_CONFIG = """hostname R-TEST
enable secret 5 $1$abcd$supersecretvalue
interface GigabitEthernet0/0
 description WAN-INTERNET
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
interface GigabitEthernet0/1
 description LAN-INTERNA
 ip address 192.168.1.1 255.255.255.0
interface GigabitEthernet0/2
 description DMZ-SERVIDORES
 ip address 172.16.10.1 255.255.255.0
ip access-list extended ACL_WAN_IN
 10 permit tcp any 172.16.10.0 0.0.0.255 eq 443
 20 deny tcp any host 172.16.10.50 eq 443
 30 permit tcp any host 200.45.112.18 eq 23
end
"""


def _opcion(nombre: str, impl: list, roll: list) -> OpcionDecision:
    return OpcionDecision(nombre_plan=nombre, descripcion_accion="Acción", efecto_en_red="Efecto",
                          comandos_cli_implementacion=impl, comandos_cli_rollback=roll)


@pytest.fixture
def sample_report() -> ReporteAuditoriaFirewall:
    h = HallazgoFirewall(
        id_hallazgo="FW-001", acl_o_componente="ACL_WAN_IN", linea_o_regla_afectada="30 permit tcp any host 200.45.112.18 eq 23",
        severidad=SeveridadEnum.CRITICA, categoria_problema="Exposición WAN ➔ Telnet", confirmado_por_batfish=True,
        desglose_visual=[DesgloseReglaVisual(rol="Regla Única", secuencia="30", accion="PERMIT", protocolo="tcp",
                                             origen="any", destino="host 200.45.112.18", puerto="eq 23", estado_flujo="Expuesto")],
        punto_critico_error="Telnet abierto a Internet", controles_normativos=["CIS-IOS-1.1 - Sin Telnet: exige SSH."],
        diagnostico_tecnico="Telnet en claro", como_mejora_la_red="Cierra Telnet", nivel_impacto_operativo=NivelImpactoEnum.BAJO,
        analisis_blast_radius="Solo legacy",
        plan_a_recomendado=_opcion("Plan A", ["configure terminal", "ip access-list extended ACL_WAN_IN", "no 30", "end"],
                                   ["configure terminal", "ip access-list extended ACL_WAN_IN", "30 permit tcp any host 200.45.112.18 eq 23", "end"]),
        plan_b_conservador=_opcion("Plan B", ["ip access-list extended ACL_WAN_IN", "25 permit tcp any host 200.45.112.18 eq 23 log"], ["no 25"]),
    )
    resumen = ResumenEjecutivo(hostname_detectado="R-TEST", dialecto_cisco="Cisco IOS / IOS-XE", score_seguridad_actual=30,
                               score_seguridad_proyectado=90, total_hallazgos=1, resumen_gerencial="Riesgo crítico.",
                               orden_prioridad_implementacion=["FW-001"])
    return ReporteAuditoriaFirewall(resumen=resumen, hallazgos=[h])


@pytest.fixture
def sample_topology() -> ContextoTopologia:
    return ContextoTopologia(hostname="R-TEST", dialecto="Cisco IOS / IOS-XE")
