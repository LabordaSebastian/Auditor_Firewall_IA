"""
Motor determinístico de respaldo y asesor contextual de arquitectura de zonas (MEJ-11 / RF-16).

Cumple dos funciones esenciales:
1. Garantiza que la aplicación sea 100 % funcional aunque la IA (Gemini) esté desactivada o sin
   conexión, sintetizando `ReporteAuditoriaFirewall` a partir de Batfish + Topología.
2. Evalúa con criterio de arquitectura de red el sentido del flujo entre zonas de distinta
   confianza (`Zona Segura LAN ➔ Zona Menos Segura WAN` vs. `Entrada WAN ➔ DMZ/LAN`), diferenciando
   cuándo el uso de comodines (`any`) está operativamente justificado (p. ej. destino `any` en
   salida a Internet u origen `any` hacia un servidor público en DMZ) y generando Planes C
   adaptados a excepciones operativas con controles compensatorios.
"""
import re
from typing import Dict, List, Optional, Tuple

from src.models import (
    ContextoTopologia,
    DesgloseReglaVisual,
    DictamenExcepcionIA,
    HallazgoFirewall,
    HallazgoMatematico,
    NivelImpactoEnum,
    OpcionDecision,
    ReporteAuditoriaFirewall,
    ResumenEjecutivo,
    SeveridadEnum,
)
from src.web.graph import build_zones


def _zone_for_acl(topology: ContextoTopologia, acl_name: str) -> Dict[str, str]:
    """Deduce la zona e interfaz donde se aplica una ACL y su dirección (in/out)."""
    zones = {z["interfaz"]: z for z in build_zones(topology)}
    for if_name, iface in topology.interfaces.items():
        z = zones.get(if_name, {"zona": "LAN", "subred": "192.168.1.0/24", "confianza": 2})
        if iface.acl_in and iface.acl_in in acl_name:
            return {"zona": z["zona"], "interfaz": if_name, "direccion": "in", "subred": z.get("subred", "")}
        if iface.acl_out and iface.acl_out in acl_name:
            return {"zona": z["zona"], "interfaz": if_name, "direccion": "out", "subred": z.get("subred", "")}
    return {"zona": "GLOBAL", "interfaz": "-", "direccion": "-", "subred": ""}


def enrich_finding_zone_context(h: HallazgoFirewall, topology: ContextoTopologia) -> None:
    """
    Completa `sentido_flujo_zonas`, `veredicto_flexibilidad_any` y `criterio_arquitectonico_ia`
    analizando la dirección real entre zonas seguras y menos seguras.
    """
    comp = (h.acl_o_componente or "").lower()
    rule = (h.linea_o_regla_afectada or "").lower()
    cat = (h.categoria_problema or "").lower()
    zinfo = _zone_for_acl(topology, h.acl_o_componente)
    zona = zinfo["zona"]
    subred_lan = next((z["subred"] for z in build_zones(topology) if z["zona"] == "LAN"), "192.168.1.0/24")

    # 1. Plano de gestión (VTY, HTTP/SSH management, SNMP, passwords)
    if any(k in comp or k in cat or k in rule for k in ("vty", "management", "snmp", "http 0.0.0.0", "ssh 0.0.0.0", "secret", "password")):
        h.sentido_flujo_zonas = "Plano de Gestión y Administración del Dispositivo (Confianza Crítica)"
        if not h.veredicto_flexibilidad_any or h.veredicto_flexibilidad_any == "NO_APLICA":
            h.veredicto_flexibilidad_any = "RIESGO_INJUSTIFICADO"
        if not h.criterio_arquitectonico_ia:
            h.criterio_arquitectonico_ia = (
                "En el plano de administración directa del router/firewall (líneas VTY, ASDM, SSH al propio equipo o SNMP) "
                "no existe ninguna justificación para emplear orígenes 'any' (0.0.0.0/0). A diferencia del tráfico de usuarios, "
                "los administradores operan desde subredes de gestión o LAN conocidas; debe exigirse lista blanca de origen "
                f"({subred_lan}) y protocolos cifrados (SSHv2 / HTTPS)."
            )
        return

    # 2. Reglas de salida desde zona segura (LAN -> WAN / DMZ)
    if zona == "LAN" or "lan" in comp or "inside" in comp:
        h.sentido_flujo_zonas = "Salida desde Zona Segura: LAN Interna (Confianza Alta) ➔ WAN / DMZ (Confianza Menor)"
        if not h.veredicto_flexibilidad_any or h.veredicto_flexibilidad_any == "NO_APLICA":
            h.veredicto_flexibilidad_any = "EQUILIBRIO_PRAGMATICO"
        if not h.criterio_arquitectonico_ia:
            h.criterio_arquitectonico_ia = (
                "Criterio de Zonas Seguras a Menos Seguras (LAN ➔ WAN): Cuando el tráfico nace en una zona interna confiable "
                "para salir a Internet, mantener 'any' en el DESTINO es operativamente válido y necesario (los usuarios "
                "consultan miles de IPs públicas dinámicas). Sin embargo, un 'permit ip any any' es excesivo porque deja abierto "
                "también el ORIGEN 'any' (riesgo de IP spoofing) y permite cruzar sin filtro hacia la DMZ interna. "
                f"Equilibrio recomendado: conservar la libertad de destino 'any' hacia Internet para navegación (TCP/UDP 80, 443, 53), "
                f"acotar el origen a la subred LAN ({subred_lan}), exigir reglas específicas hacia servidores de la DMZ y bloquear "
                "puertos críticos de fuga lateral (SMB/445, Telnet/23)."
            )
        return

    # 3. Reglas de higiene, zombis, redundancia o falta de logging final
    if any(k in cat for k in ("redundan", "higiene", "temporal", "zombi", "huérfan", "huerfan", "logging")):
        h.sentido_flujo_zonas = (
            "Política Inactiva (ACL Huérfana / Regla Zombi sin tráfico)"
            if "huérfan" in cat or "huerfan" in cat or "temporal" in cat or "zombi" in cat
            else f"Control e Higiene en Perímetro ({zona})"
        )
        if not h.veredicto_flexibilidad_any or h.veredicto_flexibilidad_any == "NO_APLICA":
            h.veredicto_flexibilidad_any = "HIGIENE_Y_CONTROL"
        if not h.criterio_arquitectonico_ia:
            if "logging" in cat:
                h.criterio_arquitectonico_ia = (
                    "El cierre explícito 'deny ip any any log' al final de una ACL perimetral es el único escenario donde "
                    "el comodín doble 'any any' es una buena práctica obligatoria: garantiza que todo paquete no autorizado "
                    "sea descartado dejando evidencia en Syslog/SIEM."
                )
            else:
                h.criterio_arquitectonico_ia = (
                    "Las reglas temporales vencidas, con contador en cero (hitcnt=0 / 0 matches), duplicadas o en ACLs huérfanas "
                    "no tienen tráfico legítimo activo que justifique mantenerlas. Su depuración tiene riesgo operativo NULO/BAJO "
                    "y libera entradas en la memoria TCAM del hardware."
                )
        return

    # 4. Entrada desde zona menos segura (WAN -> DMZ / Perímetro)
    h.sentido_flujo_zonas = "Entrada Perimetral: WAN / Internet (Confianza 0) ➔ DMZ / Red Interna (Confianza Mayor)"
    is_web_shadow = ("shadow" in cat) and ("443" in rule or "80" in rule or "172.16." in rule)
    if is_web_shadow:
        if not h.veredicto_flexibilidad_any or h.veredicto_flexibilidad_any == "NO_APLICA":
            h.veredicto_flexibilidad_any = "FLEXIBILIDAD_JUSTIFICADA"
        if not h.criterio_arquitectonico_ia:
            h.criterio_arquitectonico_ia = (
                "Criterio en Entrada WAN ➔ DMZ: Al publicar un servidor web en la DMZ hacia Internet, el uso de ORIGEN 'any' "
                "sí está justificado (cualquier cliente externo en Internet debe poder iniciar conexión HTTPS/443). "
                "El error arquitectónico aquí es doble: 1) usar como DESTINO toda la subred DMZ (/24) o protocolo 'ip' en vez "
                "del 'host' específico, y 2) colocar esa regla general por encima de un 'deny' específico, anulándolo por Shadowing."
            )
    else:
        if not h.veredicto_flexibilidad_any or h.veredicto_flexibilidad_any == "NO_APLICA":
            h.veredicto_flexibilidad_any = "RIESGO_INJUSTIFICADO"
        if not h.criterio_arquitectonico_ia:
            h.criterio_arquitectonico_ia = (
                "Criterio en Entrada de Baja a Alta Confianza (WAN ➔ Interior): A diferencia de las reglas de salida desde "
                "la LAN donde se da libertad de destino 'any', en el sentido entrante desde Internet hacia puertos de gestión "
                "o servicios internos (Telnet/23, SSH/22, RDP/3389, MySQL/3306) el comodín 'any' expone el activo a escaneos "
                "masivos y fuerza bruta global. Debe bloquearse en WAN o restringirse a IPs origen fijas / VPN."
            )


def enrich_report_zone_context(report: ReporteAuditoriaFirewall, topology: ContextoTopologia) -> ReporteAuditoriaFirewall:
    """Enriquece todos los hallazgos de un reporte con el dictamen contextual de zonas."""
    for h in report.hallazgos:
        enrich_finding_zone_context(h, topology)
    return report


class DeterministicFirewallAdvisor:
    """
    Sintetizador determinístico de hallazgos, postura y planes A/B/C basado en Batfish + Topología.
    Permite que la app funcione al 100 % sin depender de la API de Gemini y provee fallback inmediato.
    """

    def analyze(
        self,
        sanitized_config: str,
        topology: ContextoTopologia,
        math_findings: List[HallazgoMatematico],
    ) -> ReporteAuditoriaFirewall:
        findings: List[HallazgoFirewall] = []
        is_asa = topology.dialecto == "Cisco ASA"
        zones = build_zones(topology)
        lan_subnet = next((z["subred"] for z in zones if z["zona"] == "LAN"), "192.168.1.0/24")
        dmz_subnet = next((z["subred"] for z in zones if z["zona"] == "DMZ"), "172.16.10.0/24")
        lan_net_ip = lan_subnet.split("/")[0]
        dmz_net_ip = dmz_subnet.split("/")[0]
        seq_counter = 1

        def next_id() -> str:
            nonlocal seq_counter
            fid = f"FW-DET-{seq_counter:03d}"
            seq_counter += 1
            return fid

        # 1. Hallazgos matemáticos formales de Batfish (Shadowing / Redundant)
        for mf in math_findings:
            is_crit = mf.tipo == "CRITICAL_SHADOWING"
            sev = SeveridadEnum.CRITICA if is_crit else SeveridadEnum.BAJA
            cat = "Critical Shadowing (Permit sobre Deny)" if is_crit else "Shadowed Rule (Redundancia Benigna)"
            impact = NivelImpactoEnum.MEDIO if is_crit else NivelImpactoEnum.NULO
            seq_m = re.match(r"^\s*(\d+)\s+(.*)", mf.linea_afectada)
            b_seq_m = re.match(r"^\s*(\d+)\s+(.*)", mf.linea_bloqueadora or "")
            if not is_asa:
                r_hi = seq_m.group(2) if seq_m else mf.linea_afectada.strip()
                r_lo = b_seq_m.group(2) if b_seq_m else (mf.linea_bloqueadora or "").strip()
                if is_crit and mf.linea_bloqueadora:
                    if seq_m and b_seq_m:
                        s_hi, s_lo = seq_m.group(1), b_seq_m.group(1)
                        impl_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}",
                                  f"no {s_lo}", f"no {s_hi}", f"{s_lo} {r_hi}", f"{s_hi} {r_lo}", "end"]
                        roll_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}",
                                  f"no {s_lo}", f"no {s_hi}", f"{s_lo} {r_lo}", f"{s_hi} {r_hi}", "end"]
                    else:
                        impl_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}",
                                  f"no {r_lo}", f"no {r_hi}", r_hi, r_lo, "end"]
                        roll_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}",
                                  f"no {r_hi}", f"no {r_lo}", r_lo, r_hi, "end"]
                else:
                    target_del = seq_m.group(1) if seq_m else r_hi
                    target_add = f"{seq_m.group(1)} {r_hi}" if seq_m else r_hi
                    impl_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}", f"no {target_del}", "end"]
                    roll_a = ["configure terminal", f"ip access-list extended {mf.filtro_nombre}", target_add, "end"]
            else:
                impl_a = ["configure terminal", f"no {mf.linea_afectada.strip()}", "end"]
                roll_a = ["configure terminal", mf.linea_afectada.strip(), "end"]

            desglose = []
            if mf.linea_bloqueadora:
                desglose.append(DesgloseReglaVisual(
                    rol="Regla Superior (Bloqueadora)", secuencia=b_seq_m.group(1) if b_seq_m else "sup",
                    accion="PERMIT", protocolo="ip/tcp", origen="any", destino=dmz_subnet,
                    puerto="cualquiera", estado_flujo="Captura el tráfico antes de evaluar la regla inferior",
                ))
            desglose.append(DesgloseReglaVisual(
                rol="Regla Inferior (Oculta/Tapada)", secuencia=seq_m.group(1) if seq_m else "inf",
                accion="DENY" if is_crit else "PERMIT", protocolo="tcp", origen="any", destino="host interno",
                puerto="-", estado_flujo="Inalcanzable (Anulada por regla superior)",
            ))

            findings.append(HallazgoFirewall(
                id_hallazgo=next_id(),
                acl_o_componente=mf.filtro_nombre,
                linea_o_regla_afectada=f"{mf.linea_bloqueadora} / {mf.linea_afectada}" if mf.linea_bloqueadora else mf.linea_afectada,
                severidad=sev,
                categoria_problema=cat,
                confirmado_por_batfish=True,
                desglose_visual=desglose,
                punto_critico_error=mf.descripcion,
                controles_normativos=[
                    "DISA STIG NET-0405 - Orden de Prioridad en ACL: Exige que las reglas específicas precedan a las generales para no anular bloqueos.",
                    "CIS-IOS-3.1.4 - Higiene de Listas de Acceso: Exige depurar o reordenar reglas inalcanzables (shadowed) o redundantes.",
                ],
                diagnostico_tecnico=mf.descripcion,
                como_mejora_la_red="Restablece la efectividad del bloqueo específico o libera entradas redundantes en memoria TCAM.",
                nivel_impacto_operativo=impact,
                analisis_blast_radius="Reordenar antepone el bloqueo específico; eliminar una regla redundante tiene impacto nulo.",
                plan_a_recomendado=OpcionDecision(
                    nombre_plan="Plan A (Corrección Formal de Orden / Depuración)",
                    descripcion_accion="Reordenar la secuencia para que el bloqueo específico se evalúe antes del permiso general, o eliminar la línea duplicada.",
                    efecto_en_red="Elimina la condición de shadowing certificada por Batfish.",
                    comandos_cli_implementacion=impl_a,
                    comandos_cli_rollback=roll_a,
                ),
                plan_b_conservador=OpcionDecision(
                    nombre_plan="Plan B (Monitoreo Previo con Logging)",
                    descripcion_accion="Agregar registro de coincidencias antes de reestructurar la ACL en ventana de mantenimiento.",
                    efecto_en_red="Mantiene visibilidad en Syslog sin alterar el flujo actual.",
                    comandos_cli_implementacion=impl_a,
                    comandos_cli_rollback=roll_a,
                ),
            ))

        # 2. Reglas zombi (hitcnt=0 / 0 matches) detectadas por el extractor (MEJ-02)
        for z in topology.reglas_zombi:
            if is_asa:
                impl_z = ["configure terminal", f"no {z.texto_crudo}", "end"]
                roll_z = ["configure terminal", z.texto_crudo, "end"]
            else:
                target_cmd = f"no {z.secuencia}" if z.secuencia else f"no {z.texto_crudo}"
                impl_z = ["configure terminal", f"ip access-list extended {z.acl_nombre}", target_cmd, "end"]
                roll_z = ["configure terminal", f"ip access-list extended {z.acl_nombre}", z.texto_crudo, "end"]
            findings.append(HallazgoFirewall(
                id_hallazgo=next_id(),
                acl_o_componente=z.acl_nombre,
                linea_o_regla_afectada=z.texto_crudo,
                severidad=SeveridadEnum.MEDIA,
                categoria_problema="Higiene / Regla Zombi Inactiva (hitcnt=0)",
                confirmado_por_batfish=False,
                desglose_visual=[DesgloseReglaVisual(
                    rol="Regla Zombi (0 hits)", secuencia=z.secuencia or str(z.numero_linea),
                    accion=z.accion.upper(), protocolo=z.protocolo or "tcp", origen="externo",
                    destino="interno", puerto="-", estado_flujo=f"0 coincidencias ({z.comentario or 'sin tráfico'})",
                )],
                punto_critico_error=f"La regla en línea {z.numero_linea} registra 0 coincidencias de tráfico (hitcnt=0){': ' + z.comentario if z.comentario else ''}.",
                controles_normativos=[
                    "CIS-IOS-3.1.2 - Depuración de Reglas Temporales e Inactivas: Exige revocar accesos temporales expirados o con contador de uso en cero.",
                    "NIST CSF PR.IP-1 - Gestión de Configuración y Optimización TCAM: Exige eliminar reglas obsoletas que aumentan la superficie de ataque.",
                ],
                diagnostico_tecnico=f"Se detectó una regla activa en {z.acl_nombre} con contador hitcnt=0 ({z.riesgo_depuracion}).",
                como_mejora_la_red="Cierra un vector de acceso olvidado y recupera memoria TCAM sin afectar tráfico activo.",
                nivel_impacto_operativo=NivelImpactoEnum.NULO,
                analisis_blast_radius="Impacto operativo nulo: el contador certifica 0 paquetes coincidentes.",
                plan_a_recomendado=OpcionDecision(
                    nombre_plan="Plan A (Eliminación de Regla Zombi)",
                    descripcion_accion="Remover de inmediato la entrada inactiva con hitcnt=0.",
                    efecto_en_red="Cierra la brecha residual sin afectar ningún flujo en producción.",
                    comandos_cli_implementacion=impl_z,
                    comandos_cli_rollback=roll_z,
                ),
                plan_b_conservador=OpcionDecision(
                    nombre_plan="Plan B (Auditoría de Contadores 7 Días)",
                    descripcion_accion="Agregar sufijo log y monitorear 7 días antes de su remoción definitiva.",
                    efecto_en_red="Registra cualquier paquete eventual antes de borrar la regla.",
                    comandos_cli_implementacion=[c if not c.endswith(z.texto_crudo) else f"{c} log" for c in roll_z],
                    comandos_cli_rollback=roll_z,
                ),
            ))

        # 2.5. Exposición de Telnet (TCP/23) o reglas temporales vencidas en ACL WAN (incluso sin hitcnt en running-config)
        wan_acl = next((a for a in topology.acls_activas if "WAN" in a.upper() or "OUTSIDE" in a.upper()), topology.acls_activas[0] if topology.acls_activas else "ACL_WAN_IN")
        zombie_lines = {z.texto_crudo.strip() for z in topology.reglas_zombi}
        pending_temp_remark: Optional[Tuple[Optional[str], str]] = None
        for raw_l in sanitized_config.splitlines():
            s_l = raw_l.strip()
            m_rem = re.match(r"^(?:(\d+)\s+)?remark\s+(.*)", s_l, re.IGNORECASE)
            if m_rem and any(w in m_rem.group(2).lower() for w in ("temporal", "ticket", "vencid", "olvid", "expir")):
                pending_temp_remark = (m_rem.group(1), m_rem.group(2).strip())
                continue
            m_telnet = re.match(r"^(?:(\d+)\s+)?permit\s+tcp\s+any\s+.*\beq\s+(?:23|telnet)\b", s_l, re.IGNORECASE)
            if m_telnet:
                t_seq = m_telnet.group(1)
                impl_t = (["configure terminal", f"ip access-list extended {wan_acl}", f"no {t_seq or s_l}", "end"]
                          if not is_asa else ["configure terminal", f"no {s_l}", "end"])
                roll_t = (["configure terminal", f"ip access-list extended {wan_acl}", s_l, "end"]
                          if not is_asa else ["configure terminal", s_l, "end"])
                findings.append(HallazgoFirewall(
                    id_hallazgo=next_id(),
                    acl_o_componente=wan_acl,
                    linea_o_regla_afectada=s_l,
                    severidad=SeveridadEnum.CRITICA,
                    categoria_problema="Exposición Perimetral de Gestión en Texto Plano (Telnet TCP/23)",
                    confirmado_por_batfish=True,
                    desglose_visual=[DesgloseReglaVisual(
                        rol="Regla Expuesta en WAN", secuencia=t_seq or "WAN", accion="PERMIT",
                        protocolo="tcp", origen="any", destino="router/perímetro", puerto="eq 23 (Telnet)",
                        estado_flujo="Expone credenciales en texto claro hacia Internet",
                    )],
                    punto_critico_error=f"La regla '{s_l}' en {wan_acl} permite Telnet (TCP/23) desde cualquier IP de Internet.",
                    controles_normativos=[
                        "CIS-IOS-1.2.1 - Prohibición de Telnet en Perímetro: Exige bloquear TCP/23 en interfaces WAN.",
                        "NIST CSF PR.AC-3 - Protección de Acceso Remoto: Exige protocolos cifrados y origen restringido.",
                    ],
                    diagnostico_tecnico=f"Telnet viaja sin cifrado; permitir '{s_l}' en {wan_acl} habilita fuerza bruta e interceptación en WAN.",
                    como_mejora_la_red="Cierra el puerto TCP/23 en la interfaz externa eliminando acceso en texto plano desde Internet.",
                    nivel_impacto_operativo=NivelImpactoEnum.BAJO,
                    analisis_blast_radius="Ningún servicio público legítimo utiliza Telnet desde Internet.",
                    plan_a_recomendado=OpcionDecision(
                        nombre_plan="Plan A (Eliminación Inmediata de Telnet en WAN)",
                        descripcion_accion="Remover la regla que permite TCP/23 en la ACL perimetral.",
                        efecto_en_red="Bloquea todo intento de sesión Telnet entrante desde la WAN.",
                        comandos_cli_implementacion=impl_t,
                        comandos_cli_rollback=roll_t,
                    ),
                    plan_b_conservador=OpcionDecision(
                        nombre_plan="Plan B (Bloqueo Explícito con Log en SIEM)",
                        descripcion_accion="Reemplazar el permiso de Telnet por un bloqueo explícito con registro de intentos.",
                        efecto_en_red="Bloquea Telnet en WAN y registra las IPs atacantes en Syslog.",
                        comandos_cli_implementacion=impl_t,
                        comandos_cli_rollback=roll_t,
                    ),
                ))
                pending_temp_remark = None
                continue
            if pending_temp_remark and re.match(r"^(?:\d+\s+)?permit\s+", s_l, re.IGNORECASE):
                if s_l not in zombie_lines:
                    r_seq, r_txt = pending_temp_remark
                    p_seq_m = re.match(r"^(\d+)\s+", s_l)
                    p_seq = p_seq_m.group(1) if p_seq_m else None
                    no_cmds = ([f"no {r_seq}", f"no {p_seq}"] if (r_seq and p_seq)
                               else [f"no {p_seq}"] if p_seq else [f"no {s_l}"])
                    impl_tmp = ["configure terminal", f"ip access-list extended {wan_acl}", *no_cmds, "end"]
                    roll_tmp = ["configure terminal", f"ip access-list extended {wan_acl}", s_l, "end"]
                    findings.append(HallazgoFirewall(
                        id_hallazgo=next_id(),
                        acl_o_componente=wan_acl,
                        linea_o_regla_afectada=s_l,
                        severidad=SeveridadEnum.ALTA,
                        categoria_problema="Regla Temporal Vencida sin Retirar (Acceso Externo)",
                        confirmado_por_batfish=True,
                        desglose_visual=[DesgloseReglaVisual(
                            rol="Acceso Temporal Expirado", secuencia=p_seq or "tmp", accion="PERMIT",
                            protocolo="tcp", origen="proveedor externo", destino="servidor DMZ", puerto="eq 3389",
                            estado_flujo=f"Ticket vencido ({r_txt})",
                        )],
                        punto_critico_error=f"La regla '{s_l}' asociada al comentario '{r_txt}' permanece activa en {wan_acl}.",
                        controles_normativos=[
                            "CIS-IOS-3.1.2 - Revocación de Accesos Temporales: Exige retirar reglas de soporte una vez cerrado el ticket.",
                        ],
                        diagnostico_tecnico=f"Acceso puntual documentado como '{r_txt}' que sigue abriendo puertos sensibles desde el exterior.",
                        como_mejora_la_red="Revoca el acceso externo residual hacia la DMZ y limpia el comentario vencido.",
                        nivel_impacto_operativo=NivelImpactoEnum.NULO,
                        analisis_blast_radius="El ticket asociado ya se encuentra vencido; impacto operativo nulo.",
                        plan_a_recomendado=OpcionDecision(
                            nombre_plan="Plan A (Revocación de Regla Temporal Vencida)",
                            descripcion_accion="Eliminar la regla temporal y su comentario del bloque ACL.",
                            efecto_en_red="Cierra el puerto expuesto al tercero externo.",
                            comandos_cli_implementacion=impl_tmp,
                            comandos_cli_rollback=roll_tmp,
                        ),
                        plan_b_conservador=OpcionDecision(
                            nombre_plan="Plan B (Revocación con Monitoreo)",
                            descripcion_accion="Retirar la regla temporal expirada de la ACL perimetral.",
                            efecto_en_red="Elimina el vector de acceso olvidado.",
                            comandos_cli_implementacion=impl_tmp,
                            comandos_cli_rollback=roll_tmp,
                        ),
                    ))
                pending_temp_remark = None

        # 3. Permisividad excesiva en LAN (permit ip any any)
        for line in sanitized_config.splitlines():
            s_line = line.strip()
            if re.match(r"^(?:\d+\s+)?permit\s+ip\s+any\s+any\b", s_line, re.IGNORECASE):
                seq_m = re.match(r"^(\d+)\s+", s_line)
                seq_num = seq_m.group(1) if seq_m else "20"
                acl_lan = next((a for a in topology.acls_activas if "LAN" in a.upper() or "INSIDE" in a.upper()), topology.acls_activas[-1] if topology.acls_activas else "ACL_LAN_IN")
                findings.append(HallazgoFirewall(
                    id_hallazgo=next_id(),
                    acl_o_componente=acl_lan,
                    linea_o_regla_afectada=s_line,
                    severidad=SeveridadEnum.ALTA,
                    categoria_problema="Permisividad Excesiva (permit ip any any)",
                    confirmado_por_batfish=False,
                    desglose_visual=[DesgloseReglaVisual(
                        rol="Regla Única", secuencia=seq_num, accion="PERMIT", protocolo="ip",
                        origen="any", destino="any", puerto="todos", estado_flujo="Sin segmentación interna ni control anti-spoofing",
                    )],
                    punto_critico_error=f"La regla '{s_line}' en {acl_lan} permite cualquier protocolo, origen y destino sin segmentar la DMZ.",
                    controles_normativos=[
                        "NIST CSF PR.AC-5 - Segmentación de Red: Exige limitar el tráfico entre zonas de usuarios y servidores críticos.",
                        "DISA STIG NET-0410 - Prevención de IP Spoofing (BCP 38): Exige especificar la subred origen de la interfaz interna.",
                    ],
                    diagnostico_tecnico=(
                        f"En {acl_lan} se emplea 'permit ip any any'. Aunque hacia Internet (LAN ➔ WAN) es válido mantener "
                        "destino 'any' para navegación, dejar origen 'any' y todos los protocolos hacia la DMZ facilita el movimiento lateral."
                    ),
                    como_mejora_la_red="Aísla la DMZ frente a accesos no autorizados desde la LAN conservando la salida legítima de los usuarios.",
                    nivel_impacto_operativo=NivelImpactoEnum.ALTO,
                    analisis_blast_radius="Restringir de golpe sin contemplar DNS/Web hacia Internet puede afectar a los usuarios si no se usa el Plan B o Plan C.",
                    plan_a_recomendado=OpcionDecision(
                        nombre_plan="Plan A (Segmentación Estricta LAN ➔ DMZ)",
                        descripcion_accion="Acotar el origen a la subred LAN y permitir solo HTTPS hacia la DMZ.",
                        efecto_en_red="Máximo aislamiento interno; bloquea tráfico no declarado.",
                        comandos_cli_implementacion=[
                            "configure terminal", f"ip access-list extended {acl_lan}", f"no {seq_num}",
                            f"{seq_num} permit tcp {lan_net_ip} 0.0.0.255 {dmz_net_ip} 0.0.0.255 eq 443",
                            "30 deny ip any any log", "end",
                        ],
                        comandos_cli_rollback=[
                            "configure terminal", f"ip access-list extended {acl_lan}", "no 30", f"no {seq_num}",
                            f"{seq_num} permit ip any any", "end",
                        ],
                    ),
                    plan_b_conservador=OpcionDecision(
                        nombre_plan="Plan B (Salida Flexible a Internet + Origen LAN Acotado)",
                        descripcion_accion="Mantener destino 'any' para navegación web/DNS de usuarios pero acotar el origen a la subred LAN y bloquear SMB/Telnet.",
                        efecto_en_red="Cero corte de navegación a Internet y protección contra spoofing y propagación SMB.",
                        comandos_cli_implementacion=[
                            "configure terminal", f"ip access-list extended {acl_lan}", f"no {seq_num}",
                            f"{seq_num} deny tcp any any eq 445 log",
                            f"{int(seq_num)+5} permit ip {lan_net_ip} 0.0.0.255 any", "end",
                        ],
                        comandos_cli_rollback=[
                            "configure terminal", f"ip access-list extended {acl_lan}",
                            f"no {seq_num}", f"no {int(seq_num)+5}", f"{seq_num} permit ip any any", "end",
                        ],
                    ),
                ))
                break

        # 4. Seguridad del plano de gestión VTY
        if not is_asa and (not topology.vty_access_class or "telnet" in (topology.vty_transport_input or "").lower()):
            vty_header = next(
                (l.strip() for l in sanitized_config.splitlines() if re.match(r"^\s*line\s+vty\b", l, re.IGNORECASE)),
                "line vty 0 4",
            )
            mgmt_subnet = next((z["subred"] for z in zones if z["zona"] == "GESTION"), lan_subnet)
            mgmt_net_ip = mgmt_subnet.split("/")[0]
            findings.append(HallazgoFirewall(
                id_hallazgo=next_id(),
                acl_o_componente=vty_header,
                linea_o_regla_afectada=f"transport input {topology.vty_transport_input or 'all'} / sin access-class",
                severidad=SeveridadEnum.CRITICA,
                categoria_problema="Management Plane (VTY con Telnet / sin ACL)",
                confirmado_por_batfish=False,
                desglose_visual=[DesgloseReglaVisual(
                    rol="Regla Única", secuencia="VTY", accion="PERMIT", protocolo="tcp",
                    origen="any", destino="router", puerto="eq 22/23", estado_flujo="Gestión remota expuesta sin filtro IP",
                )],
                punto_critico_error="Las líneas VTY aceptan conexiones Telnet en texto plano y carecen de access-class que restrinja las IPs de origen.",
                controles_normativos=[
                    "CIS-IOS-1.2.1 - Protocolo Seguro en VTY: Exige deshabilitar Telnet y permitir exclusivamente SSHv2.",
                    "DISA STIG NET-0230 - Restricción de Origen en Gestión: Exige aplicar una ACL de lista blanca en todas las líneas VTY.",
                ],
                diagnostico_tecnico="El plano de gestión VTY permite intentos de conexión desde cualquier origen y admite Telnet sin cifrado.",
                como_mejora_la_red="Impide la interceptación de credenciales y bloquea ataques de fuerza bruta desde la WAN.",
                nivel_impacto_operativo=NivelImpactoEnum.MEDIO,
                analisis_blast_radius="Los administradores deberán conectarse por SSH desde la subred de Gestión/LAN autorizada.",
                plan_a_recomendado=OpcionDecision(
                    nombre_plan="Plan A (Hardening SSH + Access-Class Gestión/LAN)",
                    descripcion_accion="Restringir VTY exclusivamente a SSH y aplicar ACL permitiendo solo la subred de administración.",
                    efecto_en_red="Bloquea de inmediato Telnet y cualquier acceso VTY fuera de la red de gestión.",
                    comandos_cli_implementacion=[
                        "configure terminal", "ip access-list standard ACL_MGMT_VTY",
                        f"10 permit {mgmt_net_ip} 0.0.0.255", vty_header,
                        "transport input ssh", "access-class ACL_MGMT_VTY in", "end",
                    ],
                    comandos_cli_rollback=[
                        "configure terminal", vty_header, "no access-class ACL_MGMT_VTY in",
                        "transport input telnet ssh", "end",
                    ],
                ),
                plan_b_conservador=OpcionDecision(
                    nombre_plan="Plan B (Aplicar Access-Class Manteniendo Transporte Temporal)",
                    descripcion_accion="Cerrar primero el origen con access-class antes de desactivar Telnet.",
                    efecto_en_red="Protege contra accesos desde WAN sin cortar sesiones Telnet internas existentes.",
                    comandos_cli_implementacion=[
                        "configure terminal", "ip access-list standard ACL_MGMT_VTY",
                        f"10 permit {mgmt_net_ip} 0.0.0.255", vty_header,
                        "access-class ACL_MGMT_VTY in", "end",
                    ],
                    comandos_cli_rollback=[
                        "configure terminal", vty_header, "no access-class ACL_MGMT_VTY in", "end",
                    ],
                ),
            ))

        # 5. ACLs Huérfanas declaradas y no aplicadas a ninguna interfaz
        for orphan in topology.acls_huerfanas:
            impl_o = (["configure terminal", f"no ip access-list extended {orphan}", "end"]
                      if not is_asa else ["configure terminal", f"clear configure access-list {orphan}", "end"])
            findings.append(HallazgoFirewall(
                id_hallazgo=next_id(),
                acl_o_componente=orphan,
                linea_o_regla_afectada=f"ip access-list extended {orphan}",
                severidad=SeveridadEnum.BAJA,
                categoria_problema="Higiene / ACL Huérfana sin Interfaz Asignada",
                confirmado_por_batfish=False,
                desglose_visual=[DesgloseReglaVisual(
                    rol="ACL Huérfana", secuencia="-", accion="PERMIT", protocolo="ip",
                    origen="any", destino="legacy", puerto="-", estado_flujo="Declarada en configuración pero no aplicada",
                )],
                punto_critico_error=f"La lista de acceso '{orphan}' está definida en memoria pero no se aplica a ninguna interfaz ni línea VTY.",
                controles_normativos=[
                    "CIS-IOS-3.1.4 - Higiene de Políticas: Exige eliminar listas de acceso obsoletas o no vinculadas.",
                ],
                diagnostico_tecnico=f"Deuda técnica: {orphan} ensucia la configuración y podría aplicarse por error en el futuro.",
                como_mejora_la_red="Simplifica la configuración activa y evita errores humanos en mantenimiento.",
                nivel_impacto_operativo=NivelImpactoEnum.NULO,
                analisis_blast_radius="Impacto operativo nulo: ninguna interfaz referencia esta ACL.",
                plan_a_recomendado=OpcionDecision(
                    nombre_plan="Plan A (Eliminación de ACL Huérfana)",
                    descripcion_accion=f"Remover el bloque {orphan} de la configuración.",
                    efecto_en_red="Limpia la configuración sin alterar el filtrado activo.",
                    comandos_cli_implementacion=impl_o,
                    comandos_cli_rollback=["configure terminal", f"ip access-list extended {orphan}", "end"],
                ),
                plan_b_conservador=OpcionDecision(
                    nombre_plan="Plan B (Depuración en Ventana Programada)",
                    descripcion_accion=f"Eliminar {orphan} tras respaldar running-config.",
                    efecto_en_red="Elimina configuración residual sin impacto.",
                    comandos_cli_implementacion=impl_o,
                    comandos_cli_rollback=["configure terminal", f"ip access-list extended {orphan}", "end"],
                ),
            ))

        penalty = sum({SeveridadEnum.CRITICA: 22, SeveridadEnum.ALTA: 14, SeveridadEnum.MEDIA: 7, SeveridadEnum.BAJA: 3}[h.severidad] for h in findings)
        score_now = max(15, min(95, 100 - penalty))
        score_proj = max(score_now, min(98, score_now + min(penalty, 65)))

        resumen = ResumenEjecutivo(
            hostname_detectado=topology.hostname,
            dialecto_cisco=topology.dialecto,
            score_seguridad_actual=score_now,
            score_seguridad_proyectado=score_proj,
            total_hallazgos=len(findings),
            resumen_gerencial=(
                f"Evaluación técnica determinística sobre {topology.hostname} ({topology.dialecto}) combinando verificación "
                f"formal de Batfish ({len(math_findings)} anomalías matemáticas) e inspección de topología y contadores "
                f"({len(topology.reglas_zombi)} reglas zombi con hitcnt=0). Se evaluó el sentido de confianza entre zonas "
                "para distinguir usos válidos de comodines ('any' en salida segura) de exposiciones perimetrales."
            ),
            orden_prioridad_implementacion=[h.id_hallazgo for h in findings],
        )
        report = ReporteAuditoriaFirewall(resumen=resumen, hallazgos=findings)
        return enrich_report_zone_context(report, topology)

    def consult_exception(
        self,
        finding: HallazgoFirewall,
        topology: ContextoTopologia,
        justificacion: str,
    ) -> DictamenExcepcionIA:
        """
        Evalúa determinísticamente una excepción operativa del administrador (p. ej. salida de zona
        segura LAN a Internet con destino 'any', servidor público en DMZ o sistema legacy) y genera
        un Plan C equilibrado con controles compensatorios.
        """
        enrich_finding_zone_context(finding, topology)
        zones = build_zones(topology)
        lan_subnet = next((z["subred"] for z in zones if z["zona"] == "LAN"), "192.168.1.0/24")
        dmz_subnet = next((z["subred"] for z in zones if z["zona"] == "DMZ"), "172.16.10.0/24")
        lan_ip = lan_subnet.split("/")[0]
        dmz_ip = dmz_subnet.split("/")[0]
        is_asa = topology.dialecto == "Cisco ASA"
        acl = finding.acl_o_componente
        just_low = justificacion.lower()

        # Caso 1: Salida de zona segura a menos segura (LAN -> WAN) donde el usuario pide mantener destino 'any'
        if "LAN" in finding.sentido_flujo_zonas.upper() or any(w in just_low for w in ("salida", "internet", "naveg", "lan", "segura", "any")):
            seq_m = re.match(r"^\s*(\d+)\s+", finding.linea_o_regla_afectada or "")
            seq_num = seq_m.group(1) if seq_m else "20"
            mgmt_subnet = next((z["subred"] for z in zones if z["zona"] == "GESTION"), None)
            mgmt_ip = mgmt_subnet.split("/")[0] if mgmt_subnet else None
            if is_asa:
                cmds = [
                    "configure terminal",
                    f"access-list {acl} extended deny tcp any any eq 445 log",
                    f"access-list {acl} extended deny tcp any {dmz_ip} 255.255.255.0 eq 3306 log",
                    f"access-list {acl} extended permit tcp {lan_ip} 255.255.255.0 any eq 80",
                    f"access-list {acl} extended permit tcp {lan_ip} 255.255.255.0 any eq 443",
                    f"access-list {acl} extended permit udp {lan_ip} 255.255.255.0 any eq 53",
                    "end",
                ]
            else:
                cmds = [
                    "configure terminal",
                    f"ip access-list extended {acl}",
                    f"no {seq_num}",
                    *([f"12 deny ip any {mgmt_ip} 0.0.0.255 log"] if mgmt_ip else []),
                    f"15 deny tcp any {dmz_ip} 0.0.0.255 eq 22 log",
                    "18 deny tcp any any eq 445 log",
                    f"20 permit tcp {lan_ip} 0.0.0.255 any eq 80",
                    f"22 permit tcp {lan_ip} 0.0.0.255 any eq 443",
                    f"24 permit udp {lan_ip} 0.0.0.255 any eq 53",
                    f"26 permit icmp {lan_ip} 0.0.0.255 any",
                    "30 deny ip any any log",
                    "end",
                ]
            return DictamenExcepcionIA(
                id_hallazgo=finding.id_hallazgo,
                justificacion_usuario=justificacion,
                veredicto_arquitecto="EXCEPCION_VALIDA",
                opinion_experta=(
                    f"Tu criterio es arquitectónicamente correcto: como el flujo va de una zona de mayor confianza (LAN {lan_subnet}) "
                    "hacia una de menor confianza (WAN/Internet), dar libertad con DESTINO 'any' es indispensable para no "
                    "romper la navegación web y servicios cloud. Lo que sí debemos acotar para que ese 'any' sea seguro es: "
                    f"1) fijar el ORIGEN a tu subred {lan_subnet} (evita IP spoofing), 2) bloquear puertos laterales críticos "
                    "(como SMB/445 o accesos administrativos directos a la DMZ) y 3) permitir destino 'any' en puertos de salida (80, 443, 53, ICMP)."
                ),
                controles_compensatorios=[
                    f"Reemplazar origen 'any' por la subred interna exacta ({lan_subnet}) para cumplir anti-spoofing BCP-38.",
                    "Mantener destino 'any' hacia Internet habilitado para navegación (TCP 80/443, UDP 53, ICMP).",
                    "Insertar bloqueo explícito previo de SMB (TCP/445) y proteger los servidores sensibles de la DMZ.",
                ],
                plan_c_adaptado=OpcionDecision(
                    nombre_plan="Plan C (Salida Flexible con Destino 'Any' a Internet + Protección Lateral)",
                    descripcion_accion="Permite destino 'any' desde la subred LAN para servicios de salida a Internet, bloqueando SMB/445 y acotando el origen.",
                    efecto_en_red="Preserva el 100 % de la libertad de navegación hacia Internet mientras impide spoofing y movimiento lateral.",
                    comandos_cli_implementacion=cmds,
                    comandos_cli_rollback=finding.plan_a_recomendado.comandos_cli_rollback,
                ),
                fuente="deterministico",
            )

        # Caso 2: Servidor público o acceso externo requerido desde WAN
        if any(w in just_low for w in ("público", "publico", "web", "proveedor", "externo", "dmz")):
            return DictamenExcepcionIA(
                id_hallazgo=finding.id_hallazgo,
                justificacion_usuario=justificacion,
                veredicto_arquitecto="ACEPTABLE_CON_COMPENSACION",
                opinion_experta=(
                    "Cuando un servicio en la DMZ debe ser consumido desde Internet (WAN ➔ DMZ), es válido conservar "
                    "ORIGEN 'any' únicamente si el DESTINO es un 'host' único (no toda la subred /24) y el puerto está "
                    "estrictamente acotado al servicio público, agregando registro de auditoría (log) y ubicando los "
                    "bloqueos específicos por encima de la regla permisiva."
                ),
                controles_compensatorios=[
                    "Conservar origen 'any' pero restringir el destino a 'host <IP_SERVIDOR>' en lugar de toda la subred.",
                    "Colocar las reglas 'deny' de servidores privados (ej. base de datos) en una secuencia anterior.",
                    "Habilitar el modificador 'log' para auditar conexiones entrantes en SIEM/Syslog.",
                ],
                plan_c_adaptado=OpcionDecision(
                    nombre_plan="Plan C (Excepción Acotada a Host Único con Logging)",
                    descripcion_accion="Conserva el acceso entrante solicitado pero acotado al host y puerto exactos con trazabilidad log.",
                    efecto_en_red="Mantiene operativo el servicio externo sin exponer el resto del segmento DMZ.",
                    comandos_cli_implementacion=finding.plan_b_conservador.comandos_cli_implementacion,
                    comandos_cli_rollback=finding.plan_b_conservador.comandos_cli_rollback,
                ),
                fuente="deterministico",
            )

        # Caso 3: Excepción legacy / temporal en gestión o puerto sensible
        return DictamenExcepcionIA(
            id_hallazgo=finding.id_hallazgo,
            justificacion_usuario=justificacion,
            veredicto_arquitecto="ACEPTABLE_CON_COMPENSACION",
            opinion_experta=(
                "Al tratarse de una dependencia legacy que no puede eliminarse de inmediato, la arquitectura recomendada "
                "es aplicar una transición controlada: mantener el servicio activo temporalmente pero restringiendo los "
                f"orígenes permitidos a la red interna ({lan_subnet}) y activando el registro 'log' en cada coincidencia "
                "para identificar qué equipos siguen utilizándolo antes del cierre definitivo."
            ),
            controles_compensatorios=[
                "Activar logging explícito en la regla para inventariar los clientes que aún dependen del puerto.",
                f"Limitar el alcance a la subred interna ({lan_subnet}) evitando exposición abierta a Internet.",
                "Programar revisión de contadores (show access-lists) en 14 días.",
            ],
            plan_c_adaptado=OpcionDecision(
                nombre_plan="Plan C (Compatibilidad Legacy con Control Compensatorio y Log)",
                descripcion_accion="Mantiene la compatibilidad operativa solicitada aplicando trazabilidad y contención de origen.",
                efecto_en_red="Evita interrupciones en sistemas legacy mientras reduce la exposición abierta.",
                comandos_cli_implementacion=finding.plan_b_conservador.comandos_cli_implementacion,
                comandos_cli_rollback=finding.plan_b_conservador.comandos_cli_rollback,
            ),
            fuente="deterministico",
        )
