from collections import Counter
from pathlib import Path
from typing import Dict, Any
from src.models import ReporteAuditoriaFirewall, ContextoTopologia
from src.prioritization import ordered_findings, rank_findings
from src.sanitizer import ConfigSanitizer


class ReportBuilder:
    """
    Generador de informes técnicos, ejecutivos y scripts Cisco CLI de remediación y rollback.
    Aplica de-sanitización local para restaurar las IPs y secretos reales en los entregables.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def desanitize_report(self, report: ReporteAuditoriaFirewall, lookup_map: Dict[str, Any]) -> ReporteAuditoriaFirewall:
        """Aplica la tabla de mapeo local a todo el reporte estructurado."""
        report_json = report.model_dump_json()
        desanitized_json = ConfigSanitizer.desanitize(report_json, lookup_map)
        return ReporteAuditoriaFirewall.model_validate_json(desanitized_json)

    def generate_all(
        self,
        report: ReporteAuditoriaFirewall,
        topology: ContextoTopologia,
        lookup_map: Dict[str, Any],
        base_name: str,
    ) -> Dict[str, Path]:
        """Genera el informe Markdown, scripts .cli y el JSON completo."""
        desanitized_report = self.desanitize_report(report, lookup_map)

        md_path = self.output_dir / f"auditoria_{base_name}.md"
        json_path = self.output_dir / f"auditoria_{base_name}.json"
        remediation_cli_path = self.output_dir / f"remediacion_{base_name}.cli"
        rollback_cli_path = self.output_dir / f"rollback_{base_name}.cli"

        # 1. Guardar JSON
        json_path.write_text(desanitized_report.model_dump_json(indent=2), encoding="utf-8")

        # 2. Generar Markdown
        md_content = self._render_markdown(desanitized_report, topology)
        md_content = ConfigSanitizer.desanitize(md_content, lookup_map)
        md_path.write_text(md_content, encoding="utf-8")

        # 3. Generar scripts CLI
        rem_cli, roll_cli = self._render_cli_scripts(desanitized_report, base_name)
        remediation_cli_path.write_text(rem_cli, encoding="utf-8")
        rollback_cli_path.write_text(roll_cli, encoding="utf-8")

        return {
            "markdown": md_path,
            "json": json_path,
            "remediation_cli": remediation_cli_path,
            "rollback_cli": rollback_cli_path,
        }

    def _render_markdown(self, r: ReporteAuditoriaFirewall, topo: ContextoTopologia) -> str:
        res = r.resumen
        ranked = rank_findings(r)
        ordered = ordered_findings(r)
        sev_counts = Counter(h.severidad.value for h in r.hallazgos)
        total_h = len(r.hallazgos) or 1
        gain_total = res.score_seguridad_proyectado - res.score_seguridad_actual

        lines = [
            "# Informe de Auditoría de Seguridad de Red y Gestión de Cambios",
            "> **Clasificación:** `TLP:AMBER · CONFIDENCIAL` | **Verificación Formal:** `Batfish Digital Twin` | **Marcos:** `CIS · DISA STIG · NIST CSF`",
            "",
            f"**Dispositivo:** `{res.hostname_detectado}` | **Dialecto:** `{res.dialecto_cisco}`  ",
            f"**Postura de Seguridad Actual:** `{res.score_seguridad_actual}/100` ➔ **Proyectada tras Mitigación:** `{res.score_seguridad_proyectado}/100` (`+{gain_total} pts`)  ",
            f"**Total de Hallazgos Identificados:** `{res.total_hallazgos}`",
            "",
            "---",
            "",
            "## 1. Resumen Ejecutivo y Dictamen de Postura",
            res.resumen_gerencial,
            "",
            "### 1.1 Resumen de Hallazgos por Nivel de Severidad",
            "| Severidad | Cantidad | % del Total | SLA Sugerido |",
            "| :--- | :---: | :---: | :--- |",
            f"| **CRITICA** | {sev_counts.get('CRITICA', 0)} | {(sev_counts.get('CRITICA', 0) * 100 / total_h) if r.hallazgos else 0:.1f}% | Inmediata (< 24 h) |",
            f"| **ALTA** | {sev_counts.get('ALTA', 0)} | {(sev_counts.get('ALTA', 0) * 100 / total_h) if r.hallazgos else 0:.1f}% | Urgente (< 72 h) |",
            f"| **MEDIA** | {sev_counts.get('MEDIA', 0)} | {(sev_counts.get('MEDIA', 0) * 100 / total_h) if r.hallazgos else 0:.1f}% | Planificada (< 14 días) |",
            f"| **BAJA** | {sev_counts.get('BAJA', 0)} | {(sev_counts.get('BAJA', 0) * 100 / total_h) if r.hallazgos else 0:.1f}% | Mantenimiento (< 30 días) |",
            "",
            "---",
            "",
            "## 2. Alcance Técnico, Metodología y Topología Auditada",
            f"* **Total de Líneas de Configuración:** {topo.total_lineas_config}",
            f"* **ACLs Activas en Interfaces/VTY:** {', '.join(f'`{a}`' for a in topo.acls_activas) if topo.acls_activas else 'Ninguna'}",
            f"* **ACLs Huérfanas (Sin Uso Activo):** {', '.join(f'`{a}`' for a in topo.acls_huerfanas) if topo.acls_huerfanas else 'Ninguna'}",
            f"* **Protección VTY (Line 0-15):** Transport: `{topo.vty_transport_input or 'Inseguro/No configurado'}` | Access-Class: `{topo.vty_access_class or 'Ninguna'}`",
            "",
            "### Interfaces Auditadas:",
            "| Interfaz | Descripción / Nameif | IP Asignada | Máscara | Security Level | ACL Entrada | ACL Salida |",
            "| :--- | :--- | :--- | :--- | :---: | :--- | :--- |",
        ]

        for iface_name, iface in topo.interfaces.items():
            lines.append(
                f"| `{iface_name}` | {iface.descripcion or 'N/D'} | `{iface.ip_address or 'N/D'}` | "
                f"`{iface.mascara or 'N/D'}` | "
                f"{iface.security_level if iface.security_level is not None else 'N/D'} | "
                f"`{iface.acl_in or '-'}` | `{iface.acl_out or '-'}` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Matriz de Priorización Top-Down y Hoja de Ruta",
            "| # | ID | Componente / ACL | Severidad | Categoría | Validado Batfish | Impacto Operativo (Blast Radius) | Pts Plan A |",
            "| :---: | :--- | :--- | :--- | :--- | :---: | :--- | :---: |",
        ])

        gains_map = {item["id"]: item["ganancia_a"] for item in ranked}
        for pos, h in enumerate(ordered, 1):
            batfish_icon = "✅" if h.confirmado_por_batfish else "⚠️ Semántico"
            lines.append(
                f"| **{pos}** | `{h.id_hallazgo}` | `{h.acl_o_componente}` | **{h.severidad.value}** | "
                f"{h.categoria_problema} | {batfish_icon} | {h.nivel_impacto_operativo.value} | +{gains_map.get(h.id_hallazgo, 0):.2f} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Fichas Técnicas Detalladas de Hallazgos y Planes de Mitigación",
        ])

        for pos, h in enumerate(ordered, 1):
            lines.extend([
                f"### 4.{pos} [Prioridad #{pos}] Hallazgo `{h.id_hallazgo}`: {h.categoria_problema} en `{h.acl_o_componente}`",
                f"* **Regla Afectada:** `{h.linea_o_regla_afectada}`",
                f"* **Severidad:** `{h.severidad.value}` | **Verificación:** `{'Confirmado por Batfish' if h.confirmado_por_batfish else 'Semántico (IA)'}` | **Impacto Operativo:** `{h.nivel_impacto_operativo.value}`",
                "",
            ])

            # Desglose visual de reglas
            if h.desglose_visual:
                titulo_tabla = "📊 Comparativa y Colisión de Reglas:" if len(h.desglose_visual) > 1 else "📊 Desglose de la Regla Afectada:"
                lines.extend([
                    f"#### {titulo_tabla}",
                    "| Rol de la Regla | Línea | Acción | Protocolo | Origen | Destino | Puerto | Estado del Flujo |",
                    "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |",
                ])
                for r_vis in h.desglose_visual:
                    accion_badge = f"🟢 `{r_vis.accion.upper()}`" if "permit" in r_vis.accion.lower() else f"🔴 `{r_vis.accion.upper()}`"
                    lines.append(
                        f"| **{r_vis.rol}** | `{r_vis.secuencia}` | {accion_badge} | `{r_vis.protocolo}` | "
                        f"`{r_vis.origen}` | `{r_vis.destino}` | `{r_vis.puerto}` | {r_vis.estado_flujo} |"
                    )
                lines.append("")

            # Alerta destacando el punto crítico del choque
            if h.punto_critico_error:
                lines.extend([
                    f"> ⚠️ **Punto Crítico del Error:** {h.punto_critico_error}",
                    "",
                ])

            lines.extend([
                "**Controles Normativos Incumplidos (Estándares de Seguridad):**",
            ])

            if h.controles_normativos:
                for c in h.controles_normativos:
                    lines.append(f"* 🛡️ {c}")
            else:
                lines.append("* 🛡️ Sin controles específicos asignados.")

            lines.extend([
                "",
                f"**Diagnóstico Técnico:**  ",
                f"{h.diagnostico_tecnico}",
                "",
                f"**Cómo Mejora la Red:**  ",
                f"{h.como_mejora_la_red}",
                "",
                f"**Análisis de Blast Radius (Efectos Colaterales):**  ",
                f"{h.analisis_blast_radius}",
                "",
                "---",
            ])

        return "\n".join(lines)

    def _render_cli_scripts(self, r: ReporteAuditoriaFirewall, base_name: str) -> tuple[str, str]:
        rem_lines = [
            f"! =====================================================================",
            f"! SCRIPT DE REMEDIACIÓN PARA CISCO: {r.resumen.hostname_detectado}",
            f"! Generado por Cisco AI Firewall Auditor & Change Impact Advisor",
            f"! =====================================================================",
            f"! ADVERTENCIA: Verifique las opciones de Plan A (Directo) y Plan B (Monitoreo)",
            f"! =====================================================================",
            "configure terminal",
            "",
        ]

        roll_lines = [
            f"! =====================================================================",
            f"! SCRIPT DE ROLLBACK PARA CISCO: {r.resumen.hostname_detectado}",
            f"! Ejecute estos comandos si experimenta interrupción de servicios",
            f"! =====================================================================",
            "configure terminal",
            "",
        ]

        for h in r.hallazgos:
            rem_lines.append(f"! --- Hallazgo {h.id_hallazgo}: {h.categoria_problema} ---")
            rem_lines.append(f"! [PLAN A - RECOMENDADO]")
            for cmd in h.plan_a_recomendado.comandos_cli_implementacion:
                rem_lines.append(cmd)
            rem_lines.append(f"! [PLAN B - ALTERNATIVA DE MONITOREO SI SE PREFIERE TRANSICIÓN]")
            for cmd in h.plan_b_conservador.comandos_cli_implementacion:
                rem_lines.append(f"! {cmd}")
            rem_lines.append("")

            roll_lines.append(f"! --- Rollback para {h.id_hallazgo} ---")
            for cmd in h.plan_a_recomendado.comandos_cli_rollback:
                roll_lines.append(cmd)
            roll_lines.append("")

        rem_lines.extend(["end", "! write memory"])
        roll_lines.extend(["end", "! write memory"])

        return "\n".join(rem_lines), "\n".join(roll_lines)
