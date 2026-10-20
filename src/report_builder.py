import json
from pathlib import Path
from typing import Dict, Any
from src.models import ReporteAuditoriaFirewall, ContextoTopologia
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
        lines = [
            f"# Informe de Auditoría de Seguridad & Gestión de Cambios",
            f"**Dispositivo:** `{res.hostname_detectado}` | **Dialecto:** `{res.dialecto_cisco}`  ",
            f"**Postura de Seguridad Actual:** `{res.score_seguridad_actual}/100` ➔ **Proyectada tras Mitigación:** `{res.score_seguridad_proyectado}/100`  ",
            f"**Total de Hallazgos Identificados:** `{res.total_hallazgos}`",
            "",
            "---",
            "",
            "## 1. Resumen Ejecutivo y Gerencial",
            res.resumen_gerencial,
            "",
            "### Orden Recomendado de Implementación (Impacto Cero / Transición)",
            "Para minimizar cualquier riesgo de corte, se recomienda aplicar las remediaciones en el siguiente orden:",
        ]

        for idx, finding_id in enumerate(res.orden_prioridad_implementacion, 1):
            lines.append(f"{idx}. `{finding_id}`")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Mapa Topológico y Contexto Auditado",
            f"* **Total de Líneas de Configuración:** {topo.total_lineas_config}",
            f"* **ACLs Activas en Interfaces/VTY:** {', '.join(f'`{a}`' for a in topo.acls_activas) if topo.acls_activas else 'Ninguna'}",
            f"* **ACLs Huérfanas (Sin Uso Activo):** {', '.join(f'`{a}`' for a in topo.acls_huerfanas) if topo.acls_huerfanas else 'Ninguna'}",
            f"* **Protección VTY (Line 0-15):** Transport: `{topo.vty_transport_input or 'Inseguro/No configurado'}` | Access-Class: `{topo.vty_access_class or 'Ninguna'}`",
            "",
            "### Interfaces Auditadas:",
            "| Interfaz | Descripción / Nameif | IP Asignada | Security Level | ACL Entrada | ACL Salida |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for iface_name, iface in topo.interfaces.items():
            lines.append(
                f"| `{iface_name}` | {iface.descripcion or 'N/D'} | `{iface.ip_address or 'N/D'}` | "
                f"{iface.security_level if iface.security_level is not None else 'N/D'} | "
                f"`{iface.acl_in or '-'}` | `{iface.acl_out or '-'}` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 3. Matriz de Hallazgos y Severidad",
            "| ID | Componente / ACL | Severidad | Categoría | Validado Batfish | Impacto Operativo (Blast Radius) |",
            "| :--- | :--- | :--- | :--- | :---: | :--- |",
        ])

        for h in r.hallazgos:
            batfish_icon = "✅" if h.confirmado_por_batfish else "⚠️ Semántico"
            lines.append(
                f"| `{h.id_hallazgo}` | `{h.acl_o_componente}` | **{h.severidad.value}** | "
                f"{h.categoria_problema} | {batfish_icon} | {h.nivel_impacto_operativo.value} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 4. Fichas Detalladas de Hallazgos y Planes de Mitigación",
        ])

        for h in r.hallazgos:
            lines.extend([
                f"### Hallazgo `{h.id_hallazgo}`: {h.categoria_problema} en `{h.acl_o_componente}`",
                f"* **Regla Afectada:** `{h.linea_o_regla_afectada}`",
                f"* **Severidad:** `{h.severidad.value}` | **Impacto Operativo:** `{h.nivel_impacto_operativo.value}`",
                "",
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
                "#### Opciones de Decisión:",
                "",
                f"**A) {h.plan_a_recomendado.nombre_plan}:**  ",
                f"*Descripción:* {h.plan_a_recomendado.descripcion_accion}  ",
                f"*Efecto en Red:* {h.plan_a_recomendado.efecto_en_red}",
                "```cisco",
                "\n".join(h.plan_a_recomendado.comandos_cli_implementacion),
                "```",
                "",
                f"**B) {h.plan_b_conservador.nombre_plan}:**  ",
                f"*Descripción:* {h.plan_b_conservador.descripcion_accion}  ",
                f"*Efecto en Red:* {h.plan_b_conservador.efecto_en_red}",
                "```cisco",
                "\n".join(h.plan_b_conservador.comandos_cli_implementacion),
                "```",
                "",
                "**Comandos de Rollback Inmediato:**",
                "```cisco",
                "\n".join(h.plan_a_recomendado.comandos_cli_rollback),
                "```",
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
