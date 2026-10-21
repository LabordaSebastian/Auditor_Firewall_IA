"""Generador de reportes PDF corporativos (MEJ-05 / RF-09) con fpdf2 (Python puro)."""
import datetime
from collections import Counter
from typing import Dict, List, Tuple

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from src.models import ContextoTopologia, ReporteAuditoriaFirewall

SEV_COLORS: Dict[str, Tuple[int, int, int]] = {
    "CRITICA": (220, 53, 69), "ALTA": (253, 126, 20), "MEDIA": (255, 193, 7), "BAJA": (32, 163, 130),
}
PALETTE: List[Tuple[int, int, int]] = [
    (220, 53, 69), (253, 126, 20), (255, 193, 7), (32, 163, 130), (70, 130, 180), (111, 66, 193), (0, 180, 216),
]
NAVY = (15, 23, 42)
SLATE = (71, 85, 105)


def _s(text: object) -> str:
    """Convierte a latin-1 (fuentes core de PDF) reemplazando símbolos no soportados."""
    replacements = {"➔": "->", "—": "-", "–": "-", "…": "...", "“": '"', "”": '"', "‘": "'", "’": "'", "•": "-"}
    out = str(text)
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out.encode("latin-1", "replace").decode("latin-1")


class ExecutivePDFReport(FPDF):
    def __init__(self, hostname: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.hostname = _s(hostname)
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(15, 18, 15)

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*SLATE)
        self.cell(0, 6, _s(f"Cisco AI Firewall Auditor - {self.hostname}"), align="L")
        self.cell(0, 6, "CONFIDENCIAL", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(203, 213, 225)
        self.line(15, 15, 195, 15)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*SLATE)
        self.cell(0, 8, f"Pagina {self.page_no()}", align="C")

    # ---------------------------------------------------------------- helpers
    def h1(self, text: str) -> None:
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(*NAVY)
        self.cell(0, 9, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(14, 165, 233)
        self.set_line_width(0.6)
        self.line(15, self.get_y(), 60, self.get_y())
        self.set_line_width(0.2)
        self.ln(4)

    def para(self, text: str, size: int = 10, bold: bool = False) -> None:
        self.set_font("Helvetica", "B" if bold else "", size)
        self.set_text_color(30, 41, 59)
        self.multi_cell(0, 5, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def code(self, lines: List[str]) -> None:
        self.set_font("Courier", "", 8)
        self.set_fill_color(241, 245, 249)
        self.set_text_color(15, 23, 42)
        self.multi_cell(0, 4.2, _s("\n".join(lines) or "-"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def donut(self, cx: float, cy: float, radius: float, data: List[Tuple[str, int, Tuple[int, int, int]]]) -> None:
        total = sum(v for _, v, _ in data) or 1
        angle = -90.0
        for _, value, color in data:
            sweep = 360.0 * value / total
            if sweep <= 0:
                continue
            self.set_fill_color(*color)
            self.solid_arc(cx - radius, cy - radius, radius * 2, radius * 2, angle, angle + sweep, style="F")
            angle += sweep
        self.set_fill_color(255, 255, 255)
        self.ellipse(cx - radius * 0.58, cy - radius * 0.58, radius * 1.16, radius * 1.16, style="F")
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*NAVY)
        self.text(cx - 3.5, cy + 1.5, str(sum(v for _, v, _ in data)))

    def legend(self, x: float, y: float, data: List[Tuple[str, int, Tuple[int, int, int]]]) -> None:
        total = sum(v for _, v, _ in data) or 1
        self.set_font("Helvetica", "", 8)
        for i, (label, value, color) in enumerate(data):
            yy = y + i * 5.2
            self.set_fill_color(*color)
            self.rect(x, yy, 3, 3, style="F")
            self.set_text_color(30, 41, 59)
            self.text(x + 5, yy + 2.6, _s(f"{label[:34]}  {value} ({value * 100 / total:.1f}%)"))


def build_pdf(report: ReporteAuditoriaFirewall, topology: ContextoTopologia) -> bytes:
    """Genera el informe ejecutivo PDF (portada, resumen, distribucion de riesgo, hallazgos)."""
    res = report.resumen
    pdf = ExecutivePDFReport(res.hostname_detectado)

    # Portada
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 110, style="F")
    pdf.set_xy(15, 38)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(255, 255, 255)
    pdf.multi_cell(0, 11, "Informe de Auditoria de Seguridad\ny Gestion de Cambios", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(148, 163, 184)
    pdf.ln(4)
    pdf.cell(0, 7, _s(f"Dispositivo: {res.hostname_detectado}  |  {res.dialecto_cisco}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f"Fecha: {datetime.date.today().isoformat()}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_xy(15, 125)
    pdf.set_text_color(*NAVY)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Postura de seguridad", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for label, score, color in (("Actual", res.score_seguridad_actual, (220, 53, 69)),
                                ("Proyectada", res.score_seguridad_proyectado, (32, 163, 130))):
        y = pdf.get_y() + 2
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*SLATE)
        pdf.text(15, y + 5, f"{label}: {score}/100")
        pdf.set_fill_color(226, 232, 240)
        pdf.rect(60, y, 120, 6, style="F")
        pdf.set_fill_color(*color)
        pdf.rect(60, y, 120 * score / 100, 6, style="F")
        pdf.set_y(y + 10)
    pdf.set_y(175)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*SLATE)
    pdf.multi_cell(0, 5, "Verificacion formal: Batfish (Digital Twin). Razonamiento semantico: Gemini + Skill de Ciberseguridad "
                         "(CIS / DISA STIG / NIST CSF). Documento confidencial.")

    # Resumen ejecutivo
    pdf.add_page()
    pdf.h1("1. Resumen Ejecutivo")
    pdf.para(res.resumen_gerencial)
    pdf.para("Orden recomendado de implementacion:", bold=True)
    pdf.para("  ->  ".join(res.orden_prioridad_implementacion))

    # Distribucion de riesgo
    pdf.h1("2. Distribucion Grafica de Riesgo")
    sev_counts = Counter(h.severidad.value for h in report.hallazgos)
    sev_data = [(k, sev_counts[k], SEV_COLORS[k]) for k in ("CRITICA", "ALTA", "MEDIA", "BAJA") if sev_counts[k]]
    cat_counts = Counter(h.categoria_problema for h in report.hallazgos)
    cat_data = [(k, v, PALETTE[i % len(PALETTE)]) for i, (k, v) in enumerate(cat_counts.most_common())]
    y0 = pdf.get_y() + 24
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*NAVY)
    pdf.text(15, y0 - 20, "Hallazgos por severidad")
    pdf.donut(35, y0 + 2, 17, sev_data)
    pdf.legend(58, y0 - 12, sev_data)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*NAVY)
    pdf.set_y(y0 + 24)
    pdf.set_x(15)
    pdf.cell(0, 6, "Taxonomia por tipo de vulnerabilidad", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    y1 = pdf.get_y() + 20
    pdf.donut(35, y1, 17, cat_data)
    pdf.legend(58, y1 - 14, cat_data)
    pdf.set_y(y1 + 24)

    # Topologia
    pdf.h1("3. Topologia y Contexto")
    pdf.para(f"ACLs activas: {', '.join(topology.acls_activas) or 'Ninguna'}")
    pdf.para(f"ACLs huerfanas: {', '.join(topology.acls_huerfanas) or 'Ninguna'}")
    for name, iface in topology.interfaces.items():
        pdf.para(f"- {name}: {iface.descripcion or 'N/D'} | IP {iface.ip_address or 'N/D'} | "
                 f"ACL in: {iface.acl_in or '-'} / out: {iface.acl_out or '-'}", size=9)

    # Hallazgos
    pdf.add_page()
    pdf.h1("4. Fichas de Hallazgos")
    for h in report.hallazgos:
        if pdf.get_y() > 235:
            pdf.add_page()
        r, g, b = SEV_COLORS.get(h.severidad.value, SLATE)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, _s(f"  {h.id_hallazgo}  |  {h.severidad.value}  |  {h.categoria_problema}"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.para(f"Componente: {h.acl_o_componente}", size=9, bold=True)
        pdf.para(f"Regla afectada: {h.linea_o_regla_afectada}", size=9)
        if h.punto_critico_error:
            pdf.set_fill_color(254, 242, 242)
            pdf.set_text_color(153, 27, 27)
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 5, _s(f"Punto critico: {h.punto_critico_error}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
        for r_vis in h.desglose_visual:
            pdf.para(f"[{r_vis.accion.upper()}] {r_vis.rol} (linea {r_vis.secuencia}): {r_vis.protocolo} "
                     f"{r_vis.origen} -> {r_vis.destino} {r_vis.puerto} | {r_vis.estado_flujo}", size=8)
        for c in h.controles_normativos:
            pdf.para(f"* {c}", size=8)
        pdf.para(f"Diagnostico: {h.diagnostico_tecnico}", size=9)
        pdf.para(f"Blast Radius ({h.nivel_impacto_operativo.value}): {h.analisis_blast_radius}", size=9)
        pdf.para(h.plan_a_recomendado.nombre_plan, size=9, bold=True)
        pdf.code(h.plan_a_recomendado.comandos_cli_implementacion)
        pdf.para(h.plan_b_conservador.nombre_plan, size=9, bold=True)
        pdf.code(h.plan_b_conservador.comandos_cli_implementacion)
        pdf.para("Rollback:", size=9, bold=True)
        pdf.code(h.plan_a_recomendado.comandos_cli_rollback)
        pdf.ln(3)

    return bytes(pdf.output())
