"""
Generador de reportes PDF corporativos de ciberseguridad (MEJ-05 / MEJ-09 / RF-09 / RF-13.3).

Diseñado con estética editorial limpia, alto contraste legible y paleta corporativa suave
(inspirado en informes ejecutivos de Mandiant, NCC Group y Trail of Bits) usando fpdf2.
Es 100 % informativo y analítico (sin bloques de comandos CLI ni estrategias Plan A / Plan B,
los cuales residen en las vistas operativas y scripts .cli) y mantiene paridad visual 1 a 1
con la pestaña 'Reporte ejecutivo' del dashboard.
"""
import datetime
from collections import Counter
from typing import Dict, List, Tuple

from fpdf import FPDF
from fpdf.enums import Align, XPos, YPos
from fpdf.fonts import FontFace

from src.models import ContextoTopologia, HallazgoFirewall, ReporteAuditoriaFirewall
from src.prioritization import IMPACT_LABEL, ordered_findings, rank_findings

# Paleta corporativa suave y amigable a la vista (evita rojos/naranjas saturados de fondo completo)
SEV_COLORS: Dict[str, Tuple[int, int, int]] = {
    "CRITICA": (190, 38, 51),
    "ALTA": (217, 95, 14),
    "MEDIA": (180, 118, 9),
    "BAJA": (15, 118, 110),
}
SEV_SOFT: Dict[str, Tuple[int, int, int]] = {
    "CRITICA": (254, 242, 242),
    "ALTA": (255, 247, 237),
    "MEDIA": (254, 249, 195),
    "BAJA": (240, 253, 250),
}
SEV_META: Dict[str, Tuple[str, str]] = {
    "CRITICA": ("Inmediata (< 24 h)", "Exposicion directa o bypass de controles con riesgo inminente de compromiso."),
    "ALTA": ("Urgente (< 72 h)", "Debilidad severa en perimetro o segmentacion explotable sin autenticacion fuerte."),
    "MEDIA": ("Planificada (< 14 dias)", "Brecha de defensa en profundidad, trazabilidad o reglas enmascaradas (shadowing)."),
    "BAJA": ("Mantenimiento (< 30 dias)", "Higiene de configuracion, reglas obsoletas o endurecimiento preventivo."),
}
PALETTE: List[Tuple[int, int, int]] = [
    (190, 38, 51), (217, 95, 14), (180, 118, 9), (15, 118, 110), (37, 99, 235), (109, 40, 217), (14, 116, 144),
]

INK = (15, 23, 42)          # Títulos principales (#0F172A)
BODY = (51, 65, 85)         # Texto de lectura cómoda (#334155)
MUTED = (100, 116, 139)     # Etiquetas secundarias (#64748B)
BORDER = (226, 232, 240)    # Bordes suaves (#E2E8F0)
SURFACE = (248, 250, 252)   # Fondo de tarjetas y filas pares (#F8FAFC)
HEADER_BG = (241, 245, 249) # Cabeceras de tabla suaves (#F1F5F9)
WHITE = (255, 255, 255)
ACCENT = (2, 132, 199)      # Azul corporativo (#0284C7)
EMERALD = (5, 150, 105)     # Verde postura proyectada (#059669)


def _s(text: object) -> str:
    """Convierte a latin-1 (fuentes core de PDF) reemplazando símbolos Unicode frecuentes."""
    replacements = {
        "➔": "->", "→": "->", "←": "<-", "↔": "<->", "—": "-", "–": "-", "…": "...",
        "“": '"', "”": '"', "‘": "'", "’": "'", "•": "-", "·": "|", "∀": "Para todo ",
        "✔": "[OK]", "✅": "[OK]", "⚠️": "[!]", "🛡": "", "🔒": "", "🟢": "", "🔴": "", "🟡": "", "⚡": "",
    }
    out = str(text if text is not None else "")
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out.encode("latin-1", "replace").decode("latin-1")


def _maturity_label(score: int) -> str:
    if score < 40:
        return "CRITICA / VULNERABLE"
    if score < 70:
        return "MODERADA / CON BRECHAS"
    if score < 90:
        return "ROBUSTA / CONTROLADA"
    return "OPTIMA / HARDENED"


class ExecutivePDFReport(FPDF):
    def __init__(self, hostname: str, dialect: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.hostname = _s(hostname)
        self.dialect = _s(dialect)
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(15, 18, 15)

    def _reset_colors(self) -> None:
        """Restablece colores base para evitar que un fill_color previo contamine tablas o celdas."""
        self.set_fill_color(*WHITE)
        self.set_text_color(*BODY)
        self.set_draw_color(*BORDER)

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*MUTED)
        self.cell(120, 5, _s(f"INFORME EJECUTIVO DE AUDITORIA  |  {self.hostname} ({self.dialect})"), align="L")
        self.set_text_color(*ACCENT)
        self.cell(0, 5, "CONFIDENCIAL", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*BORDER)
        self.set_line_width(0.25)
        self.line(15, 14.5, 195, 14.5)
        self.ln(3.5)
        self._reset_colors()

    def footer(self) -> None:
        self.set_y(-13)
        self.set_draw_color(*BORDER)
        self.set_line_width(0.2)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(1.5)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*MUTED)
        self.cell(140, 5, "Verificacion Formal: Batfish Digital Twin  |  Evaluacion Normativa: CIS / DISA STIG / NIST CSF", align="L")
        self.set_font("Helvetica", "B", 7.5)
        self.cell(0, 5, f"Pagina {self.page_no()}", align="R")
        self._reset_colors()

    # ---------------------------------------------------------------- helpers
    def ensure_space(self, min_height: float) -> None:
        if self.get_y() + min_height > (297 - 18):
            self.add_page()

    def h1(self, text: str) -> None:
        self.ensure_space(45)
        self.ln(2)
        self.set_font("Helvetica", "B", 13.5)
        self.set_text_color(*INK)
        self.cell(0, 8, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.7)
        self.line(15, self.get_y(), 58, self.get_y())
        self.set_draw_color(*BORDER)
        self.set_line_width(0.2)
        self.line(58, self.get_y(), 195, self.get_y())
        self.ln(4)
        self._reset_colors()

    def h2(self, text: str) -> None:
        self.ensure_space(13)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*ACCENT)
        self.cell(0, 6, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)
        self._reset_colors()

    def para(self, text: str, size: float = 9.2, bold: bool = False, color: Tuple[int, int, int] = BODY) -> None:
        self.set_font("Helvetica", "B" if bold else "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 4.8, _s(text), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1.2)
        self._reset_colors()

    def info_box(self, title: str, body: str) -> None:
        """Bloque narrativo suave con borde gris claro y etiqueta superior."""
        self.ensure_space(16)
        self.set_font("Helvetica", "B", 7.8)
        self.set_text_color(*MUTED)
        self.cell(0, 4.5, _s(title.upper()), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_fill_color(*SURFACE)
        self.set_draw_color(*BORDER)
        self.set_text_color(*BODY)
        self.set_font("Helvetica", "", 8.8)
        self.multi_cell(0, 4.6, _s(body), border=1, fill=True, align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self._reset_colors()

    def evidence_line(self, rule_text: str) -> None:
        """Muestra la regla o componente auditado como evidencia documental (sin comandos de corrección)."""
        self.ensure_space(14)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*MUTED)
        self.cell(0, 4.5, "REGLA O DIRECTIVA AUDITADA (EVIDENCIA EN CONFIGURACION)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_fill_color(*HEADER_BG)
        self.set_draw_color(*BORDER)
        self.set_text_color(*INK)
        self.set_font("Courier", "B", 8)
        self.multi_cell(0, 4.8, _s(rule_text or "-"), border=1, fill=True, align="L",
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self._reset_colors()

    def donut(self, cx: float, cy: float, radius: float, data: List[Tuple[str, int, Tuple[int, int, int]]]) -> None:
        """Dibuja un gráfico donut circular perfecto (b=None en solid_arc)."""
        total = sum(v for _, v, _ in data) or 1
        angle = 0.0
        for _, value, color in data:
            sweep = 360.0 * value / total
            if sweep <= 0:
                continue
            self.set_fill_color(*color)
            if sweep >= 359.9:
                self.ellipse(cx - radius, cy - radius, radius * 2, radius * 2, style="F")
            else:
                self.solid_arc(
                    x=cx - radius,
                    y=cy - radius,
                    a=radius * 2,
                    start_angle=angle,
                    end_angle=angle + sweep,
                    b=None,
                    style="F",
                )
            angle += sweep
        inner = radius * 0.62
        self.set_fill_color(*WHITE)
        self.ellipse(cx - inner, cy - inner, inner * 2, inner * 2, style="F")
        total_txt = str(sum(v for _, v, _ in data))
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*INK)
        w = self.get_string_width(total_txt)
        self.text(cx - w / 2, cy + 1.0, total_txt)
        self.set_font("Helvetica", "", 5.5)
        self.set_text_color(*MUTED)
        sub = "HALLAZGOS"
        self.text(cx - self.get_string_width(sub) / 2, cy + 4.4, sub)
        self._reset_colors()

    def legend(self, x: float, y: float, data: List[Tuple[str, int, Tuple[int, int, int]]]) -> None:
        total = sum(v for _, v, _ in data) or 1
        self.set_font("Helvetica", "", 8)
        for i, (label, value, color) in enumerate(data[:6]):
            yy = y + i * 5.2
            self.set_fill_color(*color)
            self.rect(x, yy, 3.0, 3.0, style="F")
            self.set_text_color(*BODY)
            clean_lbl = _s(label)
            if len(clean_lbl) > 38:
                clean_lbl = clean_lbl[:35] + "..."
            self.text(x + 5, yy + 2.6, f"{clean_lbl}  ({value} | {value * 100 / total:.1f}%)")
        self._reset_colors()


def _draw_cover(pdf: ExecutivePDFReport, report: ReporteAuditoriaFirewall, topology: ContextoTopologia) -> None:
    res = report.resumen
    today = datetime.date.today().isoformat()
    pdf.add_page()

    # Encabezado institucional limpio y amigable (fondo claro con acento azul marino/cian)
    pdf.set_fill_color(*INK)
    pdf.rect(0, 0, 210, 74, style="F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 74, 210, 1.8, style="F")

    # Etiqueta superior y referencia
    pdf.set_xy(15, 13)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.cell(72, 5.5, "  CONFIDENCIAL  |  INFORME EJECUTIVO", fill=True, align="L")
    pdf.set_text_color(148, 163, 184)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5.5, _s(f"REF: AUDIT-{today.replace('-', '')}-{res.hostname_detectado}"), align="R",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(15, 24)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(56, 189, 248)
    pdf.cell(0, 5.5, "AUDITORIA DE SEGURIDAD DE REDES & VERIFICACION FORMAL (DIGITAL TWIN)",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*WHITE)
    pdf.multi_cell(0, 8.8, "Informe Ejecutivo de Postura de Seguridad\ny Hallazgos de Configuracion",
                   align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)
    pdf.set_font("Helvetica", "", 9.2)
    pdf.set_text_color(203, 213, 225)
    pdf.multi_cell(
        0, 4.6,
        "Evaluacion formal matematica con Batfish y analisis normativo bajo estandares "
        "CIS Benchmarks, DISA STIG y NIST Cybersecurity Framework.",
        align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )

    # CRÍTICO: restablecer fill_color a blanco antes de construir la tabla
    pdf._reset_colors()

    pdf.set_y(83)
    pdf.h2("Ficha Tecnica del Compromiso (Engagement Overview)")
    vty_status = f"Transport: {topology.vty_transport_input or 'No restringido'} | ACL: {topology.vty_access_class or 'Ninguna'}"
    meta_rows = [
        ("Activo Auditado", res.hostname_detectado, "Plataforma / Dialecto", res.dialecto_cisco),
        ("Fecha de Emision", today, "Total de Hallazgos", f"{res.total_hallazgos} hallazgos documentados"),
        ("Interfaces / ACLs Activas", f"{len(topology.interfaces)} interfaces | {len(topology.acls_activas)} ACLs",
         "ACLs Huerfanas / Lineas", f"{len(topology.acls_huerfanas)} huerfanas | {topology.total_lineas_config} lineas"),
        ("Plano de Gestion VTY", vty_status, "Marcos de Referencia", "CIS Benchmark | DISA STIG | NIST CSF"),
    ]
    key_style = FontFace(emphasis="BOLD", color=INK, fill_color=HEADER_BG)
    val_style = FontFace(color=BODY, fill_color=WHITE)
    pdf.set_font("Helvetica", "", 8.3)
    with pdf.table(
        col_widths=(38, 52, 38, 52),
        line_height=5.4,
        padding=2.0,
        text_align=Align.L,
        first_row_as_headings=False,
    ) as tbl:
        for k1, v1, k2, v2 in meta_rows:
            row = tbl.row()
            row.cell(_s(k1), style=key_style)
            row.cell(_s(v1), style=val_style)
            row.cell(_s(k2), style=key_style)
            row.cell(_s(v2), style=val_style)
    pdf._reset_colors()

    # Postura de seguridad comparativa
    pdf.ln(5)
    pdf.h2("Dictamen Cuantitativo de Postura de Seguridad (Escala 0 - 100)")
    gain = res.score_seguridad_proyectado - res.score_seguridad_actual
    bars = [
        ("Postura Actual", res.score_seguridad_actual, _maturity_label(res.score_seguridad_actual), SEV_COLORS["CRITICA"]),
        ("Postura Proyectada tras Mitigacion", res.score_seguridad_proyectado,
         f"{_maturity_label(res.score_seguridad_proyectado)} (+{gain} pts)", EMERALD),
    ]
    for label, score, badge, color in bars:
        y = pdf.get_y() + 1.5
        pdf.set_fill_color(*SURFACE)
        pdf.set_draw_color(*BORDER)
        pdf.rect(15, y, 180, 12, style="DF")
        pdf.set_font("Helvetica", "B", 8.8)
        pdf.set_text_color(*INK)
        pdf.text(18, y + 5.0, _s(f"{label}: {score}/100"))
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*color)
        pdf.text(18, y + 9.6, _s(badge))
        # Pista de la barra
        pdf.set_fill_color(226, 232, 240)
        pdf.rect(86, y + 3.2, 104, 5.5, style="F")
        pdf.set_fill_color(*color)
        pdf.rect(86, y + 3.2, max(2.0, 104 * max(0, min(100, score)) / 100.0), 5.5, style="F")
        pdf.set_y(y + 14)
    pdf._reset_colors()

    # Caja de alcance y metodología
    pdf.ln(3)
    pdf.set_fill_color(*SURFACE)
    pdf.set_draw_color(*BORDER)
    pdf.set_font("Helvetica", "B", 8.2)
    pdf.set_text_color(*INK)
    pdf.cell(0, 6, "  ALCANCE DEL INFORME EJECUTIVO Y CERTIFICACION METODOLOGICA", border="LTR", fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*BODY)
    pdf.multi_cell(
        0, 4.5,
        "1. Proposito Informativo: Este documento presenta el diagnostico ejecutivo y tecnico de las vulnerabilidades "
        "detectadas. Los scripts operativos de remediacion y rollback (.cli) se gestionan por separado en el Centro "
        "de Decisiones What-If del dashboard.\n"
        "2. Privacidad Zero-Leak (RFC 5737): Las direcciones IPv4 publicas y secretos fueron enmascarados antes del "
        "analisis semantico y restaurados localmente para este informe.\n"
        "3. Verificacion Formal: La alcanzabilidad de filtros (filterLineReachability), exposicion de servicios "
        "(searchFilters) y aislamiento entre zonas (reachability) fueron validados matematicamente con Batfish.",
        border="LBR", fill=True, align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf._reset_colors()


def _draw_finding(pdf: ExecutivePDFReport, h: HallazgoFirewall, pos: int, gain_a: float) -> None:
    """Dibuja una ficha técnica informativa (sin comandos CLI ni planes A/B)."""
    pdf.ensure_space(110)
    pdf._reset_colors()
    sev = h.severidad.value
    r, g, b = SEV_COLORS.get(sev, MUTED)
    soft_bg = SEV_SOFT.get(sev, SURFACE)

    # Cabecera suave y amigable: fondo claro con franja lateral de color de severidad
    y_top = pdf.get_y()
    title_txt = _s(f"5.{pos} [Prioridad #{pos}]  {h.id_hallazgo}  -  {h.categoria_problema}  (Severidad {sev})")
    pdf.set_fill_color(*soft_bg)
    pdf.set_draw_color(*BORDER)
    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.multi_cell(0, 7.2, f"   {title_txt}", border=1, fill=True, align="L",
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    y_bot = pdf.get_y()
    pdf.set_fill_color(r, g, b)
    pdf.rect(15, y_top, 3.2, y_bot - y_top, style="F")
    pdf._reset_colors()

    # Cinta de 4 metadatos técnicos con contraste limpio
    head_style = FontFace(emphasis="BOLD", color=INK, fill_color=HEADER_BG)
    cell_style = FontFace(color=BODY, fill_color=WHITE)
    pdf.set_font("Helvetica", "", 8)
    verif = "Confirmado por Batfish" if h.confirmado_por_batfish else "Semantico (IA Normativa)"
    impact_short = IMPACT_LABEL.get(h.nivel_impacto_operativo, h.nivel_impacto_operativo.value)
    with pdf.table(
        col_widths=(45, 45, 54, 36),
        line_height=5.0,
        padding=1.6,
        text_align=Align.L,
        headings_style=head_style,
    ) as tbl:
        hdr = tbl.row()
        for col in ("Componente / ACL", "Metodo de Verificacion", "Riesgo Operativo (Blast Radius)", "Impacto en Postura"):
            hdr.cell(col)
        row = tbl.row()
        row.cell(_s(h.acl_o_componente), style=cell_style)
        row.cell(_s(verif), style=cell_style)
        row.cell(_s(impact_short), style=cell_style)
        row.cell(_s(f"+{gain_a:.2f} pts"), style=FontFace(emphasis="BOLD", color=EMERALD, fill_color=WHITE))
    pdf._reset_colors()
    pdf.ln(2)

    # Evidencia: regla o directiva afectada
    pdf.evidence_line(h.linea_o_regla_afectada)

    # Tabla de desglose y colisión de reglas
    if h.desglose_visual:
        pdf.ensure_space(22)
        title = ("Comparativa y Colision de Reglas (Shadowing / Redundancia)"
                 if len(h.desglose_visual) > 1 else "Desglose Estructural de la Regla Afectada")
        pdf.set_font("Helvetica", "B", 7.8)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 4.8, _s(title.upper()), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7.4)
        with pdf.table(
            col_widths=(31, 13, 16, 14, 27, 27, 20, 32),
            line_height=4.4,
            padding=1.4,
            text_align=Align.L,
            headings_style=head_style,
        ) as tbl:
            hdr = tbl.row()
            for col in ("Rol", "Linea", "Accion", "Proto", "Origen", "Destino", "Puerto", "Estado del Flujo"):
                hdr.cell(col)
            for idx_r, rv in enumerate(h.desglose_visual):
                bg = WHITE if idx_r % 2 == 0 else SURFACE
                act = rv.accion.upper()
                act_color = EMERALD if "PERMIT" in act else SEV_COLORS["CRITICA"]
                row = tbl.row()
                row.cell(_s(rv.rol), style=FontFace(emphasis="BOLD", color=INK, fill_color=bg))
                row.cell(_s(rv.secuencia), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(act), style=FontFace(emphasis="BOLD", color=act_color, fill_color=bg))
                row.cell(_s(rv.protocolo), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(rv.origen), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(rv.destino), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(rv.puerto), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(rv.estado_flujo), style=FontFace(color=BODY, fill_color=bg))
        pdf._reset_colors()
        pdf.ln(2)

    # Punto crítico del error
    if h.punto_critico_error:
        pdf.ensure_space(13)
        pdf.set_fill_color(*SEV_SOFT["CRITICA"])
        pdf.set_draw_color(248, 180, 180)
        pdf.set_text_color(153, 27, 27)
        pdf.set_font("Helvetica", "B", 8.3)
        pdf.multi_cell(0, 4.8, _s(f"PUNTO CRITICO DEL ERROR: {h.punto_critico_error}"),
                       border=1, fill=True, align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf._reset_colors()
        pdf.ln(2)

    # Controles normativos incumplidos
    pdf.ensure_space(14)
    pdf.set_font("Helvetica", "B", 7.8)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 4.5, "CONTROLES NORMATIVOS INCUMPLIDOS (CIS / DISA STIG / NIST CSF)",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for ctrl in (h.controles_normativos or ["Sin controles especificos asignados."]):
        pdf.para(f"- {ctrl}", size=8.4, color=BODY)

    # Bloques informativos de diagnóstico, beneficio y blast radius (sin Plan A / Plan B ni CLI)
    pdf.info_box("Diagnostico Tecnico y Vector de Riesgo", h.diagnostico_tecnico)
    pdf.info_box("Beneficio de Mitigacion (Como Mejora la Red)", h.como_mejora_la_red)
    pdf.info_box(f"Analisis de Blast Radius ({h.nivel_impacto_operativo.value})", h.analisis_blast_radius)
    pdf.ln(3)


def build_pdf(report: ReporteAuditoriaFirewall, topology: ContextoTopologia) -> bytes:
    """Genera el informe ejecutivo y técnico en PDF (100 % informativo, amigable a la vista)."""
    res = report.resumen
    pdf = ExecutivePDFReport(res.hostname_detectado, res.dialecto_cisco)
    head_style = FontFace(emphasis="BOLD", color=INK, fill_color=HEADER_BG)

    # Portada
    _draw_cover(pdf, report, topology)

    # 1. Resumen Ejecutivo
    pdf.add_page()
    pdf.h1("1. Resumen Ejecutivo y Dictamen de Postura")
    pdf.h2("1.1 Dictamen Gerencial")
    pdf.para(res.resumen_gerencial)

    pdf.h2("1.2 Resumen de Hallazgos por Nivel de Severidad")
    sev_counts = Counter(h.severidad.value for h in report.hallazgos)
    total_h = len(report.hallazgos) or 1
    pdf._reset_colors()
    pdf.set_font("Helvetica", "", 8.2)
    with pdf.table(
        col_widths=(26, 16, 18, 34, 86),
        line_height=5.2,
        padding=1.8,
        text_align=Align.L,
        headings_style=head_style,
    ) as tbl:
        hdr = tbl.row()
        for col in ("Severidad", "Cant.", "% Total", "SLA Sugerido", "Definicion de Impacto Corporativo"):
            hdr.cell(col)
        for idx_s, sev in enumerate(("CRITICA", "ALTA", "MEDIA", "BAJA")):
            bg = WHITE if idx_s % 2 == 0 else SURFACE
            cnt = sev_counts.get(sev, 0)
            sla, desc = SEV_META[sev]
            row = tbl.row()
            row.cell(sev, style=FontFace(emphasis="BOLD", color=SEV_COLORS[sev], fill_color=SEV_SOFT[sev]))
            row.cell(str(cnt), style=FontFace(emphasis="BOLD", color=INK, fill_color=bg))
            row.cell(f"{(cnt * 100.0 / total_h) if report.hallazgos else 0:.1f}%", style=FontFace(color=BODY, fill_color=bg))
            row.cell(sla, style=FontFace(color=BODY, fill_color=bg))
            row.cell(desc, style=FontFace(color=BODY, fill_color=bg))
    pdf._reset_colors()
    pdf.ln(4)

    # 2. Distribución Gráfica de Riesgo (dos tarjetas lado a lado con donuts circulares)
    pdf.h1("2. Distribucion Grafica de Riesgo y Taxonomia")
    sev_data = [(k, sev_counts[k], SEV_COLORS[k]) for k in ("CRITICA", "ALTA", "MEDIA", "BAJA") if sev_counts[k]]
    cat_counts = Counter(h.categoria_problema for h in report.hallazgos)
    cat_data = [(k, v, PALETTE[i % len(PALETTE)]) for i, (k, v) in enumerate(cat_counts.most_common())]
    if sev_data:
        pdf.ensure_space(86)
        # Tarjeta 2.1
        y_box = pdf.get_y()
        pdf.set_fill_color(*SURFACE)
        pdf.set_draw_color(*BORDER)
        pdf.rect(15, y_box, 180, 38, style="DF")
        pdf.set_font("Helvetica", "B", 9.2)
        pdf.set_text_color(*INK)
        pdf.text(20, y_box + 6.5, "2.1 Matriz de Hallazgos por Severidad")
        pdf.donut(38, y_box + 22, 12.5, sev_data)
        pdf.legend(60, y_box + 11, sev_data)

        # Tarjeta 2.2
        y_box2 = y_box + 42
        box2_h = max(38.0, 14.0 + 5.2 * min(6, len(cat_data)))
        pdf.set_fill_color(*SURFACE)
        pdf.set_draw_color(*BORDER)
        pdf.rect(15, y_box2, 180, box2_h, style="DF")
        pdf.set_font("Helvetica", "B", 9.2)
        pdf.set_text_color(*INK)
        pdf.text(20, y_box2 + 6.5, "2.2 Taxonomia por Vector de Vulnerabilidad")
        pdf.donut(38, y_box2 + 6 + (box2_h - 6) / 2, 12.5, cat_data)
        pdf.legend(60, y_box2 + 11, cat_data)
        pdf.set_y(y_box2 + box2_h + 5)
        pdf._reset_colors()
    else:
        pdf.para("No se registraron hallazgos para graficar.")

    # 3. Alcance, Metodología y Topología
    pdf.h1("3. Alcance Tecnico, Metodologia y Topologia Auditada")
    pdf.h2("3.1 Superficie de Control y Plano de Gestion")
    pdf.para(f"ACLs activas en interfaces/VTY: {', '.join(topology.acls_activas) or 'Ninguna'}", size=8.8)
    pdf.para(f"ACLs huerfanas (sin aplicar): {', '.join(topology.acls_huerfanas) or 'Ninguna'}", size=8.8)
    pdf.para(
        f"Seguridad VTY (line vty 0 15): Transport input = {topology.vty_transport_input or 'No restringido'}  |  "
        f"Access-class = {topology.vty_access_class or 'Sin filtro ACL'}",
        size=8.8,
    )

    if topology.interfaces:
        pdf.h2("3.2 Inventario de Interfaces y Perimetros L3")
        pdf._reset_colors()
        pdf.set_font("Helvetica", "", 8)
        with pdf.table(
            col_widths=(33, 41, 28, 26, 27, 25),
            line_height=5.0,
            padding=1.6,
            text_align=Align.L,
            headings_style=head_style,
        ) as tbl:
            hdr = tbl.row()
            for col in ("Interfaz", "Descripcion / Nameif", "Direccion IP", "Mascara", "ACL In", "ACL Out"):
                hdr.cell(col)
            for idx_i, (name, iface) in enumerate(topology.interfaces.items()):
                bg = WHITE if idx_i % 2 == 0 else SURFACE
                row = tbl.row()
                row.cell(_s(name), style=FontFace(emphasis="BOLD", color=INK, fill_color=bg))
                row.cell(_s(iface.descripcion or "N/D"), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(iface.ip_address or "N/D"), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(iface.mascara or "N/D"), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(iface.acl_in or "-"), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(iface.acl_out or "-"), style=FontFace(color=BODY, fill_color=bg))
        pdf._reset_colors()
        pdf.ln(3)

    # 4. Matriz de Priorización Top-Down
    pdf.h1("4. Matriz de Priorizacion Top-Down y Hoja de Ruta")
    pdf.para(
        "Los hallazgos se ordenan por severidad descendente y, a igual severidad, priorizando el cambio de menor "
        "riesgo operativo (Quick Wins de impacto NULO o BAJO primero) y aquellos confirmados formalmente por Batfish.",
        size=8.8,
    )
    ranked = rank_findings(report)
    gains_by_id = {r["id"]: r["ganancia_a"] for r in ranked}
    if ranked:
        pdf._reset_colors()
        pdf.set_font("Helvetica", "", 7.8)
        with pdf.table(
            col_widths=(10, 26, 20, 32, 44, 28, 20),
            line_height=5.0,
            padding=1.6,
            text_align=Align.L,
            headings_style=head_style,
        ) as tbl:
            hdr = tbl.row()
            for col in ("#", "ID Hallazgo", "Severidad", "Componente", "Categoria / Vector", "Riesgo Cambio", "Impacto"):
                hdr.cell(col)
            for idx_p, r_item in enumerate(ranked):
                bg = WHITE if idx_p % 2 == 0 else SURFACE
                sv = r_item["severidad"]
                row = tbl.row()
                row.cell(str(r_item["posicion"]), style=FontFace(emphasis="BOLD", color=INK, fill_color=bg))
                row.cell(_s(r_item["id"]), style=FontFace(emphasis="BOLD", color=ACCENT, fill_color=bg))
                row.cell(_s(sv), style=FontFace(emphasis="BOLD", color=SEV_COLORS.get(sv, MUTED),
                                                fill_color=SEV_SOFT.get(sv, SURFACE)))
                row.cell(_s(r_item["acl"]), style=FontFace(color=BODY, fill_color=bg))
                row.cell(_s(r_item["categoria"]), style=FontFace(color=BODY, fill_color=bg))
                qw = " | Quick Win" if r_item["quick_win"] else ""
                row.cell(_s(f"{r_item['impacto']}{qw}"), style=FontFace(color=BODY, fill_color=bg))
                row.cell(f"+{r_item['ganancia_a']:.2f}", style=FontFace(emphasis="BOLD", color=EMERALD, fill_color=bg))
        pdf._reset_colors()
        pdf.ln(4)

    # 5. Fichas Técnicas Detalladas de Hallazgos
    pdf.add_page()
    pdf.h1("5. Fichas Tecnicas Detalladas de Hallazgos")
    for pos, h in enumerate(ordered_findings(report), start=1):
        _draw_finding(pdf, h, pos, gains_by_id.get(h.id_hallazgo, 0.0))

    return bytes(pdf.output())
