"""
Fase 3 (RF-12): priorización top-down y centro de decisiones What-If.

Módulo puro (sin Batfish ni Gemini): ordena los hallazgos, estima la postura de seguridad que
resultaría de las decisiones del operador y consolida los scripts CLI de esas decisiones.
Es una capa de *decisión*; la verificación formal del efecto en la red sigue delegada a Batfish.
"""
from typing import Dict, List, Optional, Tuple

from src.models import HallazgoFirewall, NivelImpactoEnum, ReporteAuditoriaFirewall, SeveridadEnum

DECISIONS = ("A", "B", "NONE")

# Orden top-down: la severidad manda; a igual severidad se aplica primero lo menos riesgoso.
SEVERITY_RANK: Dict[SeveridadEnum, int] = {
    SeveridadEnum.CRITICA: 4, SeveridadEnum.ALTA: 3, SeveridadEnum.MEDIA: 2, SeveridadEnum.BAJA: 1,
}
# Peso de cada severidad en el reparto de puntos de postura.
SEVERITY_WEIGHT: Dict[SeveridadEnum, int] = {
    SeveridadEnum.CRITICA: 10, SeveridadEnum.ALTA: 6, SeveridadEnum.MEDIA: 3, SeveridadEnum.BAJA: 1,
}
IMPACT_RANK: Dict[NivelImpactoEnum, int] = {
    NivelImpactoEnum.NULO: 0, NivelImpactoEnum.BAJO: 1, NivelImpactoEnum.MEDIO: 2, NivelImpactoEnum.ALTO: 3,
}
IMPACT_LABEL: Dict[NivelImpactoEnum, str] = {
    NivelImpactoEnum.NULO: "NULO", NivelImpactoEnum.BAJO: "BAJO", NivelImpactoEnum.MEDIO: "MEDIO", NivelImpactoEnum.ALTO: "ALTO",
}
# El Plan B (transición con monitoreo) mitiga pero no cierra del todo el riesgo.
PLAN_B_FACTOR = 0.6
QUICK_WIN_MAX_IMPACT = 1  # NULO o BAJO


def _sort_key(h: HallazgoFirewall, ai_order: Dict[str, int]) -> Tuple:
    return (
        -SEVERITY_RANK[h.severidad],
        IMPACT_RANK[h.nivel_impacto_operativo],
        0 if h.confirmado_por_batfish else 1,
        ai_order.get(h.id_hallazgo, 10_000),
        h.id_hallazgo,
    )


def ordered_findings(report: ReporteAuditoriaFirewall) -> List[HallazgoFirewall]:
    """Hallazgos en orden de implementación top-down (severidad ↓, riesgo operativo ↑)."""
    ai_order = {fid: i for i, fid in enumerate(report.resumen.orden_prioridad_implementacion)}
    return sorted(report.hallazgos, key=lambda h: _sort_key(h, ai_order))


def _gains(report: ReporteAuditoriaFirewall) -> Dict[str, float]:
    """Reparte (proyectada - actual) entre los hallazgos según su peso de severidad."""
    total_w = sum(SEVERITY_WEIGHT[h.severidad] for h in report.hallazgos) or 1
    pool = max(report.resumen.score_seguridad_proyectado - report.resumen.score_seguridad_actual, 0)
    return {h.id_hallazgo: pool * SEVERITY_WEIGHT[h.severidad] / total_w for h in report.hallazgos}


def rank_findings(report: ReporteAuditoriaFirewall) -> List[Dict]:
    """Tabla de priorización: posición, motivo, 'quick win' y puntos de postura por plan."""
    gains = _gains(report)
    ranked: List[Dict] = []
    for pos, h in enumerate(ordered_findings(report), start=1):
        impact = IMPACT_RANK[h.nivel_impacto_operativo]
        quick = impact <= QUICK_WIN_MAX_IMPACT
        ranked.append({
            "id": h.id_hallazgo,
            "posicion": pos,
            "severidad": h.severidad.value,
            "impacto": IMPACT_LABEL[h.nivel_impacto_operativo],
            "quick_win": quick,
            "confirmado_por_batfish": h.confirmado_por_batfish,
            "acl": h.acl_o_componente,
            "categoria": h.categoria_problema,
            "ganancia_a": round(gains[h.id_hallazgo], 2),
            "ganancia_b": round(gains[h.id_hallazgo] * PLAN_B_FACTOR, 2),
            "motivo": (
                f"Severidad {h.severidad.value}; riesgo de cambio {IMPACT_LABEL[h.nivel_impacto_operativo]}"
                + ("; cambio seguro de aplicar primero" if quick else "; verificar contadores y ventana antes de aplicar")
                + ("; confirmado formalmente por Batfish" if h.confirmado_por_batfish else "")
            ),
        })
    return ranked


def default_decisions(report: ReporteAuditoriaFirewall) -> Dict[str, str]:
    """Estado inicial / de reset: Plan A (recomendado) para todos los hallazgos."""
    return {h.id_hallazgo: "A" for h in report.hallazgos}


def normalize_decisions(report: ReporteAuditoriaFirewall, decisions: Dict[str, str]) -> Dict[str, str]:
    """Valida IDs y valores; los hallazgos no mencionados quedan como 'NONE' (sin cambios)."""
    known = {h.id_hallazgo for h in report.hallazgos}
    unknown = sorted(set(decisions) - known)
    if unknown:
        raise ValueError(f"Hallazgo(s) desconocido(s): {', '.join(unknown)}")
    clean: Dict[str, str] = {}
    for fid in known:
        value = str(decisions.get(fid, "NONE")).upper()
        if value not in DECISIONS:
            raise ValueError(f"Decisión inválida para {fid}: '{decisions.get(fid)}'. Usa A, B o NONE.")
        clean[fid] = value
    return clean


def projected_score(report: ReporteAuditoriaFirewall, decisions: Dict[str, str]) -> Dict:
    """Postura estimada tras aplicar las decisiones (Plan A = ganancia completa, Plan B = parcial)."""
    gains = _gains(report)
    actual = report.resumen.score_seguridad_actual
    delta = 0.0
    residuales: List[str] = []
    for h in report.hallazgos:
        d = decisions.get(h.id_hallazgo, "NONE")
        if d == "A":
            delta += gains[h.id_hallazgo]
        elif d == "B":
            delta += gains[h.id_hallazgo] * PLAN_B_FACTOR
        if d != "A":
            residuales.append(h.id_hallazgo)
    score = max(0, min(100, round(actual + delta)))
    return {
        "actual": actual,
        "proyectado": score,
        "maximo_posible": report.resumen.score_seguridad_proyectado,
        "ganancia": score - actual,
        "estimacion": True,
        "residuales": residuales,
    }


def selected_plan(h: HallazgoFirewall, decision: str):
    return h.plan_a_recomendado if decision == "A" else h.plan_b_conservador if decision == "B" else None


def commands_by_finding(report: ReporteAuditoriaFirewall, decisions: Dict[str, str]) -> List[Tuple[str, List[str]]]:
    """[(id, comandos_implementación)] de los hallazgos con decisión A/B, en orden top-down."""
    out: List[Tuple[str, List[str]]] = []
    for h in ordered_findings(report):
        plan = selected_plan(h, decisions.get(h.id_hallazgo, "NONE"))
        if plan:
            out.append((h.id_hallazgo, list(plan.comandos_cli_implementacion)))
    return out


_WRAPPERS = {"configure terminal", "conf t", "end", "write memory", "wr", "copy running-config startup-config"}


def _body(cmds: List[str]) -> List[str]:
    return [c for c in cmds if c.strip().lower() not in _WRAPPERS]


def build_scripts(report: ReporteAuditoriaFirewall, decisions: Dict[str, str]) -> Dict[str, Optional[str]]:
    """
    Scripts consolidados de las decisiones: remediación en orden top-down y rollback en orden
    inverso (el último cambio aplicado es el primero en revertirse).
    """
    chosen = [(h, decisions.get(h.id_hallazgo, "NONE")) for h in ordered_findings(report)]
    chosen = [(h, d) for h, d in chosen if d in {"A", "B"}]
    if not chosen:
        return {"remediacion": None, "rollback": None}

    def section(h: HallazgoFirewall, d: str, rollback: bool) -> List[str]:
        plan = selected_plan(h, d)
        cmds = plan.comandos_cli_rollback if rollback else plan.comandos_cli_implementacion
        return [f"! --- {h.id_hallazgo} · Plan {d} · {h.acl_o_componente} ({h.severidad.value}) ---", "configure terminal",
                *_body(cmds), "end", ""]

    rem = ["! Script consolidado de remediación (centro de decisiones What-If)",
           f"! Equipo: {report.resumen.hostname_detectado} · {len(chosen)} cambio(s) en orden top-down", ""]
    for h, d in chosen:
        rem += section(h, d, rollback=False)
    rem += ["write memory", ""]
    roll = ["! Script consolidado de rollback (orden inverso al de aplicación)",
            f"! Equipo: {report.resumen.hostname_detectado}", ""]
    for h, d in reversed(chosen):
        roll += section(h, d, rollback=True)
    roll += ["write memory", ""]
    return {"remediacion": "\n".join(rem), "rollback": "\n".join(roll)}

