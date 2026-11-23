"""Pruebas de la Fase 3 (RF-12): priorización top-down, centro de decisiones What-If y reset."""
import pytest
from fastapi.testclient import TestClient

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.models import NivelImpactoEnum, ReporteAuditoriaFirewall, SeveridadEnum
from src.prioritization import (
    PLAN_B_FACTOR, build_scripts, commands_by_finding, default_decisions, normalize_decisions,
    ordered_findings, projected_score, rank_findings,
)
from src.web.app import app
from src.web.service import service
from tests.test_reachability import _make_session


def _variant(base, fid, sev, impact, batfish=False, cmds=None):
    h = base.hallazgos[0].model_copy(deep=True)
    h.id_hallazgo, h.severidad, h.nivel_impacto_operativo, h.confirmado_por_batfish = fid, sev, impact, batfish
    if cmds:
        h.plan_a_recomendado.comandos_cli_implementacion = cmds[0]
        h.plan_a_recomendado.comandos_cli_rollback = cmds[1]
    return h


@pytest.fixture
def report(sample_report) -> ReporteAuditoriaFirewall:
    """4 hallazgos con severidades/impactos mezclados; la IA los listó en otro orden."""
    S, N = SeveridadEnum, NivelImpactoEnum
    hs = [
        _variant(sample_report, "F-BAJA", S.BAJA, N.NULO),
        _variant(sample_report, "F-CRIT-ALTO", S.CRITICA, N.ALTO),
        _variant(sample_report, "F-CRIT-NULO", S.CRITICA, N.NULO, batfish=True),
        _variant(sample_report, "F-ALTA", S.ALTA, N.MEDIO),
    ]
    r = sample_report.model_copy(deep=True)
    r.hallazgos = hs
    r.resumen.score_seguridad_actual, r.resumen.score_seguridad_proyectado = 20, 90
    r.resumen.orden_prioridad_implementacion = ["F-BAJA", "F-ALTA", "F-CRIT-ALTO", "F-CRIT-NULO"]
    return r


# ------------------------------------------------------------------ priorización
def test_ranking_is_top_down_severity_then_lowest_risk(report):
    assert [h.id_hallazgo for h in ordered_findings(report)] == ["F-CRIT-NULO", "F-CRIT-ALTO", "F-ALTA", "F-BAJA"]
    rk = rank_findings(report)
    assert [r["posicion"] for r in rk] == [1, 2, 3, 4]
    assert rk[0]["quick_win"] and rk[0]["confirmado_por_batfish"] and "Batfish" in rk[0]["motivo"]
    assert not rk[1]["quick_win"] and rk[3]["quick_win"]  # BAJA/NULO sigue siendo quick win aunque vaya al final


def test_ranking_is_deterministic_on_ties(report):
    report.hallazgos.append(_variant(report, "F-A-CRIT-NULO", SeveridadEnum.CRITICA, NivelImpactoEnum.NULO, batfish=True))
    ids = [h.id_hallazgo for h in ordered_findings(report)]
    assert ids[:2] == ["F-CRIT-NULO", "F-A-CRIT-NULO"]   # empate total: gana el que la IA ya había priorizado
    assert ids == [h.id_hallazgo for h in ordered_findings(report)]


# ------------------------------------------------------------------ postura proyectada
def test_projected_score_matches_report_extremes(report):
    assert projected_score(report, default_decisions(report))["proyectado"] == 90        # todo Plan A = proyectado de la IA
    none = projected_score(report, {h.id_hallazgo: "NONE" for h in report.hallazgos})
    assert none["proyectado"] == 20 and none["ganancia"] == 0 and len(none["residuales"]) == 4


def test_plan_b_gains_less_than_plan_a_and_partial_selection_is_monotonic(report):
    a = projected_score(report, default_decisions(report))["proyectado"]
    b = projected_score(report, {h.id_hallazgo: "B" for h in report.hallazgos})["proyectado"]
    assert 20 < b < a and abs((b - 20) - (a - 20) * PLAN_B_FACTOR) <= 1
    only_crit = projected_score(report, {"F-CRIT-NULO": "A", "F-CRIT-ALTO": "A"})["proyectado"]
    assert 20 < only_crit < a                                                            # críticos aportan más que BAJA


def test_normalize_decisions_validates(report):
    assert normalize_decisions(report, {"F-BAJA": "a"})["F-BAJA"] == "A"
    assert normalize_decisions(report, {"F-BAJA": "c"})["F-BAJA"] == "C"
    assert normalize_decisions(report, {})["F-ALTA"] == "NONE"
    with pytest.raises(ValueError, match="desconocido"):
        normalize_decisions(report, {"FW-XXX": "A"})
    with pytest.raises(ValueError, match="inválida"):
        normalize_decisions(report, {"F-BAJA": "X"})


# ------------------------------------------------------------------ scripts consolidados
def test_scripts_follow_priority_and_rollback_is_reversed(report):
    for h, tag in zip(report.hallazgos, ["b", "c1", "c2", "a"]):
        h.plan_a_recomendado.comandos_cli_implementacion = ["configure terminal", f"cmd-{tag}", "end"]
        h.plan_a_recomendado.comandos_cli_rollback = ["configure terminal", f"undo-{tag}", "end"]
    s = build_scripts(report, {"F-BAJA": "A", "F-CRIT-ALTO": "A", "F-CRIT-NULO": "A", "F-ALTA": "NONE"})
    rem, roll = s["remediacion"], s["rollback"]
    assert rem.index("cmd-c2") < rem.index("cmd-c1") < rem.index("cmd-b")      # top-down
    assert roll.index("undo-b") < roll.index("undo-c1") < roll.index("undo-c2")  # inverso
    assert "cmd-a" not in rem and rem.count("configure terminal") == 3         # omitido fuera, un contexto por cambio
    assert build_scripts(report, {}) == {"remediacion": None, "rollback": None}


def test_commands_by_finding_uses_selected_plan(report):
    sel = dict(commands_by_finding(report, {"F-CRIT-NULO": "B", "F-BAJA": "A"}))
    assert set(sel) == {"F-CRIT-NULO", "F-BAJA"}
    assert sel["F-CRIT-NULO"] == report.hallazgos[2].plan_b_conservador.comandos_cli_implementacion


# ------------------------------------------------------------------ API What-If (Batfish simulado)
class FakeAnalyzer:
    def __init__(self):
        self.iso_configs = []

    def compare_candidate(self, base, cand, fname, acls):
        return {"cambios": [{"acl": "ACL_WAN_IN", "accion_nueva": "DENY", "linea_nueva": "x", "linea_anterior": "y"}],
                "errores": [], "total_cambios": 1}

    def check_zone_isolation(self, cfg, fname, zones):
        self.iso_configs.append(cfg)
        estado = "AISLADO" if len(self.iso_configs) > 1 else "FUGA"   # 1ª llamada = base, 2ª = candidata
        return [{"origen": "WAN", "destino": "DMZ", "estado": estado, "detalle": "d"}]


@pytest.fixture
def client():
    service.sessions.clear()
    return TestClient(app)


@pytest.fixture
def fake(monkeypatch):
    f = FakeAnalyzer()
    monkeypatch.setattr(service, "_analyzer", lambda: f)
    return f


def _session_with(report):
    s = _make_session("wi1")
    s.report, s.report_source = report, "gemini"
    return s


def test_summary_exposes_priorities_and_default_decisions(client, sample_report):
    _session_with(sample_report)
    j = client.get("/api/session/wi1").json()
    assert j["prioridades"][0]["id"] == "FW-001" and j["decisiones_default"] == {"FW-001": "A"}


def test_whatif_returns_posture_flows_isolation_delta_and_scripts(client, fake, sample_report):
    _session_with(sample_report)
    r = client.post("/api/session/wi1/whatif", json={"decisiones": {"FW-001": "A"}})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["aplicados"] == ["FW-001"] and j["total_cambios"] == 1
    assert j["postura"]["proyectado"] == sample_report.resumen.score_seguridad_proyectado
    assert j["aislamiento"]["cambios"] == [{"origen": "WAN", "destino": "DMZ", "antes": "FUGA", "despues": "AISLADO"}]
    assert "no 30" in j["scripts"]["remediacion"] and "FW-001" in j["scripts"]["rollback"]
    assert "eq 23" in fake.iso_configs[0] and "eq 23" not in fake.iso_configs[1]  # base intacta; candidata sin Telnet


def test_whatif_without_selection_skips_batfish(client, monkeypatch, sample_report):
    _session_with(sample_report)
    monkeypatch.setattr(service, "_analyzer", lambda: (_ for _ in ()).throw(AssertionError("no debe consultar Batfish")))
    j = client.post("/api/session/wi1/whatif", json={"decisiones": {"FW-001": "NONE"}}).json()
    assert j["plan"] == "NINGUNO" and j["total_cambios"] == 0 and j["aplicados"] == []
    assert j["postura"]["proyectado"] == j["postura"]["actual"] and j["scripts"]["remediacion"] is None


@pytest.mark.parametrize("payload,code", [
    ({"decisiones": {"FW-001": "Z"}}, 422),
    ({"decisiones": {"FW-999": "A"}}, 400),
])
def test_whatif_validation(client, fake, sample_report, payload, code):
    _session_with(sample_report)
    assert client.post("/api/session/wi1/whatif", json=payload).status_code == code


def test_whatif_requires_report_and_session(client, fake):
    _make_session("wi1")  # sin reporte de IA
    assert client.post("/api/session/wi1/whatif", json={"decisiones": {}}).status_code == 400
    assert client.post("/api/session/nope/whatif", json={"decisiones": {}}).status_code == 404


def test_isolation_failure_does_not_break_whatif(client, monkeypatch, sample_report):
    _session_with(sample_report)

    class Flaky(FakeAnalyzer):
        def check_zone_isolation(self, *a):
            if self.iso_configs:
                raise RuntimeError("consulta rota")
            return super().check_zone_isolation(*a)
    flaky = Flaky()
    monkeypatch.setattr(service, "_analyzer", lambda: flaky)
    j = client.post("/api/session/wi1/whatif", json={"decisiones": {"FW-001": "A"}}).json()
    assert j["total_cambios"] == 1 and "RuntimeError" in j["aislamiento"]["error"]


def test_existing_diff_endpoint_still_works_after_refactor(client, fake, sample_report):
    _session_with(sample_report)
    j = client.post("/api/session/wi1/diff", json={"plan": "A"}).json()
    assert j["plan"] == "A" and j["total_cambios"] == 1 and "_candidate" not in j and j["diff_config"]


# ------------------------------------------------------------------ integración real con Batfish
def test_whatif_end_to_end_with_real_batfish(client, sample_report):
    try:
        BatfishAnalyzer().connect()
    except BatfishUnavailableError:
        pytest.skip("Batfish Docker no está activo en este momento.")
    _session_with(sample_report)
    j = client.post("/api/session/wi1/whatif", json={"decisiones": {"FW-001": "A"}}).json()
    assert j["total_cambios"] >= 1, j                      # cerrar Telnet cambia el tratamiento de flujos
    assert j["aislamiento"] and "error" not in j["aislamiento"]
    assert j["postura"]["proyectado"] > j["postura"]["actual"]
