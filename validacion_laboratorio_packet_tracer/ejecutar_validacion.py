#!/usr/bin/env python3
"""
Validación end-to-end reproducible del laboratorio Cisco Packet Tracer (RF-15).

Replica de forma automática el "Plan Maestro de Pruebas Espejo" de la guía:
  1. Audita la configuración VULNERABLE de R-BORDE-CORP y verifica hallazgos y pruebas de tráfico.
  2. Genera la remediación con el Centro de Decisiones What-If (Plan A + Plan C determinístico).
  3. Aplica el script a la configuración, vuelve a auditar y verifica que todo mejora.

Cada prueba de tráfico de este script tiene su par en Packet Tracer (ver GUIA_LAB_PACKET_TRACER.md):
si ambos resultados coinciden, la aplicación es correcta.

Requisitos: contenedor Batfish activo (`docker ps | grep batfish`). No usa Gemini (100 % local).

Uso (desde la raíz del repositorio):
    .venv/bin/python validacion_laboratorio_packet_tracer/ejecutar_validacion.py
"""
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.batfish_analyzer import BatfishAnalyzer  # noqa: E402
from src.config_patcher import apply_commands  # noqa: E402
from src.deterministic_advisor import DeterministicFirewallAdvisor  # noqa: E402
from src.web.service import service  # noqa: E402

HERE = Path(__file__).resolve().parent
CFG_VULNERABLE = HERE / "configs" / "r-borde-corp_vulnerable.cfg"
RESULTADOS = HERE / "resultados"
JUSTIFICACION_PLAN_C = (
    "La VLAN 10 de usuarios necesita salir a Internet con destino any para navegar, pero quiero bloquear "
    "el acceso lateral a la VLAN 20 de Gestión y a los puertos administrativos de la DMZ."
)

# (id, descripción, zona origen, src, dst, proto, puerto, esperado ANTES, esperado DESPUÉS, prueba equivalente en Packet Tracer)
FLOW_TESTS = [
    ("T1", "WAN → Base de datos crítica (HTTPS 443)", "WAN", "8.8.8.66", "172.16.10.50", "TCP", 443, True, False,
     "PC-ATACANTE-WAN → Web Browser → https://172.16.10.50"),
    ("T2", "WAN → Web pública legítima (HTTPS 443)", "WAN", "8.8.8.66", "172.16.10.10", "TCP", 443, True, True,
     "PC-ATACANTE-WAN → Web Browser → https://172.16.10.10"),
    ("T3", "WAN → Telnet del router (TCP 23)", "WAN", "8.8.8.66", "200.45.112.18", "TCP", 23, True, False,
     "PC-ATACANTE-WAN → Command Prompt → telnet 200.45.112.18"),
    ("T4", "VLAN 10 Usuarios → VLAN 20 Gestión (SSH 22)", "LAN", "192.168.10.10", "192.168.20.10", "TCP", 22, True, False,
     "PC-VENTAS-VLAN10 → Command Prompt → ping 192.168.20.10"),
    ("T5", "VLAN 10 Usuarios → Internet (HTTP 80), ida y retorno", "LAN", "192.168.10.10", "8.8.8.8", "TCP", 80, True, True,
     "PC-VENTAS-VLAN10 → Web Browser → http://8.8.8.8"),
]


@dataclass
class Check:
    id: str
    descripcion: str
    esperado: str
    obtenido: str
    ok: bool
    packet_tracer: str = ""


def _yn(value: Optional[bool]) -> str:
    return "PERMIT" if value else "DENY"


def _flow_checks(session: Any, fase: str, idx_expected: int) -> List[Check]:
    out: List[Check] = []
    for tid, desc, zona, src, dst, proto, port, exp_antes, exp_despues, pt in FLOW_TESTS:
        r = service.traceroute(session, zona, src, dst, proto, port)
        exp = exp_antes if idx_expected == 0 else exp_despues
        ret = r.get("retorno")
        got = bool(r["permitido"])
        ok = got == exp
        detalle = _yn(got)
        if tid == "T5" and got:  # la navegación solo funciona si también vuelve la respuesta
            ok = ok and bool(ret and ret["permitido"])
            detalle += f" · retorno {_yn(bool(ret and ret['permitido']))}"
        out.append(Check(f"{fase}-{tid}", desc, _yn(exp) + (" · retorno PERMIT" if tid == "T5" and exp else ""),
                         detalle, ok, pt))
    return out


def _cell(cells: List[Dict[str, Any]], origen: str, destino: str) -> str:
    return next((c["estado"] for c in cells if c["origen"] == origen and c["destino"] == destino), "N/D")


def run_validation(verbose: bool = False) -> Dict[str, Any]:
    """Ejecuta toda la validación y devuelve {'checks': [...], 'remediacion': str, 'score_antes', 'score_despues'}."""
    log: Callable[[str], None] = print if verbose else (lambda _m: None)
    cfg_before = CFG_VULNERABLE.read_text(encoding="utf-8")
    checks: List[Check] = []

    # ------------------------------------------------------------------ ETAPA 1: auditoría vulnerable
    log("▶ Etapa 1: auditoría de la configuración vulnerable…")
    prev = service.preview_config(cfg_before, CFG_VULNERABLE.name)
    checks.append(Check("E1-SINTAXIS", "Batfish parsea toda la configuración (initIssues vacío)", "0 líneas no reconocidas",
                        f"{len(prev['sintaxis']['problemas'])} líneas", prev["sintaxis"]["disponible"] and not prev["sintaxis"]["problemas"]))
    checks.append(Check("E1-TOPOLOGIA", "Radiografía: 5 interfaces, 2 ACLs activas, 1 huérfana", "5 / 2 / 1",
                        f"{len(prev['interfaces'])} / {len(prev['acls_activas'])} / {len(prev['acls_huerfanas'])}",
                        (len(prev["interfaces"]), len(prev["acls_activas"]), len(prev["acls_huerfanas"])) == (5, 2, 1)))

    s1 = service.run_audit(cfg_before, CFG_VULNERABLE.name, sanitize=True, use_ai=False)
    score1 = s1.report.resumen.score_seguridad_actual
    cats = [h.categoria_problema for h in s1.report.hallazgos]
    for clave, etiqueta in [("Critical Shadowing", "Shadowing crítico (línea 20 tapada por la 10)"),
                            ("Shadowed Rule", "Regla redundante (línea 70 duplicada de la 60)"),
                            ("Telnet", "Telnet (TCP/23) expuesto en WAN"),
                            ("Temporal", "Regla temporal vencida sin retirar (RDP)"),
                            ("Permisividad", "ACL LAN con permit ip any any"),
                            ("Management Plane", "VTY con Telnet y sin access-class"),
                            ("Huérfana", "ACL huérfana sin interfaz")]:
        checks.append(Check(f"E1-HALLAZGO-{clave.split()[0].upper()}", f"Detecta: {etiqueta}", "detectado",
                            "detectado" if any(clave in c for c in cats) else "NO detectado", any(clave in c for c in cats)))
    checks.append(Check("E1-SCORE", "Postura inicial crítica (< 40/100)", "< 40", str(score1), score1 < 40))

    tipos = {(m.tipo, m.linea_afectada.split()[0]) for m in s1.math_findings}
    checks.append(Check("E1-BATFISH-SHADOW", "filterLineReachability: CRITICAL_SHADOWING línea 20 y REDUNDANT línea 70",
                        "2 anomalías formales", f"{sorted(tipos)}",
                        ("CRITICAL_SHADOWING", "20") in tipos and ("REDUNDANT", "70") in tipos))
    expos = {e["servicio"] for e in service.exposure(s1)["exposiciones"]}
    checks.append(Check("E1-EXPOSICION", "searchFilters: Telnet, HTTP y RDP alcanzables desde WAN", "Telnet+HTTP+RDP",
                        ", ".join(sorted(expos)), {"Telnet", "HTTP", "RDP"} <= expos))
    iso1 = service.isolation(s1)["celdas"]
    checks.append(Check("E1-AISLAMIENTO", "Matriz de aislamiento: LAN → GESTION en FUGA", "FUGA", _cell(iso1, "LAN", "GESTION"),
                        _cell(iso1, "LAN", "GESTION") == "FUGA"))
    checks += _flow_checks(s1, "ANTES", 0)

    # T5b: sin la regla 'established' el retorno se descarta (causa del fallo observado en Packet Tracer)
    sin_est = "\n".join(l for l in cfg_before.splitlines() if "established" not in l) + "\n"
    bf = BatfishAnalyzer()
    bf.connect()
    r = bf.simulate_packet(sin_est, "sin_established.cfg", "GigabitEthernet0/1.10", "192.168.10.10", "8.8.8.8", "TCP", 80,
                           network_name="validacion_lab")
    checks.append(Check("ANTES-T5b", "Sin 'permit tcp any any established' la ida pasa pero la respuesta se descarta",
                        "ida PERMIT · retorno DENY",
                        f"ida {_yn(r['permitido'])} · retorno {_yn(bool(r.get('retorno') and r['retorno']['permitido']))}",
                        r["permitido"] and r.get("retorno") is not None and not r["retorno"]["permitido"],
                        "PC-VENTAS-VLAN10: el ping funciona pero la web a 8.8.8.8 no carga"))

    # ------------------------------------------------------------------ ETAPA 2/3: Plan C + What-If
    log("▶ Etapa 2: Plan C (consultor determinístico) y simulación What-If…")
    lan = next(h for h in s1.report.hallazgos if h.acl_o_componente == "ACL_LAN_IN")
    dictamen = DeterministicFirewallAdvisor().consult_exception(lan, s1.topology, JUSTIFICACION_PLAN_C)
    s1.cache.setdefault("plan_c", {})[lan.id_hallazgo] = dictamen.plan_c_adaptado
    checks.append(Check("E3-PLAN-C", "Consultor de excepciones aprueba el Plan C de salida a Internet",
                        "EXCEPCION_VALIDA", dictamen.veredicto_arquitecto, dictamen.veredicto_arquitecto == "EXCEPCION_VALIDA"))
    decisiones = {h.id_hallazgo: ("C" if h.id_hallazgo == lan.id_hallazgo else "A") for h in s1.report.hallazgos}
    wi = service.what_if(s1, decisiones)
    cambios_iso = {(c["origen"], c["destino"], c["despues"]) for c in (wi["aislamiento"] or {}).get("cambios", [])}
    checks.append(Check("E4-WHATIF", "What-If con Plan A + Plan C: LAN → GESTION pasa a AISLADO",
                        "AISLADO", "AISLADO" if ("LAN", "GESTION", "AISLADO") in cambios_iso else str(cambios_iso),
                        ("LAN", "GESTION", "AISLADO") in cambios_iso))
    checks.append(Check("E4-POSTURA", "Postura proyectada ≥ 70", "≥ 70", str(wi["postura"]["proyectado"]),
                        wi["postura"]["proyectado"] >= 70))
    script = wi["scripts"]["remediacion"]

    # ------------------------------------------------------------------ ETAPA 5: re-auditoría
    log("▶ Etapa 5: aplicar la remediación y re-auditar…")
    cfg_after = apply_commands(cfg_before, script.splitlines())
    (HERE / "configs" / "r-borde-corp_remediado.cfg").write_text(cfg_after, encoding="utf-8")
    s2 = service.run_audit(cfg_after, "r-borde-corp_remediado.cfg", sanitize=True, use_ai=False)
    score2 = s2.report.resumen.score_seguridad_actual
    checks.append(Check("DESPUES-SCORE", "Postura final óptima (≥ 90/100)", "≥ 90", str(score2), score2 >= 90))
    checks.append(Check("DESPUES-HALLAZGOS", "0 hallazgos tras la remediación", "0", str(len(s2.report.hallazgos)),
                        len(s2.report.hallazgos) == 0))
    checks.append(Check("DESPUES-BATFISH", "0 reglas sombreadas o redundantes (Batfish)", "0", str(len(s2.math_findings)),
                        len(s2.math_findings) == 0))
    iso2 = service.isolation(s2)["celdas"]
    checks.append(Check("DESPUES-AISLAMIENTO", "Matriz de aislamiento: LAN → GESTION AISLADO", "AISLADO",
                        _cell(iso2, "LAN", "GESTION"), _cell(iso2, "LAN", "GESTION") == "AISLADO"))
    checks += _flow_checks(s2, "DESPUES", 1)

    return {"checks": checks, "remediacion": script, "score_antes": score1, "score_despues": score2}


def render_markdown(result: Dict[str, Any]) -> str:
    checks: List[Check] = result["checks"]
    ok = sum(c.ok for c in checks)
    lines = [
        "# Resultado de la validación automática del laboratorio",
        "",
        f"* **Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"* **Resultado:** {'✅ TODAS LAS PRUEBAS PASARON' if ok == len(checks) else '❌ HAY PRUEBAS FALLIDAS'} ({ok}/{len(checks)})",
        f"* **Postura de seguridad:** {result['score_antes']}/100 → {result['score_despues']}/100",
        "",
        "| Estado | Prueba | Esperado | Obtenido | Equivalente en Packet Tracer |",
        "| :-: | :-- | :-- | :-- | :-- |",
    ]
    for c in checks:
        lines.append(f"| {'✅' if c.ok else '❌'} | `{c.id}` {c.descripcion} | {c.esperado} | {c.obtenido} | {c.packet_tracer or '—'} |")
    lines += ["", "## Script de remediación generado por la aplicación (Plan A + Plan C)", "", "```cisco", result["remediacion"].strip(), "```", ""]
    return "\n".join(lines)


def main() -> int:
    result = run_validation(verbose=True)
    md = render_markdown(result)
    RESULTADOS.mkdir(exist_ok=True)
    (RESULTADOS / "RESULTADO_VALIDACION.md").write_text(md, encoding="utf-8")
    checks: List[Check] = result["checks"]
    print()
    for c in checks:
        print(f"{'PASS' if c.ok else 'FAIL'}  {c.id:<22} {c.descripcion}  →  {c.obtenido}")
    failed = [c for c in checks if not c.ok]
    print(f"\nPostura: {result['score_antes']} → {result['score_despues']} · {len(checks) - len(failed)}/{len(checks)} pruebas OK")
    print(f"Informe: {RESULTADOS / 'RESULTADO_VALIDACION.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
