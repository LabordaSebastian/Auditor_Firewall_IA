"""Servicio de orquestación del dashboard web (MEJ-05): sesiones de auditoría en memoria."""
import difflib
import json
import re
import threading
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.config import BATFISH_HOST, BATFISH_PORT, GEMINI_API_KEY, GEMINI_MODEL, REPORTS_DIR, SNAPSHOTS_DIR
from src.config_patcher import apply_commands
from src.gemini_advisor import GeminiFirewallAdvisor
from src.models import ContextoTopologia, HallazgoMatematico, ReporteAuditoriaFirewall
from src.report_builder import ReportBuilder
from src.sanitizer import ConfigSanitizer
from src.topology_extractor import CiscoTopologyExtractor
from src.web.graph import build_graph, build_zones

DEMO_DIR = SNAPSHOTS_DIR / "lab_cisco_vuln" / "configs"
MAX_SESSIONS = 20


class SessionNotFound(KeyError):
    """La sesión de auditoría solicitada no existe (o fue desalojada de memoria)."""


@dataclass
class AuditSession:
    id: str
    filename: str
    base_name: str
    sanitize: bool
    raw_config: str
    sanitized_config: str
    lookup_map: Dict[str, Any]
    topology: ContextoTopologia
    math_findings: List[HallazgoMatematico]
    report: Optional[ReporteAuditoriaFirewall]
    report_source: str  # gemini | cache | none
    ai_error: Optional[str]
    graph: Dict[str, Any]
    zones: List[Dict[str, Any]]
    cache: Dict[str, Any] = field(default_factory=dict)


class AuditService:
    def __init__(self) -> None:
        self.sessions: Dict[str, AuditSession] = {}
        self._bf_lock = threading.Lock()  # los snapshots Batfish comparten nombre de red

    # ------------------------------------------------------------------ utilidades
    @staticmethod
    def _deep_desanitize(data: Any, lookup_map: Dict[str, Any]) -> Any:
        if not lookup_map.get("ip_mappings") and not lookup_map.get("secret_mappings"):
            return data
        return json.loads(ConfigSanitizer.desanitize(json.dumps(data, ensure_ascii=False), lookup_map))

    @staticmethod
    def _resanitize(text: str, lookup_map: Dict[str, Any]) -> str:
        """real -> sintético (inverso de desanitize) para entradas del usuario y comandos CLI."""
        result = text
        for synth, real in lookup_map.get("ip_mappings", {}).items():
            result = re.sub(r"\b" + re.escape(real) + r"\b", synth, result)
        for token, secret in lookup_map.get("secret_mappings", {}).items():
            result = result.replace(secret, token)
        return result

    def _analyzer(self) -> BatfishAnalyzer:
        analyzer = BatfishAnalyzer(host=BATFISH_HOST, port=BATFISH_PORT)
        analyzer.connect()
        return analyzer

    def get(self, session_id: str) -> AuditSession:
        if session_id not in self.sessions:
            raise SessionNotFound(session_id)
        return self.sessions[session_id]

    # ------------------------------------------------------------------ estado
    def status(self) -> Dict[str, Any]:
        batfish_ok, batfish_detail = True, f"Conectado en {BATFISH_HOST}:{BATFISH_PORT}"
        try:
            self._analyzer()
        except BatfishUnavailableError as exc:
            batfish_ok, batfish_detail = False, str(exc)
        return {
            "batfish": {"ok": batfish_ok, "detalle": batfish_detail},
            "gemini": {"ok": bool(GEMINI_API_KEY), "modelo": GEMINI_MODEL},
        }

    def list_demos(self) -> List[Dict[str, str]]:
        demos = []
        for cfg in sorted(DEMO_DIR.glob("fw-borde-*.cfg")):
            sample_id = cfg.stem.replace("fw-borde-", "")
            demos.append({"id": sample_id, "archivo": cfg.name,
                          "etiqueta": "Cisco ASA (object-groups)" if sample_id == "asa" else "Cisco IOS / IOS-XE"})
        return demos

    def demo_path(self, sample_id: str) -> Path:
        path = DEMO_DIR / f"fw-borde-{re.sub(r'[^a-z0-9]', '', sample_id.lower())}.cfg"
        if not path.exists():
            raise FileNotFoundError(sample_id)
        return path

    # ------------------------------------------------------------------ auditoría
    def run_audit(self, raw_config: str, filename: str, sanitize: bool = True,
                  use_ai: bool = True, prefer_cache: bool = False) -> AuditSession:
        base_name = Path(filename).stem
        sanitizer = ConfigSanitizer()
        if sanitize:
            sanitized, lookup_map = sanitizer.sanitize(raw_config, source_filename=filename)
        else:
            sanitized, lookup_map = raw_config, {"metadata": {}, "ip_mappings": {}, "secret_mappings": {}}

        topology = CiscoTopologyExtractor(sanitized).extract_topology()

        with self._bf_lock:
            math_findings = self._analyzer().analyze_snapshot(sanitized, config_filename=filename)

        report, source, ai_error = self._build_report(
            sanitized, topology, math_findings, lookup_map, base_name, use_ai, prefer_cache
        )

        findings_by_acl = Counter(h.acl_o_componente for h in report.hallazgos) if report else Counter(
            m.filtro_nombre for m in math_findings
        )
        graph = build_graph(topology, dict(findings_by_acl))
        zones = build_zones(topology)
        graph_display = self._deep_desanitize(graph, lookup_map)

        session = AuditSession(
            id=uuid.uuid4().hex[:12], filename=filename, base_name=base_name, sanitize=sanitize,
            raw_config=raw_config, sanitized_config=sanitized, lookup_map=lookup_map, topology=topology,
            math_findings=math_findings, report=report, report_source=source, ai_error=ai_error,
            graph=graph_display, zones=zones,
        )
        if len(self.sessions) >= MAX_SESSIONS:
            self.sessions.pop(next(iter(self.sessions)))
        self.sessions[session.id] = session
        return session

    def _build_report(self, sanitized: str, topology: ContextoTopologia,
                      math_findings: List[HallazgoMatematico], lookup_map: Dict[str, Any],
                      base_name: str, use_ai: bool, prefer_cache: bool):
        cache_path = REPORTS_DIR / f"auditoria_{base_name}.json"

        def from_cache() -> Optional[ReporteAuditoriaFirewall]:
            if cache_path.exists():
                return ReporteAuditoriaFirewall.model_validate_json(cache_path.read_text(encoding="utf-8"))
            return None

        if prefer_cache or not use_ai:
            cached = from_cache()
            if cached:
                return cached, "cache", None
            if not use_ai:
                return None, "none", None

        if not GEMINI_API_KEY:
            cached = from_cache()
            return (cached, "cache", None) if cached else (None, "none", "GEMINI_API_KEY no configurada")
        try:
            report = GeminiFirewallAdvisor().analyze(sanitized, topology, math_findings)
            report = ReportBuilder(REPORTS_DIR).desanitize_report(report, lookup_map)
            return report, "gemini", None
        except Exception as exc:  # fallo de red/cuota: degradar a caché si existe
            cached = from_cache()
            err = f"{type(exc).__name__}: {str(exc)[:200]}"
            return (cached, "cache", err) if cached else (None, "none", err)

    # ------------------------------------------------------------------ payloads
    def summary(self, s: AuditSession) -> Dict[str, Any]:
        rep = s.report
        sev = Counter(h.severidad.value for h in rep.hallazgos) if rep else Counter()
        cat = Counter(h.categoria_problema for h in rep.hallazgos) if rep else Counter()
        return {
            "id": s.id, "archivo": s.filename, "hostname": s.topology.hostname, "dialecto": s.topology.dialecto,
            "sanitizar": s.sanitize,
            "sanitizacion": {
                "ips": len(s.lookup_map.get("ip_mappings", {})),
                "secretos": len(s.lookup_map.get("secret_mappings", {})),
            },
            "fuente_reporte": s.report_source, "error_ia": s.ai_error,
            "resumen": rep.resumen.model_dump() if rep else None,
            "hallazgos": [h.model_dump(mode="json") for h in rep.hallazgos] if rep else [],
            "distribucion": {"severidad": dict(sev), "categoria": dict(cat)},
            "matematicos": self.shadowing(s),
            "grafo": s.graph,
        }

    def shadowing(self, s: AuditSession) -> List[Dict[str, Any]]:
        data = [m.model_dump() for m in s.math_findings]
        return self._deep_desanitize(data, s.lookup_map)

    def sanitization_view(self, s: AuditSession) -> Dict[str, Any]:
        view = ConfigSanitizer.build_sanitization_view(s.raw_config, s.sanitized_config, s.lookup_map)
        view["activa"] = s.sanitize
        return view

    # ------------------------------------------------------------------ Batfish interactivo
    def traceroute(self, s: AuditSession, zona_origen: str, src_ip: str, dst_ip: str,
                   protocolo: str, puerto: Optional[int]) -> Dict[str, Any]:
        zone = next((z for z in s.zones if z["nombre"] == zona_origen), None)
        if not zone:
            raise ValueError(f"Zona de origen desconocida: {zona_origen}")
        src = self._resanitize(src_ip, s.lookup_map)
        dst = self._resanitize(dst_ip, s.lookup_map)
        with self._bf_lock:
            result = self._analyzer().simulate_packet(
                s.sanitized_config, s.filename, zone["interfaz"], src, dst, protocolo, puerto
            )
        return self._deep_desanitize(result, s.lookup_map)

    def isolation(self, s: AuditSession) -> Dict[str, Any]:
        if "isolation" not in s.cache:
            with self._bf_lock:
                cells = self._analyzer().check_zone_isolation(s.sanitized_config, s.filename, s.zones)
            s.cache["isolation"] = cells
        return {"zonas": [z["nombre"] for z in s.zones], "celdas": s.cache["isolation"]}

    def exposure(self, s: AuditSession) -> Dict[str, Any]:
        if "exposure" not in s.cache:
            wan_acls: List[str] = []
            for z in s.zones:
                if z["zona"] == "WAN":
                    iface = s.topology.interfaces[z["interfaz"]]
                    wan_acls += [a for a in (iface.acl_in,) if a and a not in wan_acls]
            with self._bf_lock:
                rows = self._analyzer().scan_exposed_ports(s.sanitized_config, s.filename, wan_acls)
            s.cache["exposure"] = self._deep_desanitize(rows, s.lookup_map)
        return {"exposiciones": s.cache["exposure"]}

    def _compare_commands(self, s: AuditSession, commands: List[str]) -> Dict[str, Any]:
        """Aplica `commands` sobre la config sanitizada y compara con Batfish (compareFilters)."""
        candidate = apply_commands(s.sanitized_config, commands)
        acls = sorted(set(re.findall(r"^ip access-list (?:extended|standard) (\S+)", candidate, re.M))
                      | set(re.findall(r"^access-list (\S+)", candidate, re.M)))
        with self._bf_lock:
            result = self._analyzer().compare_candidate(s.sanitized_config, candidate, s.filename, acls)
        result["candidate"] = candidate
        result["acls"] = acls
        return result

    def digital_twin_diff(self, s: AuditSession, plan: str) -> Dict[str, Any]:
        """
        Digital Twin diferencial (MEJ-01): certifica con compareFilters qué flujos cambian al
        aplicar el Plan A/B. Si la comparación conjunta falla (p. ej. cambios de plano de gestión
        VTY que Batfish no puede comparar), se evalúa cada hallazgo por separado.
        """
        if not s.report:
            raise ValueError("No hay hallazgos con planes de remediación para simular.")
        plan = plan.upper()
        per_finding: List[tuple] = []
        for h in s.report.hallazgos:
            opcion = h.plan_a_recomendado if plan == "A" else h.plan_b_conservador
            per_finding.append((h.id_hallazgo, [self._resanitize(c, s.lookup_map) for c in opcion.comandos_cli_implementacion]))
        all_commands = [c for _, cmds in per_finding for c in cmds]

        combined = self._compare_commands(s, all_commands)
        cambios, errores = combined["cambios"], combined["errores"]
        no_verificables: List[Dict[str, str]] = []
        modo = "conjunto"

        if errores:  # fallback: un candidato por hallazgo
            modo = "por_hallazgo"
            cambios, errores = [], []
            for fid, cmds in per_finding:
                res = self._compare_commands(s, cmds)
                if res["errores"]:
                    no_verificables.append({"id": fid, "motivo": "Batfish no puede comparar este cambio (p. ej. plano de gestión VTY / ACL estándar)."})
                    continue
                for c in res["cambios"]:
                    c["id_hallazgo"] = fid
                    cambios.append(c)

        diff_lines = list(difflib.unified_diff(
            s.sanitized_config.splitlines(), combined["candidate"].splitlines(),
            "actual", f"candidata_plan_{plan}", lineterm="", n=1,
        ))
        result = {
            "plan": plan, "modo": modo, "cambios": cambios, "total_cambios": len(cambios),
            "errores": errores, "no_verificables": no_verificables, "diff_config": diff_lines,
        }
        return self._deep_desanitize(result, s.lookup_map)


    # ------------------------------------------------------------------ descargas
    def build_cli(self, s: AuditSession) -> Dict[str, str]:
        if not s.report:
            raise ValueError("Sin reporte de IA: no hay scripts disponibles.")
        rem, roll = ReportBuilder(REPORTS_DIR)._render_cli_scripts(s.report, s.base_name)
        return {"remediacion": rem, "rollback": roll}

    def build_markdown(self, s: AuditSession) -> str:
        if not s.report:
            raise ValueError("Sin reporte de IA: no hay informe disponible.")
        md = ReportBuilder(REPORTS_DIR)._render_markdown(s.report, s.topology)
        return ConfigSanitizer.desanitize(md, s.lookup_map)


service = AuditService()
