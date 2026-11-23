import json
import time
from pathlib import Path
from typing import List, Optional, Type, TypeVar
from google import genai
from google.genai import types
from pydantic import BaseModel

from src.config import GEMINI_API_KEY, GEMINI_MODEL, SKILLS_DIR
from src.deterministic_advisor import DeterministicFirewallAdvisor, enrich_report_zone_context
from src.models import (
    ContextoTopologia,
    DictamenExcepcionIA,
    HallazgoFirewall,
    HallazgoMatematico,
    ReporteAuditoriaFirewall,
)

TModel = TypeVar("TModel", bound=BaseModel)
_FALLBACK_MODELS = (
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
    "gemini-3.8-flash",
)
_REQUEST_TIMEOUT_MS = 25_000


class GeminiFirewallAdvisor:
    """
    Motor cognitivo de ciberseguridad impulsado por Gemini.
    Inyecta la Skill especializada y exige salida estructurada bajo Pydantic.
    """

    def __init__(self, api_key: str = GEMINI_API_KEY, model_name: str = GEMINI_MODEL):
        self.api_key = api_key
        self.model_name = model_name
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def _load_skill_knowledge(self) -> str:
        """Carga y consolida SKILL.md y los archivos de referencias normativas."""
        knowledge_parts = []

        skill_md = SKILLS_DIR / "SKILL.md"
        if skill_md.exists():
            knowledge_parts.append(f"=== METODOLOGÍA GENERAL DE AUDITORÍA ===\n{skill_md.read_text(encoding='utf-8')}")

        refs_dir = SKILLS_DIR / "references"
        if refs_dir.exists():
            for ref_file in sorted(refs_dir.glob("*.md")):
                title = ref_file.stem.replace("-", " ").upper()
                knowledge_parts.append(f"=== REFERENCIA: {title} ===\n{ref_file.read_text(encoding='utf-8')}")

        return "\n\n".join(knowledge_parts)

    def analyze(
        self,
        sanitized_config: str,
        topology: ContextoTopologia,
        math_findings: List[HallazgoMatematico],
    ) -> ReporteAuditoriaFirewall:
        """
        Envía la configuración sanitizada, el contexto topológico y los hallazgos matemáticos
        a Gemini para generar el reporte de auditoría y plan de decisión estructurado.
        """
        if not self.client:
            raise ValueError("GEMINI_API_KEY no configurada. Por favor revisa tu archivo .env.")

        system_instruction = (
            "Eres el Cisco AI Firewall Auditor & Change Impact Advisor. "
            "Tu misión es auditar configuraciones de firewalls y routers Cisco con máximo rigor técnico, "
            "evaluar el radio de impacto operativo (Blast Radius) y formular opciones de remediación Plan A vs Plan B. "
            "DEBES cumplir estrictamente las normas CIS Controls, DISA STIG y NIST CSF provistas en tus directivas.\n\n"
            f"{self._load_skill_knowledge()}"
        )

        user_prompt = (
            "A continuación tienes los datos de la auditoría técnica para evaluar:\n\n"
            f"1. RESUMEN DE TOPOLOGÍA DETECTADA:\n"
            f"{topology.model_dump_json(indent=2)}\n\n"
            f"2. RESULTADOS DE VERIFICACIÓN FORMAL MATEMÁTICA (BATFISH / DETERMINÍSTICO):\n"
            f"{json.dumps([f.model_dump() for f in math_findings], indent=2)}\n\n"
            f"3. CONFIGURACIÓN SANITIZADA DEL DISPOSITIVO:\n"
            f"```cisco\n{sanitized_config}\n```\n\n"
            "INSTRUCCIONES CRÍTICAS:\n"
            "- Debes incluir TODOS los hallazgos matemáticos confirmados por Batfish/verificador.\n"
            "- Si 'reglas_zombi' en la topología contiene reglas con hit_count=0 (hitcnt=0 / 0 matches), repórtalas como reglas zombi/inactivas candidatas a depuración con impacto operativo NULO o BAJO para optimizar memoria TCAM.\n"
            "- Identifica además vulnerabilidades normativas (puertos inseguros expuestos en WAN, falta de deny ip any any log, permisividad excesiva, VTY inseguras, etc.).\n"
            "- Para cada hallazgo, proporciona un Plan A (Hardening Estricto) y un Plan B (Transición con Logging de prueba).\n"
            "- En 'desglose_visual', desglosa con total precisión la(s) regla(s): si es una colisión/shadowing/redundancia genera 2 filas comparativas ('Regla Superior (Bloqueadora)' vs 'Regla Inferior (Oculta/Tapada)') con rol, secuencia, acción (PERMIT/DENY), protocolo, origen, destino, puerto y estado del flujo. Si es una regla individual (exposición WAN, permisividad, regla temporal), genera 1 fila ('Regla Única').\n"
            "- En 'punto_critico_error', redacta 1 frase concisa y clara remarcando con precisión quirúrgica dónde reside el choque o la vulnerabilidad.\n"
            "- CRITERIO ARQUITECTÓNICO DE ZONAS Y USO DE 'ANY' (MUY IMPORTANTE):\n"
            "  * Evalúa siempre la dirección del flujo entre zonas ('sentido_flujo_zonas'): no es lo mismo una regla de SALIDA desde una zona segura hacia una menos segura (ej. LAN ➔ WAN/Internet) que una regla de ENTRADA desde una zona insegura (WAN ➔ DMZ/LAN).\n"
            "  * En 'veredicto_flexibilidad_any' y 'criterio_arquitectonico_ia', emite una opinión de arquitecto pragmático: explica cuándo SÍ es válido dar libertad con 'any' (ej. destino 'any' en salida de LAN a Internet para navegación web/DNS, u origen 'any' hacia un único host público en DMZ) y qué controles compensatorios aplicar (acotar el origen a la subred LAN para evitar spoofing, bloquear puertos laterales críticos como SMB/445 y exigir reglas específicas hacia la DMZ), en vez de exigir a ciegas que todo sea hiper-específico cuando eso rompería la salida a Internet.\n"
            "- En 'controles_normativos', NUNCA pongas solo códigos secos (como 'CIS-IOS-3.1.4'). DEBES redactar cada control en formato para todo público (APB): 'CODIGO - Nombre Amigable: Explicación sencilla de 1 renglón de qué exige la norma'.\n"
            "- Devuelve ÚNICAMENTE la estructura JSON que valida exactamente contra el esquema requerido."
        )

        return self._generate_structured(
            prompt=user_prompt,
            schema=ReporteAuditoriaFirewall,
            system_instruction=system_instruction,
            topology=topology,
        )

    def _models_sequence(self) -> List[str]:
        models_to_try = [self.model_name]
        for fallback_m in _FALLBACK_MODELS:
            if fallback_m not in models_to_try:
                models_to_try.append(fallback_m)
        return models_to_try

    def _generate_structured(
        self,
        prompt: str,
        schema: Type[TModel],
        system_instruction: Optional[str] = None,
        topology: Optional[ContextoTopologia] = None,
    ) -> TModel:
        """Invoca Gemini con timeout acotado y rotación automática entre modelos ante errores 503/429."""
        models_to_try = self._models_sequence()
        last_error: Optional[Exception] = None
        cfg_kwargs = {
            "temperature": 0.1,
            "response_mime_type": "application/json",
            "response_schema": schema,
            "http_options": types.HttpOptions(timeout=_REQUEST_TIMEOUT_MS),
        }
        if system_instruction is not None:
            cfg_kwargs["system_instruction"] = system_instruction
        gen_config = types.GenerateContentConfig(**cfg_kwargs)

        # Primera pasada rápida por toda la lista de modelos; si el primero falla, reintenta una vez al final
        for candidate_model in [*models_to_try, self.model_name]:
            try:
                response = self.client.models.generate_content(
                    model=candidate_model,
                    contents=prompt,
                    config=gen_config,
                )
                if response and response.text:
                    raw_text = response.text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                    parsed = schema.model_validate_json(raw_text)
                    if isinstance(parsed, ReporteAuditoriaFirewall) and topology is not None:
                        return enrich_report_zone_context(parsed, topology)  # type: ignore[return-value]
                    return parsed
            except Exception as e:
                last_error = e
                msg = str(e)
                if "503" in msg or "429" in msg or "UNAVAILABLE" in msg:
                    time.sleep(1)
                continue

        raise RuntimeError(f"Error consultando Gemini tras reintentar con {models_to_try}: {last_error}")

    def consult_exception(
        self,
        finding: HallazgoFirewall,
        topology: ContextoTopologia,
        justificacion: str,
    ) -> DictamenExcepcionIA:
        """
        Consultor interactivo de excepciones operativas: evalúa la justificación del usuario
        según el sentido de confianza entre zonas (ej. salida de zona segura LAN ➔ WAN donde se
        requiere libertad de destino 'any') y diseña un Plan C con controles compensatorios.
        Si Gemini no está disponible, utiliza el motor determinístico de arquitectura.
        """
        if not self.client:
            return DeterministicFirewallAdvisor().consult_exception(finding, topology, justificacion)

        prompt = (
            "Eres un Arquitecto Senior de Ciberseguridad de Redes Cisco. El administrador del firewall "
            "te plantea una necesidad operativa real sobre el siguiente hallazgo:\n\n"
            f"- Hallazgo: {finding.id_hallazgo} ({finding.categoria_problema}) en {finding.acl_o_componente}\n"
            f"- Regla actual: {finding.linea_o_regla_afectada}\n"
            f"- Sentido de zonas: {finding.sentido_flujo_zonas}\n"
            f"- Topología: {topology.model_dump_json()}\n"
            f"- Contexto / Excepción planteada por el operador: \"{justificacion}\"\n\n"
            "INSTRUCCIONES DE CRITERIO ARQUITECTÓNICO:\n"
            "1. Evalúa con criterio pragmático el sentido entre zonas: si es tráfico de SALIDA de una zona más segura a una menos segura (ej. LAN ➔ WAN/Internet), reconoce explícitamente que usar destino 'any' es razonable y necesario para navegar a Internet, siempre que se acote el ORIGEN a la subred interna (anti-spoofing), se proteja la DMZ y se bloqueen puertos críticos (ej. SMB 445).\n"
            "2. Si es un servidor público en DMZ (WAN ➔ DMZ), reconoce que el origen 'any' es necesario, pero exige destino 'host' específico y puerto acotado.\n"
            "3. Diseña un 'plan_c_adaptado' con comandos Cisco CLI válidos que respeten la libertad operativa solicitada aplicando controles compensatorios inteligentes.\n"
            "Devuelve ÚNICAMENTE el JSON compatible con DictamenExcepcionIA."
        )
        try:
            res = self._generate_structured(prompt=prompt, schema=DictamenExcepcionIA)
            res.fuente = "gemini"
            return res
        except Exception:
            pass
        return DeterministicFirewallAdvisor().consult_exception(finding, topology, justificacion)
