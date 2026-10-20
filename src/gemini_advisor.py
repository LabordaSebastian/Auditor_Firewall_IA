import json
from pathlib import Path
from typing import List, Optional
from google import genai
from google.genai import types

from src.config import GEMINI_API_KEY, GEMINI_MODEL, SKILLS_DIR
from src.models import (
    ReporteAuditoriaFirewall,
    ContextoTopologia,
    HallazgoMatematico,
)


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
            "- Identifica además vulnerabilidades normativas (puertos inseguros expuestos en WAN, falta de deny ip any any log, permisividad excesiva, VTY inseguras, etc.).\n"
            "- Para cada hallazgo, proporciona un Plan A (Hardening Estricto) y un Plan B (Transición con Logging de prueba).\n"
            "- En 'controles_normativos', NUNCA pongas solo códigos secos (como 'CIS-IOS-3.1.4'). DEBES redactar cada control en formato para todo público (APB): 'CODIGO - Nombre Amigable: Explicación sencilla de 1 renglón de qué exige la norma'.\n"
            "- Devuelve ÚNICAMENTE la estructura JSON que valida exactamente contra el esquema requerido."
        )

        import time

        models_to_try = [self.model_name]
        for fallback_m in ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.8-flash"]:
            if fallback_m not in models_to_try:
                models_to_try.append(fallback_m)

        last_error = None
        for candidate_model in models_to_try:
            for attempt in range(2):
                try:
                    response = self.client.models.generate_content(
                        model=candidate_model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            temperature=0.1,
                            response_mime_type="application/json",
                            response_schema=ReporteAuditoriaFirewall,
                        ),
                    )
                    if response and response.text:
                        raw_text = response.text.strip()
                        if raw_text.startswith("```json"):
                            raw_text = raw_text[7:]
                        if raw_text.startswith("```"):
                            raw_text = raw_text[3:]
                        if raw_text.endswith("```"):
                            raw_text = raw_text[:-3]
                        return ReporteAuditoriaFirewall.model_validate_json(raw_text.strip())
                except Exception as e:
                    last_error = e
                    # Pausa breve si es error 503 o 429 por pico de tráfico
                    if "503" in str(e) or "429" in str(e) or "UNAVAILABLE" in str(e):
                        time.sleep(2)
                    continue

        raise RuntimeError(f"Error consultando Gemini tras reintentar con {models_to_try}: {last_error}")
