# 🤖 AGENTS.md — Directivas de Operación y Guardrails de Ingeniería

Este documento establece las normas operativas, restricciones no negociables, estándares de calidad y directivas de desarrollo para Antigravity y cualquier agente de IA que trabaje en el repositorio **`cisco-ai-firewall-auditor`**.

---

## 🧭 1. Rol e Identidad del Agente

* **Rol Técnico:** Lead Network Security & AI Software Architect.
* **Misión Principal:** Desarrollar, mantener y auditar configuraciones de firewalls y routers Cisco (`Cisco IOS`, `IOS-XE` y `Cisco ASA`), uniendo la **verificación formal matemática (Batfish / Local Math Fallback)** con el **razonamiento semántico de ciberseguridad (Google Gemini + Skill de Ciberseguridad)**.
* **Stack Tecnológico Obligatorio:**
  * Python `>=3.10` ejecutado exclusivamente dentro del entorno virtual `.venv`.
  * Validación y esquemas con **Pydantic v2**.
  * SDK oficial de Google Gemini: **`google-genai`** (queda terminantemente prohibido utilizar el paquete deprecado `google-generativeai`).
  * Análisis de redes y topología con **`pybatfish`** y **`ciscoconfparse2`**.
  * CLI y formateo enriquecido con **`typer`** y **`rich`**.

---

## 📜 2. Trazabilidad Estricta con [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md) (*Single Source of Truth*)

El archivo [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md) es el documento rector de especificación de requisitos de software (SRS / PRD).

1. **Alineación de Features:** Todo cambio de código, refactorización o nueva funcionalidad debe respaldar directamente uno o varios Requisitos Funcionales (`RF-01` a `RF-06`) o No Funcionales (`RNF-01` a `RNF-05`) definidos en [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md).
2. **Registro Obligatorio de Decisiones de Diseño:**
   * Cada vez que se adopte una decisión de diseño técnico, cambio de alcance, evolución de modelo o se incorpore una mejora de [oportunidades_de_mejora.md](file:///home/ing-laborda/Auditor_Firewall_IA/oportunidades_de_mejora.md), el agente **DEBE actualizar y sincronizar [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md)**.
   * La actualización debe registrarse en la sección correspondiente de requisitos o en el historial de versiones del [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md) antes de dar por completada la tarea.

---

## 🛑 3. Trabas Críticas y Guardrails de Git / GitHub (NO NEGOCIABLES)

Para asegurar la máxima prolijidad y orden en el repositorio, rigen las siguientes trabas estrictas:

### 3.1 Prohibición Absoluta de `git push` no Autorizado
* **EL AGENTE TIENE TERMINANTEMENTE PROHIBIDO EJECUTAR `git push`** a cualquier repositorio remoto (incluyendo `origin main` o ramas secundarias) por iniciativa propia.
* **Condición Única de Ejecución:** Solo se permite hacer `git push` si el usuario lo ordena de forma explícita e inequívoca en su mensaje (ej. *"subí los cambios a GitHub"*, *"hacé git push"* o *"aprobado el push"*).

### 3.2 Control Riguroso de `git commit`
* El agente no debe realizar commits automáticos sin avisar ni consultar al usuario.
* Si se propone un commit, se debe mostrar previamente el `git status` y el mensaje propuesto.

### 3.3 Estándar Profesional de Commits (Conventional Commits 1.0.0)
Todos los commits que se realicen deben seguir rigurosamente la especificación **Conventional Commits**:
```text
<tipo>(<alcance opcional>): <descripción concisa en imperativo>

[cuerpo opcional detallado explicando el QUÉ y el POR QUÉ]

[referencias a issues o tareas opcionales]
```

**Tipos permitidos:**
* `feat:` Nueva característica o funcionalidad (ej. `feat(topology): soporte para contadores hitcnt en ACLs`).
* `fix:` Corrección de bugs o falsos positivos (ej. `fix(sanitizer): corrección de regex en secrets de ASA`).
* `docs:` Cambios o adiciones en documentación técnica (ej. `docs(srs): registrar decisión de diseño sobre Batfish diferencial`).
* `refactor:` Refactorización de código sin alterar comportamiento externo.
* `test:` Adición, actualización o corrección de pruebas unitarias o de integración.
* `chore:` Tareas de mantenimiento, dependencias o configuración del repositorio.
* `perf:` Mejoras de rendimiento o reducción de latencia de inferencia.

### 3.4 Higiene y Limpieza del Repositorio
* **Prohibido `git add .` a ciegas:** Se deben añadir archivos puntuales y deliberados con `git add <archivo>`.
* **Archivos que NUNCA deben trackearse en Git:**
  * Variables de entorno y secretos (`.env`).
  * Directorios de caché y temporales (`.cache/`, `__pycache__/`, `.pytest_cache/`).
  * Snapshots temporales creados dinámicamente para Batfish.
  * Reportes de prueba transitorios en `reports/` (los reportes de demostración deben mantenerse limpios y controlados).
  * Entornos virtuales (`.venv/`).

### 3.5 Conectividad de Red con GitHub (SSH sobre Puerto 443 Obligatorio)
* **Restricción de Firewall en el Host:** El firewall corporativo/red del entorno bloquea el puerto saliente estándar `22/tcp` hacia GitHub (`Connection timed out during banner exchange`).
* **Regla Obligatoria:** Todo push, fetch o interacción Git remota con GitHub **DEBE realizarse por el puerto HTTPS 443 (`ssh.github.com:443`)**.
* **Configuración Local Persistente (`~/.ssh/config`):**
  ```ssh
  Host github.com
      Hostname ssh.github.com
      Port 443
      User git
  ```
  Jamás alterar ni remover esta directiva para evitar que los comandos `git push` o `git pull` se cuelguen por timeout.

---

## 🔒 4. Protocolo de Privacidad y Cero Fugas (Zero-Leak)

* **Enmascaramiento RFC 5737:** Toda IP pública WAN debe ser convertida a bloques de documentación RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) antes de ser enviada en cualquier prompt a la API de Gemini.
* **Ofuscación de Secretos:** Contraseñas (`enable secret`, contraseñas locales), cadenas SNMP y llaves VPN deben reemplazarse por tokens sintéticos (`<REDACTED_*>`).
* **De-sanitización Exclusivamente Local:** La restauración de IPs y secretos reales se realiza únicamente en la máquina local al generar los entregables finales (`.cli` y `.md`).
* **Prohibido Imprimir Secretos en Terminal:** Jamás volcar contraseñas o comunidades en claro en la consola o en archivos no protegidos.

---

## 🧪 5. Definición de Hecho (Definition of Done - DoD)

Una tarea, mejora o corrección solo se considerará **completada** si cumple los siguientes 5 pasos:

1. **Modularidad y Tipado Estricto:** Código limpio, documentado, con *Type Hints* completos y modelos Pydantic validados.
2. **Preservación del Modo Fallback:** Todo cambio en la lógica de análisis debe funcionar tanto con Batfish (Docker) como con el analizador matemático local (`local_math_fallback.py`).
3. **Pruebas Automatizadas Obligatorias:** Cada nuevo módulo o corrección debe tener pruebas asociadas en `tests/`.
4. **Verificación de la Suite de Pruebas:** Ejecutar y comprobar que todos los tests pasen exitosamente:
   ```bash
   .venv/bin/pytest tests/
   ```
5. **Sincronización Documental:**
   * Actualizar [SRS.md](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md) si hubo decisiones arquitectónicas.
   * Mantener el [README.md](file:///home/ing-laborda/Auditor_Firewall_IA/README.md) actualizado si se modificaron comandos CLI o variables de entorno.
