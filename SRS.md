# Documento de Especificación de Requisitos de Software (SRS / PRD)
**Proyecto:** `cisco-ai-firewall-auditor`  
**Rol del Agente en Google Antigravity:** Lead Network Security Software Engineer & AI Architect  
**Entorno Base de Desarrollo:** Xubuntu Linux (8 GB+ RAM, Docker Engine, Python 3.10+)

---

## 1. Visión General del Proyecto

### 1.1 Nombre del Proyecto
**Cisco AI Firewall Auditor & Change Impact Advisor (`cisco-ai-firewall-auditor`)**

### 1.2 Propósito Principal
Herramienta CLI profesional en Python que audita configuraciones de firewalls y routers Cisco (`show running-config` y `show access-lists`), combinando **verificación formal matemática (Batfish)** con **razonamiento semántico de ciberseguridad (Gemini 2.5 Pro + Skill especializada)**. Su propósito no es solo listar fallas, sino actuar como un **Asistente de Decisiones y Gestión de Cambios**, generando un informe práctico de impacto en la red (*Blast Radius*), opciones de mitigación (Plan A vs. Plan B) y scripts `.cli` de remediación y *rollback* listos para producción.

### 1.3 Problema Exacto que Resuelve
1. **Alucinación aritmética de los LLMs en redes:** Los modelos de lenguaje fallan al calcular solapamiento de subredes, máscaras *wildcard* invertidas (`0.0.15.255`) y jerarquías anidadas de `object-group` en archivos de miles de líneas. Se resuelve delegando el álgebra booleana de paquetes a **Batfish**.
2. **Falta de contexto de seguridad en motores determinísticos:** Herramientas como Batfish detectan reglas solapadas (*shadowed*), pero no comprenden que un `permit tcp any any eq 23` o un `remark Regla temporal 2023` es una vulnerabilidad crítica. Se resuelve con **Gemini 2.5 Pro** dotado de una **Skill de Ciberseguridad (CIS Benchmark / DISA STIG / NIST CSF)**.
3. **Miedo al corte de servicio en producción:** Tocar una ACL activa puede interrumpir tráfico legítimo. Se resuelve mediante una **Matriz de Efectos e Impacto Operativo** y análisis diferencial que clasifica cambios de riesgo cero frente a cambios que requieren transición gradual.
4. **Fuga de información sensible hacia APIs externas:** Enviar configuraciones crudas a la nube expone IPs públicas WAN, cadenas SNMP y secretos. Se resuelve mediante una capa de **Sanitización Reversible Local** previa al envío a la API de Gemini.

---

## 2. Stack Tecnológico y Arquitectura

### 2.1 Entorno e Infraestructura Local
* **Sistema Operativo Host:** Xubuntu Linux (mínimo 8 GB de RAM, 2.5 GB libres en disco).
* **Contenedorización:** Docker & Docker Compose ejecutando `batfish/allinone:latest` en los puertos locales `9997` y `9996`.
* **Lenguaje Core:** Python `>=3.10` gestionado mediante entorno virtual `.venv`.

### 2.2 Librerías y Dependencias Principales (`requirements.txt`)
* **Motor de IA:** `google-genai>=1.0.0` (SDK oficial actual de Google Gemini; **prohibido** usar el paquete legado deprecado `google-generativeai`). Modelo objetivo: `gemini-2.5-pro` (y soporte configurable para `gemini-2.5-flash` en pruebas rápidas `[Sugerido por la IA]`).
* **Verificación Formal de Red:** `pybatfish>=0.58.0` (cliente Python para consultas de diagramas de decisión binaria BDD sobre ACLs y ruteo).
* **Parser de Topología Cisco:** `ciscoconfparse2>=0.4.0` (extracción jerárquica de interfaces, descripciones, niveles de seguridad, `object-group` y asociación de ACLs).
* **Sanitización y Ofuscación:** `netconan>=0.14.0` apoyado por un motor nativo con la librería estándar `ipaddress` y `re` para mapeo determinístico reversible de IPs públicas (no-RFC 1918) y credenciales.
* **Validación de Datos y Estructuras:** `pydantic>=2.0.0` (esquemas estrictos para `response_schema` de Gemini y modelos internos).
* **Interfaz CLI y Reportes:** `typer>=0.9.0` y `rich>=13.0.0` (tablas en terminal, barras de progreso, paneles de severidad y exportación Markdown/CLI).
* **Configuración:** `python-dotenv>=1.0.0` para manejo seguro de `GEMINI_API_KEY`.
* **Persistencia Local `[Sugerido por la IA]`:** `sqlite3` (librería estándar) o almacenamiento JSON local en `.cache/` para guardar el mapa de traducción de IPs sanitizadas (*lookup table*) y el historial de auditorías.

### 2.3 Arquitectura del Pipeline (6 Etapas)
1. **Capa 1 - Sanitización Local (`sanitizer.py`):** Lee el `.cfg` original, enmascara IPs públicas WAN, contraseñas y comunidades SNMP, preserva IPs privadas RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) para no alterar la topología interna, y guarda un diccionario local de reversión (`lookup_map.json`).
2. **Capa 2 - Extracción de Contexto (`topology_extractor.py`):** Usa `ciscoconfparse2` sobre la configuración sanitizada para vincular cada ACL con su interfaz aplicada (`ip access-group` en IOS / `access-group` en ASA), dirección (`in`/`out`), `description` de interfaz, `security-level` y comentarios `remark`.
3. **Capa 3 - Análisis Matemático (`batfish_analyzer.py`):** Sube el snapshot sanitizado al contenedor `batfish/allinone` y ejecuta consultas determinísticas (`filterLineReachability`, `searchFilters`, `compareFilters`).
4. **Capa 4 - Motor Cognitivo (`gemini_advisor.py` + `skills/`):** Inyecta la Skill de Ciberseguridad (`SKILL.md` + `references/`) en `system_instruction` (o Context Cache), adjunta la configuración sanitizada + el mapa de topología + el JSON matemático de Batfish, y solicita a `gemini-2.5-pro` una evaluación estructurada bajo esquema Pydantic.
5. **Capa 5 - Validación Diferencial `[Sugerido por la IA]`:** Opcionalmente genera un snapshot candidato con las reglas propuestas y ejecuta `compareFilters` en Batfish para certificar matemáticamente qué flujos cambian antes de emitir el reporte.
6. **Capa 6 - De-sanitización y Entrega (`cli.py`):** Reemplaza localmente los tokens ofuscados (`PUBLIC_WAN_IP_1`) por las IPs reales usando el `lookup_map.json` local, y escribe en `reports/` el informe ejecutivo/técnico `.md`, el detalle `.json` y los scripts `.cli` (remediación y rollback).

---

## 3. Casos de Uso Core y Flujo de Usuario

### Flujo Principal: Auditoría Completa de un Firewall Cisco
1. **Preparación:** El administrador de red coloca un archivo de configuración Cisco (ej. `snapshots/lab_cisco_vuln/configs/fw-borde-cisco.cfg`) en el directorio del proyecto y verifica que el contenedor Docker de Batfish esté activo.
2. **Ejecución en CLI:** El usuario ejecuta en la terminal de Xubuntu:
   ```bash
   python -m src.cli audit snapshots/lab_cisco_vuln/configs/fw-borde-cisco.cfg --sanitize --dialect auto --output reports/
   ```
3. **Pre-procesamiento Seguro:**
   * La consola muestra con `Rich` qué IPs públicas y secretos fueron enmascarados localmente antes de salir a Internet.
   * El extractor de topología informa cuántas interfaces, zonas, `object-group` y ACLs activas o huérfanas (no aplicadas a ninguna interfaz) se detectaron.
4. **Verificación Determinística en Batfish:**
   * El CLI conecta a `localhost:9997`, inicializa el snapshot y obtiene en milisegundos todas las líneas inalcanzables (*Shadowed Rules*), líneas redundantes y flujos críticos abiertos desde interfaces externas.
5. **Razonamiento con Gemini Pro y Skill de Ciberseguridad:**
   * El sistema carga los archivos `SKILL.md`, `cis-cisco-controls.md` y `blast-radius-matrix.md`.
   * Envía el payload combinado a `gemini-2.5-pro` con `temperature=0.1` y validación Pydantic.
6. **Revisión de Resultados y Toma de Decisiones:**
   * El usuario visualiza un resumen ejecutivo en la terminal clasificado por severidad (`CRITICA`, `ALTA`, `MEDIA`, `BAJA`).
   * Abre el archivo generado `reports/auditoria_fw-borde-cisco.md` donde revisa, para cada regla problemática:
     * **Por qué es vulnerable** y qué control CIS/NIST incumple.
     * **Cómo mejora a la red** aplicar el cambio.
     * **Efecto operativo (*Blast Radius*)** en la red actual.
     * **Decisión:** Aplicar **Plan A (Cierre/Hardening directo)** o **Plan B (Transición segura agregando `log` para monitorear hits antes de bloquear)**.
7. **Implementación y Rollback:**
   * El usuario toma el archivo `reports/remediacion_fw-borde-cisco.cli` (ya de-sanitizado localmente con sus IPs reales) para aplicarlo en ventana de mantenimiento, contando con `reports/rollback_fw-borde-cisco.cli` para revertir en segundos si ocurre algún imprevisto.

---

## 4. Requisitos Funcionales (MVP)

### RF-01: Módulo de Sanitización Reversible (`src/sanitizer.py`)
* **RF-01.1:** Debe identificar todas las direcciones IPv4 en el archivo de configuración y clasificar mediante la librería `ipaddress` cuáles son privadas (`is_private` RFC 1918) y cuáles son públicas/globales.
* **RF-01.2:** Las IPs privadas internas deben conservarse (o mapearse opcionalmente bajo flag `--sanitize-internal` `[Sugerido por la IA]`), mientras que toda IP pública debe ser reemplazada por una IP sintética determinística del bloque de documentación RFC 5737 (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) para que **Batfish siga reconociéndola como una IP sintácticamente válida** sin exponer la IP real a Gemini Pro.
* **RF-01.3:** Debe ofuscar cadenas sensibles de Cisco: `enable secret`, `enable password`, `username ... password/secret`, `snmp-server community`, `tacacs-server key`, `radius-server key`, `crypto isakmp key` y `pre-shared-key` usando `netconan` o expresiones regulares específicas de Cisco.
* **RF-01.4:** Debe almacenar el diccionario bidireccional `{ip_sintetica: ip_real}` en memoria y en un archivo temporal local (excluido por `.gitignore`) para restaurar los valores reales en los archivos finales `.md` y `.cli`.

### RF-02: Extractor de Topología y Contexto Cisco (`src/topology_extractor.py`)
* **RF-02.1:** Soportar dialectos **Cisco IOS / IOS-XE** (`ip access-list standard/extended`, `ip access-group`, `line vty` con `access-class`) y **Cisco ASA** (`access-list`, `access-group ... interface`, `security-level`, `object network`, `object service`, `object-group` anidados y reglas NAT 8.3+).
* **RF-02.2:** Detectar **ACLs Huérfanas** (listas de acceso declaradas en la configuración pero no vinculadas a ninguna interfaz, línea VTY, `class-map` ni proceso de ruteo/NAT) `[Sugerido por la IA]`.
* **RF-02.3:** Extraer los comentarios (`remark`) asociados a cada secuencia o línea de ACL y los contadores de impacto (`hitcnt=X`) si el archivo proviene de un `show access-lists`.

### RF-03: Motor Matemático con Batfish (`src/batfish_analyzer.py`)
* **RF-03.1:** Empaquetar automáticamente el archivo `.cfg` sanitizado en la estructura de carpetas requerida por Batfish (`snapshot/configs/<filename>.cfg`) e inicializar la sesión con `bf.init_snapshot()`.
* **RF-03.2:** Ejecutar `bf.q.filterLineReachability().answer().frame()` para identificar con certeza matemática:
  * **Shadowed Rules (Reglas pisadas):** Líneas que jamás serán alcanzadas porque una línea superior las engloba.
  * **Redundant Rules:** Líneas que tienen la misma acción (`permit`/`deny`) que una regla superior o posterior sin alterar el comportamiento.
  * **Critical Shadowing (`Permit` sobre `Deny`):** Casos críticos donde una regla permisiva superior anula una regla de bloqueo específica inferior.
* **RF-03.3:** Ejecutar `bf.q.searchFilters()` para verificar exposición de puertos críticos de gestión/servicios (TCP 21, 22, 23, 80, 445, 3389; UDP 161, 162) desde fuentes externas.
* **RF-03.4:** Proveer un método `verify_candidate_diff(baseline_snapshot, candidate_snapshot)` que ejecute `bf.q.compareFilters()` para listar exactamente qué flujos cambian entre la configuración actual y la remediación propuesta `[Sugerido por la IA]`.

### RF-04: Paquete de Conocimiento — Skill de Ciberseguridad (`skills/cisco-security-advisor/`)
* **RF-04.1:** Implementar el archivo `SKILL.md` estructurado en **7 Fases Obligatorias de Auditoría**:
  1. Expansión de `object` y `object-group` (y validación de IPs reales pre-NAT en Cisco ASA 8.3+).
  2. Evaluación de Shadowing Crítico reportado por Batfish.
  3. Detección de Permisividad Excesiva (`permit ip any any`, máscaras wildcard excesivamente amplias como `0.0.255.255` hacia servidores críticos, puertos de texto plano o gestión expuestos en WAN).
  4. Higiene y Ciclo de Vida (reglas temporales vencidas en `remark`, reglas sin uso con `hitcnt=0`, ACLs huérfanas).
  5. Trazabilidad Forense en Data Plane (verificación de cierre explícito `deny ip any any log` antes del *implicit deny* silencioso).
  6. Seguridad del Management Plane (`access-class` en `line vty`, `transport input ssh`, restricción de ASDM/SSH y SNMP en ASA).
  7. Generación de Remediación Segura y Rollback en sintaxis exacta de Cisco CLI.
* **RF-04.2 (Formato APB de Controles Normativos):** Incluir en `references/cis-cisco-controls.md` y forzar en el prompt de Gemini que los controles **CIS Cisco Benchmark**, **DISA STIG** y **NIST CSF** se devuelvan en formato transparente APB (`CODIGO - Nombre Amigable: Explicación sencilla de qué exige la norma`), eliminando siglas crípticas aisladas en los informes técnicos y ejecutivos.
* **RF-04.3:** Incluir en `references/blast-radius-matrix.md` la guía de clasificación de impacto operativo (*Riesgo Nulo*, *Riesgo Bajo*, *Riesgo Medio*, *Riesgo Alto*) y los criterios para redactar el **Plan A (Hardening Directo)** y el **Plan B (Transición con Logging)**.

### RF-05: Integración con Gemini Pro (`src/gemini_advisor.py`)
* **RF-05.1:** Utilizar `from google import genai` y `from google.genai import types`.
* **RF-05.2:** Inyectar el contenido consolidado de `SKILL.md` y los archivos de `references/` dentro de `types.GenerateContentConfig(system_instruction=...)`. Soportar opcionalmente *Context Caching* (`client.caches.create()`) cuando el volumen de referencias supere el umbral mínimo de tokens.
* **RF-05.3:** Forzar salida JSON estricta mediante `response_mime_type="application/json"` y `response_schema=ReporteAuditoriaFirewall` (modelo Pydantic).

### RF-06: Generador de Informes y Scripts CLI (`src/cli.py` + `src/report_builder.py` `[Sugerido por la IA]`)
* **RF-06.1:** Exportar el informe completo en Markdown (`reports/auditoria_<nombre>.md`) con:
  * Resumen Ejecutivo y Puntaje de Postura de Seguridad (0 a 100).
  * Mapa de Interfaces y ACLs auditadas.
  * Tabla resumen de hallazgos por severidad y radio de impacto (*Blast Radius*).
  * Ficha detallada por cada hallazgo:
    * **Desglose Tabular Visual (ADR-003):** Tabla comparativa de colisión de reglas (Regla Superior vs Inferior) o desglose de regla única.
    * **Punto Crítico del Error:** Alerta destacada remarcando el vector de riesgo o choque exacto.
    * Controles normativos en formato explicativo APB (ADR-001).
    * Diagnóstico técnico, beneficio para la red y análisis de efectos colaterales (*Blast Radius*).
    * Opciones de decisión (**Plan A: Hardening Estricto** vs. **Plan B: Transición con Monitoreo**).
    * Scripts Cisco CLI listos para aplicar y revertir (Rollback).
* **RF-06.2:** Exportar archivos independientes `.cli` (`remediacion_<nombre>.cli` y `rollback_<nombre>.cli`) con sintaxis válida de modo configuración de Cisco (`configure terminal`, números de secuencia de ACL o recreación ordenada de ACEs, y `end` / `write memory` comentados por seguridad).
* **RF-06.3:** Incluir en el repositorio un archivo de configuración de laboratorio (`snapshots/lab_cisco_vuln/configs/fw-borde-cisco.cfg`) con **al menos 7 vulnerabilidades representativas inyectadas** (Shadowed rule, Permit sobre Deny, Telnet/23 expuesto en WAN, `remark` temporal vencido de proveedor, `permit ip any any` interno sin segmentación, falta de `deny ip any any log` explícito, y VTY sin `access-class` o con Telnet habilitado) para pruebas inmediatas y demostración en GitHub.

### RF-07: Dashboard Web Interactivo y API REST (`src/web/` + `src.cli serve`) `[MEJ-05]`
* **RF-07.1:** Exponer una API REST construida sobre **FastAPI** (`src/web/app.py`, `src/web/routes.py`) con endpoints para diagnóstico del sistema (`/api/status`), auditoría en vivo con subida de archivo `.cfg` (`/api/audit`), carga instantánea de demos de laboratorio (`/api/demo/{sample_id}`), sesiones en memoria (`/api/session/{id}`) y descarga de entregables (`.pdf`, `.md`, `.cli`).
* **RF-07.2:** Proveer una interfaz gráfica moderna en Vanilla HTML5/CSS/JS (Dark Mode + Glassmorphism, Google Fonts `Outfit` y `JetBrains Mono`) servida estáticamente sin dependencias de Node.js o npm.
* **RF-07.3:** Proveer un switch interactivo de Sanitización Reversible Zero-Leak (RFC 5737 y secretos) habilitado por defecto (`Enabled = True`), con visualizador modal transparente de mapeo biunívoco y diff interactivo línea a línea (Original vs. Sanitizado).
* **RF-07.4:** Integrar el comando de terminal `python -m src.cli serve [--host 127.0.0.1] [--port 8000] [--open-browser]` para iniciar el servidor uvicorn directamente desde la CLI de Typer.

### RF-08: Grafo Topológico Interactivo y Digital Twin Batfish (`src/web/graph.py` + `src/batfish_analyzer.py`) `[MEJ-05]`
* **RF-08.1:** Generar automáticamente un grafo topológico de red L3 con deducción de zonas de seguridad (WAN, DMZ, LAN, Gestión) e interfaces asociadas a partir de las configuraciones y tablas de Batfish.
* **RF-08.2:** Implementar un lienzo interactivo en Canvas con motor de física elástica en JavaScript puro (repulsión coulombiana, resortes, zoom, pan, arrastre de nodos a 60 FPS) y drawer lateral de ficha técnica por nodo o enlace.
* **RF-08.3 (El Camino del Paquete):** Permitir simulación visual de tráfico en tiempo real mediante `bf.q.traceroute()` y `bf.q.testFilters()` con animación de partículas lumínicas sobre los enlaces, onda expansiva de colisión y banner indicando la regla exacta que permitió o bloqueó el flujo.
* **RF-08.4:** Proveer una Matriz de Aislamiento y Perímetros (Cross-Zone Matrix) que evalúe alcanzabilidad con Batfish e identifique fugas perimétricas hacia servicios críticos.
* **RF-08.5:** Proveer verificación diferencial Digital Twin (`compareFilters`) comparando la configuración actual contra el Plan A o Plan B, con fallback por hallazgo para cambios en plano de gestión (VTY).

### RF-09: Distribución Gráfica de Riesgo y Exportación PDF Corporativa (`src/pdf_generator.py`) `[MEJ-05]`
* **RF-09.1:** Renderizar en el dashboard dos gráficos vectoriales Donut SVG: **Matriz de Hallazgos por Severidad** y **Taxonomía por Tipo de Vulnerabilidad**, con centro oscuro totalizador, porcentajes calculados dinámicamente y filtrado interactivo al hover o clic.
* **RF-09.2:** Generar reportes ejecutivos en PDF de diseño corporativo formal listos para entrega C-Level utilizando **`fpdf2`** (Python puro, sin dependencias nativas de SO), incluyendo portada institucional, posturas de seguridad actual vs. proyectada, gráficos donut vectoriales, topología y fichas completas de hallazgos con scripts CLI.
* **RF-09.3:** Proveer hoja de estilos `@media print` para exportación directa de alta fidelidad desde el navegador web.


---

## 5. Requisitos No Funcionales

* **RNF-01 (Privacidad y Seguridad Zero-Leak):** Ninguna dirección IP pública real ni cadena de contraseña/comunidad SNMP del archivo original debe ser transmitida en el payload HTTP hacia la API de Google Gemini cuando el flag `--sanitize` esté activo (activo por defecto `[Sugerido por la IA]`).
* **RNF-02 (Compatibilidad Sintáctica con Batfish):** El sanitizador no debe reemplazar IPs públicas por cadenas de texto arbitrarias (como `"PUBLIC_IP_1"`), ya que eso rompería el parser de Batfish. Debe mapearlas biunívocamente a direcciones IPv4 válidas reservadas para documentación/benchmarking (RFC 5737 / RFC 2544: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`) conservando la longitud de prefijo o máscara *wildcard* exacta.
* **RNF-03 (Determinismo y Precisión):** La temperatura del modelo Gemini debe fijarse en `0.1`. Ninguna afirmación sobre reglas solapadas (*shadowed*) debe originarse por inferencia libre del LLM si no está respaldada por el output de Batfish o del verificador de subredes.
* **RNF-05 (Verificación Formal Estricta - Batfish Obligatorio):** La verificación matemática de alcanzabilidad de reglas, solapamiento y topología se delega de forma exclusiva al motor formal Batfish en contenedor Docker (`localhost:9997`). Se descontinúa cualquier motor heurístico local para asegurar rigor de grado telecomunicaciones (cero alucinaciones). Si el servicio no está disponible, el sistema alerta de forma bloqueante instruyendo iniciar el contenedor.

---

## 6. Esquema de Datos Inicial (Modelado)

### 6.1 Esquemas Pydantic para Salida Estructurada de Gemini (`src/models.py`)

```python
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class SeveridadEnum(str, Enum):
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"

class NivelImpactoEnum(str, Enum):
    NULO = "NULO (Cambio Seguro / Regla Inalcanzable)"
    BAJO = "BAJO (Solo agrega trazabilidad o limpia objetos huérfanos)"
    MEDIO = "MEDIO (Restringe puertos/subredes; requiere verificar contadores)"
    ALTO = "ALTO (Bloquea flujos permisivos activos; riesgo de corte si no se audita antes)"

class OpcionDecision(BaseModel):
    nombre_plan: str = Field(description="Ej: Plan A (Hardening Estricto) o Plan B (Transición con Monitoreo)")
    descripcion_accion: str
    efecto_en_red: str
    comandos_cli_implementacion: List[str]
    comandos_cli_rollback: List[str]

class HallazgoFirewall(BaseModel):
    id_hallazgo: str = Field(description="Identificador único, ej: FW-CISCO-001")
    acl_o_componente: str = Field(description="Nombre de la ACL, interfaz o línea VTY afectada")
    linea_o_regla_afectada: str = Field(description="Comando o ACE exacto donde reside el problema")
    severidad: SeveridadEnum
    categoria_problema: str = Field(
        description="Ej: Shadowed Rule, Critical Shadowing (Permit sobre Deny), Exposición WAN, Permisividad Excesiva, Higiene/Regla Temporal, Falta de Logging, Management Plane"
    )
    confirmado_por_batfish: bool = Field(description="True si fue validado matemáticamente por Batfish")
    controles_normativos: List[str] = Field(description="Controles CIS Cisco Benchmark, DISA STIG o NIST CSF aplicables")
    diagnostico_tecnico: str = Field(description="Explicación detallada de por qué la regla es vulnerable o ineficiente")
    como_mejora_la_red: str = Field(description="Beneficio directo de seguridad o rendimiento al corregir esta regla")
    nivel_impacto_operativo: NivelImpactoEnum
    analisis_blast_radius: str = Field(description="Qué flujos, usuarios o servicios podrían verse afectados al aplicar el cambio")
    plan_a_recomendado: OpcionDecision
    plan_b_conservador: OpcionDecision

class ResumenEjecutivo(BaseModel):
    hostname_detectado: str
    dialecto_cisco: str = Field(description="Cisco IOS / IOS-XE / Cisco ASA")
    score_seguridad_actual: int = Field(ge=0, le=100)
    score_seguridad_proyectado: int = Field(ge=0, le=100)
    total_hallazgos: int
    resumen_gerencial: str
    orden_prioridad_implementacion: List[str] = Field(
        description="Lista ordenada de IDs de hallazgos sugiriendo qué aplicar primero (empezando por impacto operativo NULO/BAJO)"
    )

class ReporteAuditoriaFirewall(BaseModel):
    resumen: ResumenEjecutivo
    hallazgos: List[HallazgoFirewall]
```

### 6.2 Esquema del Mapa de Sanitización Local (`lookup_map.json` `[Sugerido por la IA]`)

```json
{
  "metadata": {
    "source_file": "fw-borde-cisco.cfg",
    "timestamp": "2026-10-17T19:00:00Z",
    "sanitization_version": "1.0"
  },
  "ip_mappings": {
    "198.51.100.10": "200.45.112.18",
    "203.0.113.5": "181.30.22.100"
  },
  "secret_mappings": {
    "<REDACTED_SECRET_1>": "$1$eR2p$K8s9...",
    "<REDACTED_SNMP_1>": "CorpRoCommunity2025"
  }
}
```

---

## 7. Estructura de Directorios Sugerida

```text
cisco-ai-firewall-auditor/
├── docker-compose.yml                  # Servicio batfish/allinone con límite de RAM configurado
├── .env.example                        # GEMINI_API_KEY, GEMINI_MODEL=gemini-2.5-pro, BATFISH_HOST=localhost
├── .gitignore                          # Ignora .venv/, .env, .cache/, lookup_map.json
├── requirements.txt                    # Dependencias fijadas del proyecto
├── README.md                           # Documentación profesional para GitHub (arquitectura, instalación en Xubuntu, uso)
├── skills/
│   └── cisco-security-advisor/
│       ├── SKILL.md                    # Metodología de 7 fases para auditoría de firewalls Cisco
│       └── references/
│           ├── cis-cisco-controls.md   # Controles CIS IOS/ASA, DISA STIG y NIST CSF
│           ├── cisco-acl-antipatterns.md # Puertos críticos, wildcards riesgosas, NAT ASA 8.3+
│           └── blast-radius-matrix.md  # Matriz para evaluar impacto en red y diseñar Plan A / Plan B
├── snapshots/
│   └── lab_cisco_vuln/
│       └── configs/
│           ├── fw-borde-ios.cfg        # Config de prueba Cisco IOS-XE con 7 vulnerabilidades inyectadas
│           └── fw-borde-asa.cfg        # Config de prueba Cisco ASA con object-groups y shadowing [Sugerido por la IA]
├── src/
│   ├── __init__.py
│   ├── config.py                       # Carga de variables de entorno y rutas [Sugerido por la IA]
│   ├── models.py                       # Modelos Pydantic (ReporteAuditoriaFirewall, HallazgoFirewall, etc.)
│   ├── sanitizer.py                    # Sanitización reversible de IPs públicas (RFC 5737) y secretos
│   ├── topology_extractor.py           # Parser con ciscoconfparse2 (Interfaces, ACLs, Remarks, Huérfanas)
│   ├── batfish_analyzer.py             # Cliente pybatfish (filterLineReachability, searchFilters, compareFilters)
│   ├── gemini_advisor.py               # Integración con google-genai, carga de Skill y validación Pydantic
│   ├── report_builder.py               # De-sanitización local y renderizado de archivos .md, .json y .cli [Sugerido por la IA]
│   └── cli.py                          # Punto de entrada con Typer y Rich (comandos: audit, sanitize-preview, check-env)
├── tests/                              # Tests unitarios para sanitizer, parser, reportes y Batfish
│   ├── test_sanitizer.py
│   ├── test_topology_extractor.py
│   ├── test_report_builder.py
│   └── test_batfish_analyzer.py
└── reports/                            # Salida de informes Markdown y scripts .cli de remediación y rollback
    └── .gitkeep
```

---

## 8. Instrucciones de Implementación para el Agente en Google Antigravity `[Sugerido por la IA]`

1. **Orden de construcción recomendado:**
   * **Paso 1:** Crear los archivos de configuración base (`docker-compose.yml`, `requirements.txt`, `.env.example`, `.gitignore`) y los modelos de datos en `src/models.py`.
   * **Paso 2:** Redactar de forma exhaustiva los archivos de conocimiento en `skills/cisco-security-advisor/` (`SKILL.md` y los 3 archivos en `references/`).
   * **Paso 3:** Crear las configuraciones vulnerables de laboratorio en `snapshots/lab_cisco_vuln/configs/` (`fw-borde-ios.cfg` y `fw-borde-asa.cfg`) asegurando que contengan casos reales de *shadowing*, puertos de gestión expuestos, reglas temporales vencidas e IP públicas simuladas para poner a prueba el sanitizador.
   * **Paso 4:** Implementar `src/sanitizer.py`, `src/topology_extractor.py` y `src/batfish_analyzer.py`.
   * **Paso 5:** Implementar `src/gemini_advisor.py` usando exclusivamente el SDK `google-genai` (`client = genai.Client()`), `src/report_builder.py` y la interfaz de línea de comandos en `src/cli.py`.
   * **Paso 6:** Generar un `README.md` completo en español (con diagramas Mermaid de arquitectura y guía paso a paso en Xubuntu) listo para publicar en GitHub.

---

## 9. Registro de Decisiones de Diseño e Historial Técnico (ADR)

### ADR-001 (2026-10-20): Adopción de Formato APB para Controles Normativos
* **Estado:** Aprobado e Implementado.
* **Contexto:** La salida original de controles normativos en `HallazgoFirewall.controles_normativos` presentaba únicamente siglas secas (`CIS-IOS-3.1.4`, `DISA STIG NET-0405`, `NIST CSF PR.AC-4`), resultando críptica para audiencias no especializadas y gerencia.
* **Decisión Técnica:** 
  1. Forzar en el esquema Pydantic y en el prompt del sistema que Gemini devuelva cada control bajo la estructura:  
     `CODIGO - Nombre Amigable: Explicación sencilla de qué exige la norma`.
  2. Modificar [report_builder.py](file:///home/ing-laborda/Auditor_Firewall_IA/src/report_builder.py) para renderizar cada control como una viñeta individual con icono `🛡️` bajo la sección *Controles Normativos Incumplidos (Estándares de Seguridad)*.
* **Impacto:** Reportes 100% legibles y transparentes para cualquier lector, sin necesidad de consultar manualmente los frameworks externos.

### ADR-002 (2026-10-20): Descontinuación del Fallback Heurístico Local y Adopción Exclusiva de Batfish
* **Estado:** Aprobado e Implementado.
* **Contexto:** Se contaba con un motor fallback en Python puro (`local_math_fallback.py`) para operar en ausencia de Docker/Batfish. Si bien aportaba portabilidad básica, sus heurísticas regex tenían limitaciones estructurales con objetos complejos de Cisco ASA, rangos de puertos y no permitían análisis diferencial ni traceroutes virtuales.
* **Decisión Técnica:**
  1. Dar de baja `src/local_math_fallback.py` y remover el flag `--fallback-local-math` del CLI.
  2. Establecer **Batfish (Docker)** como requisito de infraestructura formal obligatorio en la Etapa 3 del pipeline.
  3. Crear suite de pruebas directas en [tests/test_batfish_analyzer.py](file:///home/ing-laborda/Auditor_Firewall_IA/tests/test_batfish_analyzer.py).
* **Impacto:** Nivel enterprise garantizado (BDDs de Microsoft/UCLA), cero falsos positivos matemáticos, simplificación del codebase y habilitación directa para simulación digital twin diferencial.

### ADR-003 (2026-10-20): Visualización Tabular de Colisión de Reglas y Punto Crítico del Choque
* **Estado:** Aprobado e Implementado.
* **Contexto:** En auditorías con reglas superpuestas o anomalías perimétricas, presentar la regla afectada únicamente como una cadena plana de texto dificultaba distinguir de un vistazo el choque exacto entre direcciones, máscaras wildcard y puertos.
* **Decisión Técnica:**
  1. Incorporar el modelo Pydantic `DesgloseReglaVisual` (`rol`, `secuencia`, `accion`, `protocolo`, `origen`, `destino`, `puerto`, `estado_flujo`) y el atributo `punto_critico_error` en `HallazgoFirewall`.
  2. Instruir al modelo Gemini para generar comparativas de 2 filas en conflictos (*Regla Superior (Bloqueadora)* vs *Regla Inferior (Oculta/Tapada)*) o de 1 fila en reglas individuales vulnerables, junto con un resumen de punto crítico.
  3. Renderizar en [report_builder.py](file:///home/ing-laborda/Auditor_Firewall_IA/src/report_builder.py) una tabla visual Markdown con insignias de color (🟢 `PERMIT`, 🔴 `DENY`) y un bloque destacado de alerta (`> ⚠️ Punto Crítico del Error`).
* **Impacto:** Comprensión visual inmediata del choque de reglas (*Top-Down* de Cisco) para administradores y auditores, manteniendo la de-sanitización automática de IPs y la compatibilidad con el JSON estructurado.

### ADR-004 (2026-10-21): Dashboard Web Interactivo, Grafo Digital Twin, Sanitización Transparente y PDF FPDF2 (MEJ-05)
* **Estado:** Aprobado e Implementado.
* **Contexto:** La CLI basada en `Rich` es óptima para operadores de terminal, pero gerentes de seguridad C-Level y auditores corporativos requieren explorar la topología de red visualmente, entender colisiones, simular tráfico en tiempo real y exportar informes PDF imprimibles. Asimismo, se requería total transparencia sobre qué información es enmascarada antes de interactuar con la IA.
* **Decisión Técnica:**
  1. **Backend REST:** Adopción de **FastAPI** + **Uvicorn** (`src/web/`), acoplado a la CLI mediante `python -m src.cli serve`.
  2. **Frontend Ligero Sin Build:** Vanilla HTML5, CSS Glassmorphism Dark Mode (tokens HSL, `backdrop-filter`, fuentes `Outfit` y `JetBrains Mono`) y JavaScript puro a 60 FPS, eliminando complejidad de toolchains de npm.
  3. **Grafo Topológico Interactivo con Física Elástica:** Representación con Canvas y algoritmo force-directed de repulsión/resortes, clasificación automática de zonas de seguridad (WAN, DMZ, LAN, Gestión) y drawer de ficha técnica contextual al clic.
  4. **Simulador "El Camino del Paquete":** Integración directa con `bf.q.traceroute()` y `bf.q.testFilters()` con animación sobre el grafo e indicación exacta de reglas de descarte.
  5. **Sanitización Opcional y Transparente:** Switch por defecto activo (`Enabled = True`), modal de mapeo biunívoco y visor diff sintáctico en tiempo real (Original vs. Sanitizado).
  6. **Distribución Gráfica de Riesgo:** Donut Charts vectoriales SVG de Severidad y Taxonomía con centro totalizador y filtrado interactivo.
  7. **Generador PDF Corporativo:** Implementación con **`fpdf2`** (Python puro, sin dependencias nativas de Cairo/Pango) complementada con estilos `@media print`.
* **Impacto:** Interfaz unificada de grado telecomunicaciones que transforma la suite en un Digital Twin interactivo accesible para operadores y comités ejecutivos.