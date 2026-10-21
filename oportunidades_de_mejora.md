# 🚀 Roadmap y Oportunidades Claras de Mejora
**Proyecto:** Cisco AI Firewall Auditor & Change Impact Advisor (`cisco-ai-firewall-auditor`)  
**Fecha:** Octubre 2026  
**Objetivo:** Plan de evolución técnica para potenciar la precisión, automatización y adopción en entornos de producción.

---

## 📌 Resumen de Prioridades

| ID | Área / Módulo | Nivel de Esfuerzo | Impacto Técnico | Prioridad |
| :--- | :--- | :---: | :---: | :---: |
| **MEJ-01** | Validación Diferencial Post-Remediación (Batfish `compareFilters`) | Medio | Muy Alto | **P1 (Crítica)** |
| **MEJ-02** | Análisis de Contadores de Tráfico (`hitcnt=0` / Reglas Zombi) | Bajo | Alto | **P1 (Crítica)** |
| **MEJ-03** | Auditoría en Vivo vía SSH (Integración Netmiko / Scrapli) | Medio | Muy Alto | **P2 (Alta)** |
| **MEJ-04** | Parser Avanzado de Objetos y NAT en Cisco ASA (8.3+) | Medio | Alto | **P2 (Alta)** |
| **MEJ-05** | Dashboard Web Interactivo y Reportes en PDF | Medio | Alto | ✅ **Completada** |
| **MEJ-06** | Integración CI/CD y NetDevOps (GitHub Actions / GitLab CI) | Bajo | Medio | **P3 (Media)** |
| **MEJ-07** | Soporte Multi-Vendor (Fortinet FortiOS, Palo Alto PAN-OS, Juniper) | Alto | Muy Alto | **P4 (Evolutiva)** |
| **MEJ-08** | Optimización de Inferencia y Context Caching en Gemini | Bajo | Medio | **P4 (Evolutiva)** |

---

## 🛠️ Detalle de las Oportunidades de Mejora

### 1. Validación Diferencial Post-Remediación (Simulación Digital Twin)
* **Contexto:** Actualmente, el sistema genera scripts `.cli` de remediación (Plan A y Plan B) y de rollback basados en la evaluación de la configuración inicial.
* **Mejora:**
  1. Crear una función que aplique sintácticamente los comandos del script de remediación sobre la configuración original sanitizada, generando una *configuración candidata*.
  2. Cargar la configuración candidata en Batfish como un segundo snapshot.
  3. Ejecutar `bf.q.compareFilters(currentSnapshot, candidateSnapshot)` para certificar matemáticamente qué flujos exactos pasan de `PERMIT` a `DENY` o viceversa.
  4. Incorporar en el informe una sección de **"Certificación Matemática de No-Regresión"**, asegurando al 100% que la remediación no provocó efectos colaterales imprevistos.

---

### 2. Detección de Reglas Zombi mediante Análisis de `hitcnt`
* **Contexto:** Muchas auditorías se realizan sobre la salida de `show access-lists`, la cual incluye contadores de coincidencias (`hitcnt=X` o `(0 matches)`).
* **Mejora:**
  1. Extender [topology_extractor.py](file:///home/ing-laborda/Auditor_Firewall_IA/src/topology_extractor.py) para parsear contadores de hits por secuencia/línea.
  2. Si una regla tiene `hitcnt=0` y un comentario `remark` o fecha de creación antigua, catalogarla como regla inactiva/zombi.
  3. Proponer su depuración con riesgo operativo **NULO o BAJO**, reduciendo el tamaño de la tabla TCAM en routers y switches de capa 3.

---

### 3. Conexión Directa a Dispositivos de Red (Live Audit CLI)
* **Contexto:** Actualmente el usuario debe extraer manualmente el archivo `.cfg` o copiar y pegar el output de la terminal.
* **Mejora:**
  1. Incorporar un nuevo subcomando al CLI:
     ```bash
     python -m src.cli audit-device --host 10.0.0.1 --user admin --dialect ios --enable-pass
     ```
  2. Utilizar librerías como `netmiko` o `scrapli` para ejecutar de forma no interactiva:
     * `show running-config`
     * `show access-lists`
     * `show version`
  3. Pipeline directo: Descarga en memoria ➔ Sanitización inmediata ➔ Auditoría ➔ Presentación de resultados sin dejar archivos crudos desprotegidos en disco.

---

### 4. Parser Profundo de `object-group` y Lógica NAT en Cisco ASA (8.3+)
* **Contexto:** En Cisco ASA versión 8.3 en adelante, el orden de evaluación de NAT y ACL exige que las reglas de entrada en la interfaz `outside` utilicen la **IP privada real (pre-NAT)** del servidor destino. Además, se emplean grupos de objetos anidados (`object-group network` y `object-group service`).
* **Mejora:**
  1. Extender las consultas de Batfish (`bf.q.searchFilters`) y [topology_extractor.py](file:///home/ing-laborda/Auditor_Firewall_IA/src/topology_extractor.py) para auditar la resolución completa de `object-group` anidados y reglas NAT pre/post-traducción en Cisco ASA.
  2. Implementar una heurística que detecte si una ACL de ASA está apuntando por error a la IP pública externa en vez de a la IP pre-NAT, alertando sobre descartes involuntarios de tráfico legítimo.

---

### 5. Dashboard Web Moderno y Exportación a PDF (MEJ-05) `[IMPLEMENTADO]`
* **Estado:** ✅ **Completado e Implementado (Octubre 2026)** — Ver [RF-07](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md), [RF-08](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md), [RF-09](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md) y [ADR-004](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md).
* **Contexto:** La CLI con `Rich` es excelente para ingenieros de redes, pero los auditores de seguridad corporativa y gerentes C-Level prefieren reportes gráficos y ejecutivos.
* **Componentes Entregados:**
  1. **Plataforma Web Reactiva y Dark Mode Glassmorphism (`src/web/`):**
     * Backend REST sobre FastAPI (`src/web/app.py`, `src/web/routes.py`, `src/web/service.py`).
     * Subida de `.cfg` por drag-and-drop y demos pre-cargadas de Cisco IOS y ASA.
     * Switch de **Sanitización Reversible Zero-Leak** (opcional, activado por defecto) con modal de mapeo biunívoco y visor diff sintáctico en tiempo real.
     * Indicadores de **Postura de Seguridad** (SVG Gauges circulares: Actual vs. Proyectada).
     * **Distribución Gráfica de Riesgo:** Gráficos vectoriales Donut SVG de Severidad y Taxonomía con filtrado interactivo.
     * Explorador de hallazgos con visualización tabular de colisiones y selector **Plan A vs Plan B** con diff de comandos.
  2. **Grafo Topológico Interactivo y Digital Twin Batfish:**
     * Lienzo interactivo en Canvas con motor de física elástica en JavaScript puro (60 FPS, repulsión coulombiana, resortes, zoom y pan).
     * Deducción autónoma de zonas de seguridad (WAN, DMZ, LAN, Gestión) e interfaces.
     * **Simulador "El Camino del Paquete" (`bf.q.traceroute`):** Animación de partículas de tráfico en vivo con detección de reglas de bloqueo u omisión.
     * **Matriz de Aislamiento y Perímetros (Cross-Zone Matrix):** Verificación de fugas perimétricas con Batfish.
     * **Digital Twin Diferencial (`bf.q.compareFilters`):** Certificación matemática de cambios de flujo con fallback por hallazgo.
  3. **Exportación Corporativa en PDF (`src/pdf_generator.py`):**
     * Generador de PDF en Python puro con `fpdf2` (portada institucional, métricas, donuts vectoriales, fichas de hallazgos y scripts CLI).
     * Hoja de estilos de impresión `@media print` para exportación nativa de alta fidelidad.
  4. **Comando CLI Integrado:** `python -m src.cli serve --host 127.0.0.1 --port 8000 [--open-browser]`.


---

### 6. Integración CI/CD y NetDevOps (GitOps Firewall Policy)
* **Contexto:** Las empresas modernas gestionan sus configuraciones de red como código (*Infrastructure as Code* / NetDevOps).
* **Mejora:**
  1. Crear una GitHub Action / GitLab CI pipeline que ejecute:
     ```bash
     python -m src.cli audit configs/fw-borde.cfg --fail-on-critical
     ```
  2. Bloquear *Pull Requests* si se detectan:
     * Reglas con *Critical Shadowing* (un `permit` que anula a un `deny`).
     * Exposición de puertos inseguros a WAN (Telnet/23, HTTP/80, SMB/445).
     * Líneas VTY sin `access-class` restrictiva.

---

### 7. Expansión Multi-Vendor
* **Contexto:** Muchas organizaciones cuentan con entornos heterogéneos donde Cisco convive con otras marcas líderes.
* **Mejora:**
  * **Fortinet FortiOS:** Parseo de políticas `firewall policy` (`srcintf`, `dstintf`, `service`). Batfish tiene soporte nativo para FortiOS.
  * **Palo Alto Networks (PAN-OS):** Parseo de `security rules` basadas en aplicaciones (App-ID) y zonas.
  * **Juniper JunOS:** Parseo de jerarquías `security policies from-zone to-zone`.

---

### 8. Optimización de Inferencia y Context Caching con Google Gemini
* **Contexto:** Actualmente, el prompt del sistema envía los archivos normativos ([SKILL.md](file:///home/ing-laborda/Auditor_Firewall_IA/skills/cisco-security-advisor/SKILL.md) y `references/`) en cada llamada.
* **Mejora:**
  1. Habilitar **Context Caching** (`client.caches.create()`) del SDK `google-genai` para mantener en caché permanente las directivas CIS Benchmark y DISA STIG.
  2. Reducir los costos de tokens y la latencia de respuesta a menos de 2 segundos por auditoría en ejecuciones masivas por lotes.
