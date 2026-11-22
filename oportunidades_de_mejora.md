# 🚀 Roadmap y Oportunidades Claras de Mejora
**Proyecto:** Cisco AI Firewall Auditor & Change Impact Advisor (`cisco-ai-firewall-auditor`)  
**Fecha:** Octubre 2026  
**Objetivo:** Plan de evolución técnica para potenciar la precisión, automatización y adopción en entornos de producción.

---

## 📌 Resumen de Prioridades y Roadmap de 4 Fases

| ID / Fase | Área / Módulo | Nivel de Esfuerzo | Impacto Técnico | Estado / Prioridad |
| :--- | :--- | :---: | :---: | :---: |
| **Fase 1** | **Vista Previa Pre-Flight, Sintaxis (`initIssues`) y Guía de Demos** | Medio | Alto | ✅ **Completada e Implementada** |
| **Fase 2** | **Digital Twin Robusto (Fix ASA 500) y Reachability Simbólica (`reachability`, `testFilters`, `routes`, `layer3Edges`)** | Medio | Muy Alto | ✅ **Completada e Implementada** (RF-11 / ADR-006) |
| **Fase 3** | **Priorización Top-Down, Centro de Decisiones What-If y Botón de Reset** | Medio | Muy Alto | ✅ **Completada e Implementada** (RF-12 / ADR-007) |
| **Fase 4** | **Blast Radius Diferencial (`differentialReachability`), Feedback a la IA y Refactorización de Reportes** | Medio | Muy Alto | **Siguiente (Fase 4)** |
| **MEJ-09** | **UX Modular por Pestañas (Tabs) y Visor Web Nativo del Reporte Ejecutivo (con Refactor Estético)** | Medio | Alto | ✅ **Completada e Implementada** (RF-13 / ADR-008) |
| **MEJ-02** | **Análisis de Contadores de Tráfico (`hitcnt=0` / Reglas Zombi)** | Bajo | Alto | ✅ **Completada e Implementada** (RF-14) |
| **MEJ-11** | **Criterio Arquitectónico de Zonas (Uso Contextual de `Any`), Consultor Plan C y Motor Determinístico** | Medio | Muy Alto | ✅ **Completada e Implementada** (RF-16) |
| **MEJ-10** | **Desarrollo de Laboratorio en Cisco Packet Tracer y Validación Empírica End-to-End** | Medio | Muy Alto | **Siguiente / Prioridad Actual (P1)** |
| **MEJ-03** | Auditoría en Vivo vía SSH (Integración Netmiko / Scrapli) | Medio | Muy Alto | **P2 (Alta)** |
| **MEJ-07** | Soporte Multi-Vendor (Fortinet FortiOS, Palo Alto PAN-OS, Juniper) | Alto | Muy Alto | **P3 (Evolutiva)** |
| **MEJ-08** | Optimización de Inferencia y Context Caching en Gemini | Bajo | Medio | **P3 (Evolutiva)** |

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

### 2. Detección de Reglas Zombi mediante Análisis de `hitcnt` (MEJ-02) `[IMPLEMENTADO]`
* **Estado:** ✅ **Completada e Implementada (2026-11-22)** — Ver [RF-14](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md).
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

---

### 9. UX Modular por Pestañas (Tabs), Visor Web Nativo del Reporte y Refactorización Estética (MEJ-09)
* **Estado:** ✅ **Completada e Implementada (2026-11-21)** — Pestañas de primer nivel, visor web nativo idéntico al PDF (con modo papel, donuts vectoriales, tablas y barra superior en bloques de código sin solapamiento del botón *Copiar*) y refactorización integral de `src/pdf_generator.py` y `src/report_builder.py` (RF-13.1, RF-13.2, RF-13.3 / ADR-008).
* **Contexto:** Actualmente el dashboard muestra todas las secciones en un único scroll vertical extenso (hero, donuts, herramientas Batfish, topología, matriz, reachability simbólica, centro What-If y hallazgos). A medida que la suite incorpora herramientas de análisis formal, la experiencia de usuario se sobrecarga visualmente. Asimismo, para leer el informe ejecutivo completo el operador se ve obligado a descargar el archivo PDF o Markdown, y el formato de reporte actual requiere pulido y optimización visual (tablas de colisión, saltos de página y consistencia tipográfica).
* **Mejora:**
  1. **Navegación Modular por Pestañas (Tabs de Primer Nivel):**
     * Reestructurar el dashboard post-auditoría en vistas organizadas:
       * 📊 **Postura & Hallazgos:** Indicadores de postura (gauges), donuts de riesgo, filtros interactivos y listado priorizado de vulnerabilidades.
       * 🎯 **Decisiones What-If:** Centro de decisiones top-down, presets de remediación, simulación en vivo y descarga de scripts `.cli`.
       * 🌐 **Topología & Simulación:** Lienzo interactivo en Canvas (física elástica 60 FPS), drawer contextual y simulador "El Camino del Paquete".
       * ⚡ **Herramientas Batfish:** Matriz de aislamiento perimétrico, reachability simbólica (`∀ paquetes`), prueba atómica de ACLs (`testFilters`) e inventario de red (`routes`, `layer3Edges`).
       * 📄 **Reporte Ejecutivo (Visor Nativo):** Pestaña dedicada con la visualización integral del informe sin requerir descarga de archivos.
  2. **Visor Web Nativo del Reporte Ejecutivo:**
     * Renderizar el informe completo formateado directamente en la pestaña del dashboard con diseño editorial cuidado, índice lateral interactivo (tabla de contenidos navegable), tablas de desglose de colisiones y bloques de comandos copiables con un clic.
  3. **Refactorización y Pulido Integral del Reporte (PDF y Web) — [RECORDATORIO CRÍTICO]:**
     * Acomodar y estandarizar la generación del informe ejecutivo tanto en `src/pdf_generator.py` como en `src/report_builder.py`.
     * Resolver desbordes de texto en celdas de tablas, asegurar saltos de página limpios en el PDF sin títulos huérfanos, formatear con elegancia los controles normativos APB y alinear la paleta de colores institucional para entrega C-Level formal de máxima prolijidad.

---

### 10. Desarrollo de Laboratorio en Cisco Packet Tracer y Validación Empírica End-to-End (MEJ-10)
* **Estado:** 🎯 **Pendiente / Próximo Paso Prioritario** — Ver [RF-15](file:///home/ing-laborda/Auditor_Firewall_IA/SRS.md).
* **Contexto:** Habiendo completado las capacidades formales (Batfish), semánticas (Gemini), de priorización What-If y reportes ejecutivos, es fundamental contrastar empíricamente todo lo que informa y recomienda la aplicación contra una topología simulada real en **Cisco Packet Tracer**.
* **Alcance y Pasos de Validación:**
  1. **Construcción del Laboratorio en Packet Tracer (`.pkt`):**
     * Recriar la topología perimetral de tres zonas (**WAN / Internet**, **DMZ Servidores** y **LAN Usuarios**) con routers Cisco IOS y/o firewall Cisco ASA, PCs clientes y servidores (HTTPS/443, MySQL/3306, HTTP/80, RDP/3389, Telnet/23, SSH/22).
     * Cargar la configuración vulnerable inicial (`running-config`) en el equipo de borde.
  2. **Verificación Empírica Pre-Remediación (Estado Vulnerable):**
     * Comprobar con tráfico real y *Simulation Mode* (PDU / ping / navegador web / cliente Telnet-SSH en Packet Tracer) que cada hallazgo reportado por la aplicación ocurre exactamente como lo predice el **Digital Twin de Batfish**:
       * Que la regla de *Critical Shadowing* deja pasar tráfico hacia el servidor que debía estar bloqueado.
       * Que los puertos expuestos desde WAN y líneas VTY responden tal como lo alerta la matriz de aislamiento y el simulador *"El Camino del Paquete"*.
       * Que los contadores `show access-lists` reflejan `0 matches` / `hitcnt=0` en las reglas zombi y aumentan en las reglas activas.
  3. **Aplicación de Scripts `.cli` Generados por la App y Validación Post-Remediación:**
     * Copiar y pegar en la consola CLI de Packet Tracer los scripts de **Remediación (Plan A / Plan B / What-If)** generados por la aplicación para verificar que no existan errores de sintaxis en el IOS/ASA real.
     * Re-ejecutar las pruebas de tráfico entre zonas para certificar que las brechas se cerraron sin cortar los servicios legítimos (validando empíricamente el *Blast Radius* y la *Matriz de Aislamiento*).
     * Probar el script de **Rollback (`.cli`)** en la consola del dispositivo y confirmar que el equipo vuelve exactamente a su estado original sin residuos de configuración.

