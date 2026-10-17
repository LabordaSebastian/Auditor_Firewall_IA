---
name: cisco-security-advisor
description: Skill experta en auditoría de seguridad y evaluación de impacto de cambios en firewalls y routers Cisco (IOS, IOS-XE y ASA).
---

# Metodología de Auditoría Cisco AI Firewall Auditor

Esta habilidad guía al motor cognitivo en el análisis de configuraciones Cisco (`show running-config` y `show access-lists`), combinando los resultados de verificación formal matemática (Batfish) con las mejores prácticas normativas (CIS Benchmarks, DISA STIG y NIST CSF).

## 7 Fases Obligatorias de Auditoría

### Fase 1: Contextualización Topológica y Expansión de Objetos
* Identificar el rol del equipo (Router de Borde, Firewall Perimetral ASA, Core de Segmentación).
* Determinar qué interfaces tienen ACLs aplicadas y en qué dirección (`in` / `out`).
* En Cisco ASA:
  * Verificar niveles de seguridad (`security-level` 0 en WAN vs 100 en LAN).
  * Tener presente la regla de ASA 8.3+: las ACLs en la interfaz de entrada filtran usando la **IP real pre-NAT** del host destino si el tráfico viene de menor a mayor seguridad.
* Identificar **ACLs Huérfanas**: listas de acceso declaradas pero no vinculadas a ninguna interfaz ni función activa (representan deuda técnica de bajo impacto para remoción).

### Fase 2: Evaluación de Shadowing Crítico (Batfish Findings)
* Analizar las reglas solapadas (*Shadowed Rules*) confirmadas por Batfish:
  * **Shadowing Benigno/Redundante:** Reglas redundantes con la misma acción (`permit` sobre `permit`).
  * **Critical Shadowing (Permit sobre Deny):** Una regla permisiva previa (`permit ip any any` o rango amplio) anula una regla restrictiva posterior (`deny tcp any host X eq 23`). Esto es un fallo de seguridad de severidad CRÍTICA.
  * **Shadowing Inverso (Deny sobre Deny):** Reglas inalcanzables que pueden removerse con riesgo operativo NULO.

### Fase 3: Permisividad Excesiva y Superficie de Ataque
* **Permisividad Extrema:** Presencia de `permit ip any any` en interfaces perimetrales sin inspección ni justificación.
* **Wildcards Excesivas:** Uso de máscaras invertidas amplias (ej. `0.0.255.255` o `0.255.255.255`) apuntando a servidores de base de datos o zonas de producción.
* **Exposición WAN de Puertos Inseguros y Gestión:**
  * Protocolos en texto plano: Telnet (TCP 23), HTTP (TCP 80), FTP (TCP 21).
  * Protocolos de gestión y compartición: SSH directo desde `any`, RDP (TCP 3389), SMB (TCP 445), SNMP (UDP 161/162).

### Fase 4: Higiene, Ciclo de Vida y Reglas Fantasma
* **Reglas Temporales Vencidas:** Buscar en los comentarios `remark` menciones a fechas pasadas, tickets de soporte expirados ("regla temporal", "ticket 2023", "prueba proveedor").
* **Reglas Sin Uso:** Si se cuenta con `show access-lists` con contadores `hitcnt`, señalar reglas con `hitcnt=0` con antigüedad conocida.

### Fase 5: Trazabilidad Forense en el Data Plane
* Comprobar la existencia de una regla explícita de descarte con logging al final de cada ACL activa:
  * Cisco IOS: `deny ip any any log`
  * Cisco ASA: Por defecto el *implicit deny* genera syslog 106023, pero se recomienda logging explícito o confirmación de monitoreo.
* La ausencia de logging en descartes impide la detección temprana de escaneos de red y ataques de fuerza bruta.

### Fase 6: Seguridad del Plano de Gestión (Management Plane)
* **Líneas VTY (0 a 15):**
  * Deben contar con `access-class <ACL> in` restringiendo el acceso exclusivamente a IPs/subredes autorizadas de administración (RFC 1918 / Jump Host).
  * Deben forzar `transport input ssh` (prohibiendo `telnet` o `all`).
* **Cisco ASA Management:**
  * Restringir comandos `http <subred> <máscara> <interfaz>` y `ssh <subred> <máscara> <interfaz>`.
  * Validación de comunidades SNMP (`snmp-server community`).

### Fase 7: Gestión de Cambios (Blast Radius, Plan A vs. Plan B y Rollback)
Para cada hallazgo identificado:
1. **Calcular el Radio de Impacto (*Blast Radius*):**
   * Evaluar si tocar la regla puede interrumpir tráfico productivo.
2. **Generar Plan A (Hardening Estricto):**
   * Remediación óptima e inmediata en producción según las mejores prácticas (bloqueo, eliminación de regla shadowed, restricción exacta).
3. **Generar Plan B (Transición Segura con Monitoreo):**
   * Diseñado para administradores temerosos de cortes: en lugar de bloquear abruptamente, insertar temporalmente una regla equivalente con cláusula `log` para auditar hits en Syslog durante 7-14 días antes del bloqueo definitivo.
4. **Script de Rollback:**
   * Comandos Cisco CLI exactos para revertir la acción en segundos si algo falla.
