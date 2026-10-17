# Matriz de Radio de Impacto Operativo (Blast Radius) y Estrategia de Decisión

Este documento establece la metodología para clasificar el impacto de los cambios propuestos y formular las dos alternativas de remediación (**Plan A** vs. **Plan B**).

## 1. Clasificación del Nivel de Impacto Operativo

| Nivel de Impacto | Criterio de Riesgo | Ejemplos Típicos | Recomendación de Aplicación |
| :--- | :--- | :--- | :--- |
| **NULO** | Cambio 100% seguro. No afecta tráfico activo porque la regla es matemáticamente inalcanzable. | Reglas solapadas (*shadowed*), objetos huérfanos, eliminación de líneas duplicadas. | Puede aplicarse en horario de oficina sin ventana formal. |
| **BAJO** | Agrega telemetría o trazabilidad sin bloquear paquetes existentes. | Agregar `log` al `deny` final, añadir `remark` descriptivos, habilitar SSH en VTY manteniendo acceso. | Ventana de bajo impacto. Monitoreo pasivo. |
| **MEDIO** | Restringe subredes o puertos con baja probabilidad de tráfico legítimo, pero requiere verificación previa. | Cerrar puertos legacy (ej. Telnet/23 en VTY) donde ya existe SSH, restringir wildcards excesivas a `/24`. | Validar contadores `hitcnt` antes de aplicar. Ventana de mantenimiento estándar. |
| **ALTO** | Bloqueo de flujos permisivos amplios que podrían transportar tráfico productivo no documentado. | Reemplazar `permit ip any any` por reglas específicas, cerrar puertos que registran hits recientes. | **Obligatorio Plan B (Transición)**. Nunca aplicar bloqueo directo sin periodo de observación. |

## 2. Definición de Estrategias: Plan A vs. Plan B

### Plan A: Hardening Estricto (Recomendado para Máxima Seguridad)
* **Objetivo:** Eliminar de inmediato la brecha o vulnerabilidad.
* **Acción:** `no <regla_vulnerable>` o reemplazo directo por `deny` / regla restringida.
* **Cuándo usarlo:**
  * Impacto NULO o BAJO.
  * Vulnerabilidad CRÍTICA con exploit activo o puertos peligrosos expuestos a WAN (ej. Telnet o SMB).

### Plan B: Transición Segura con Monitoreo (Para Administradores Cautelosos)
* **Objetivo:** Eliminar el miedo a cortar servicios legítimos no documentados en empresas grandes.
* **Metodología de 2 Fases:**
  1. **Fase 1 (Observación):** En lugar de bloquear o borrar la regla amplia, se inserta una regla idéntica con el flag `log` (o se deja la regla permisiva pero antecedida por reglas específicas de auditoría) y se instruye al administrador a monitorear los logs del Syslog durante 7 a 14 días.
  2. **Fase 2 (Cierre Definitivo):** Si durante ese periodo el Syslog no registra tráfico crítico o legítimo en esos puertos, se procede a ejecutar el script de bloqueo definitivo con total tranquilidad.
* **Cuándo usarlo:**
  * Siempre que el nivel de impacto sea MEDIO o ALTO.
  * Cuando existan reglas con `remark` ambiguos ("regla temporal", "app legacy") y no se tenga inventario exacto.
