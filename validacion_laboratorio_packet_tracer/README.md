# 🧪 Validación del Auditor con un Laboratorio en Cisco Packet Tracer

Esta carpeta demuestra que **`cisco-ai-firewall-auditor`** diagnostica y corrige correctamente una red corporativa típica
(WAN/ISP, DMZ, LAN con VLANs 802.1Q, ACLs vulnerables). Cualquier persona puede **reproducir las pruebas** en minutos.

| Archivo / carpeta | Contenido |
| :-- | :-- |
| [`GUIA_LAB_PACKET_TRACER.md`](GUIA_LAB_PACKET_TRACER.md) | Guía paso a paso: topología, direccionamiento, DHCP, scripts CLI y **Plan Maestro de Pruebas Espejo** App ↔ Packet Tracer. |
| [`configs/`](configs) | Configuraciones listas para pegar: `r-borde-corp_vulnerable.cfg`, `r-isp-wan.cfg`, `sw-core-lan.cfg` y `r-borde-corp_remediado.cfg` (generada por la app). |
| [`ejecutar_validacion.py`](ejecutar_validacion.py) | Script que repite **automáticamente** todas las pruebas (antes → remediación → después) con Batfish. |
| [`resultados/RESULTADO_VALIDACION.md`](resultados/RESULTADO_VALIDACION.md) | Último informe: 31 pruebas, postura **15 → 95/100** y el script de remediación generado. |
| `tests/test_validacion_laboratorio.py` | Mismo escenario integrado en la suite (`pytest`). |

---

## 🔁 Cómo repetir la validación automática

Requisitos: entorno `.venv` y el contenedor Batfish activo (`docker ps | grep batfish`). No usa Gemini: es 100 % local y determinístico.

```bash
.venv/bin/python validacion_laboratorio_packet_tracer/ejecutar_validacion.py   # imprime PASS/FAIL y regenera el informe
.venv/bin/pytest tests/test_validacion_laboratorio.py -q                        # misma validación dentro de pytest
```

El script devuelve código de salida `0` si las 31 pruebas pasan y `1` si alguna falla.

---

## 🗺️ El laboratorio en una vista

```text
 PC-ATACANTE-WAN (8.8.8.66)   SRV-INTERNET (8.8.8.8)
              \                /
              [ SW-WAN ]── R-ISP-WAN ──(200.45.112.16/29)── 🔥 R-BORDE-CORP ──┬── Gi0/2 DMZ 172.16.10.0/24
                                                                              │     ├ SRV-WEB-PUBLICO .10
                                                                              │     └ SRV-DB-CRITICO  .50
                                                                              └── Gi0/1 trunk 802.1Q ── SW-CORE-LAN
                                                                                    ├ VLAN 10 Usuarios 192.168.10.0/24
                                                                                    └ VLAN 20 Gestión  192.168.20.0/24
```

Vulnerabilidades inyectadas en `R-BORDE-CORP`: shadowing (línea 10 anula el deny de la 20), Telnet abierto a Internet,
acceso RDP temporal vencido, regla duplicada, `permit ip any any` en la LAN, VTY con Telnet sin `access-class`,
`enable password` débil, SNMP `public` y una ACL huérfana.

---

## ✅ Qué se valida (pruebas espejo)

Cada prueba de tráfico de la app tiene su equivalente en Packet Tracer; si **ambos resultados coinciden**, la app es correcta.

| Prueba | Flujo | En la app | En Packet Tracer | Antes | Después |
| :-: | :-- | :-- | :-- | :-: | :-: |
| **T1** | WAN → Base de datos (HTTPS 443) | Simulador `8.8.8.66 → 172.16.10.50 TCP 443` | `PC-ATACANTE-WAN` → `https://172.16.10.50` | 🚨 PERMIT (shadowing) | 🛡️ DENY |
| **T2** | WAN → Web pública (HTTPS 443) | `8.8.8.66 → 172.16.10.10 TCP 443` | `PC-ATACANTE-WAN` → `https://172.16.10.10` | ✅ PERMIT | ✅ PERMIT |
| **T3** | WAN → Telnet del router | `8.8.8.66 → 200.45.112.18 TCP 23` | `telnet 200.45.112.18` | 🚨 PERMIT | 🛡️ DENY |
| **T4** | VLAN 10 → VLAN 20 Gestión | `192.168.10.10 → 192.168.20.10 TCP 22` | `ping 192.168.20.10` | 🚨 PERMIT (fuga) | 🛡️ DENY (AISLADO) |
| **T5** | VLAN 10 → Internet (ida y retorno) | `192.168.10.10 → 8.8.8.8 TCP 80` | `http://8.8.8.8` | ✅ PERMIT | ✅ PERMIT |

Además el script verifica: sintaxis Batfish limpia, radiografía de topología, los 7 tipos de hallazgo, anomalías formales
(`filterLineReachability`), puertos expuestos (`searchFilters`), matriz de aislamiento (`LAN → GESTION`: `FUGA` → `AISLADO`),
Plan C del consultor de excepciones, simulación What-If y la **re-auditoría final: 0 hallazgos y postura 95/100**.

### 🔎 Hallazgo del propio laboratorio (T5)
Al probar en Packet Tracer, el `ping` a `8.8.8.8` funcionaba pero la web no. La causa era una **ACL de entrada WAN sin estado**
que descartaba la respuesta TCP. Esto llevó a mejorar la app: el simulador ahora usa `bidirectionalTraceroute` y avisa
cuando *la ida pasa pero el retorno se descarta* (prueba `ANTES-T5b`). El laboratorio incorpora `75 permit tcp any any established`.

---

## 🧭 Alcance y estado de la validación

* **Validado automáticamente (Batfish, reproducible):** las 31 pruebas del script, comprobadas en cada ejecución.
* **Validado empíricamente en Packet Tracer:** la causa del fallo de T5 (ACL sin estado). Las demás parejas de pruebas
  de la tabla anterior se ejecutan siguiendo la [guía](GUIA_LAB_PACKET_TRACER.md); el resultado esperado de cada una es el
  de las columnas *Antes / Después*.
* **Nota de privacidad:** las contraseñas de las configuraciones (`claveinsegura`, `AdminSec2025!`, `public`) son ficticias,
  solo para el laboratorio.
