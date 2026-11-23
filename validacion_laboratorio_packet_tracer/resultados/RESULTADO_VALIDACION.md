# Resultado de la validación automática del laboratorio

* **Fecha:** 2026-11-22 23:45:46
* **Resultado:** ✅ TODAS LAS PRUEBAS PASARON (31/31)
* **Postura de seguridad:** 15/100 → 95/100

| Estado | Prueba | Esperado | Obtenido | Equivalente en Packet Tracer |
| :-: | :-- | :-- | :-- | :-- |
| ✅ | `E1-SINTAXIS` Batfish parsea toda la configuración (initIssues vacío) | 0 líneas no reconocidas | 0 líneas | — |
| ✅ | `E1-TOPOLOGIA` Radiografía: 5 interfaces, 2 ACLs activas, 1 huérfana | 5 / 2 / 1 | 5 / 2 / 1 | — |
| ✅ | `E1-HALLAZGO-CRITICAL` Detecta: Shadowing crítico (línea 20 tapada por la 10) | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-SHADOWED` Detecta: Regla redundante (línea 70 duplicada de la 60) | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-TELNET` Detecta: Telnet (TCP/23) expuesto en WAN | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-TEMPORAL` Detecta: Regla temporal vencida sin retirar (RDP) | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-PERMISIVIDAD` Detecta: ACL LAN con permit ip any any | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-MANAGEMENT` Detecta: VTY con Telnet y sin access-class | detectado | detectado | — |
| ✅ | `E1-HALLAZGO-HUÉRFANA` Detecta: ACL huérfana sin interfaz | detectado | detectado | — |
| ✅ | `E1-SCORE` Postura inicial crítica (< 40/100) | < 40 | 15 | — |
| ✅ | `E1-BATFISH-SHADOW` filterLineReachability: CRITICAL_SHADOWING línea 20 y REDUNDANT línea 70 | 2 anomalías formales | [('CRITICAL_SHADOWING', '20'), ('REDUNDANT', '70')] | — |
| ✅ | `E1-EXPOSICION` searchFilters: Telnet, HTTP y RDP alcanzables desde WAN | Telnet+HTTP+RDP | HTTP, RDP, Telnet | — |
| ✅ | `E1-AISLAMIENTO` Matriz de aislamiento: LAN → GESTION en FUGA | FUGA | FUGA | — |
| ✅ | `ANTES-T1` WAN → Base de datos crítica (HTTPS 443) | PERMIT | PERMIT | PC-ATACANTE-WAN → Web Browser → https://172.16.10.50 |
| ✅ | `ANTES-T2` WAN → Web pública legítima (HTTPS 443) | PERMIT | PERMIT | PC-ATACANTE-WAN → Web Browser → https://172.16.10.10 |
| ✅ | `ANTES-T3` WAN → Telnet del router (TCP 23) | PERMIT | PERMIT | PC-ATACANTE-WAN → Command Prompt → telnet 200.45.112.18 |
| ✅ | `ANTES-T4` VLAN 10 Usuarios → VLAN 20 Gestión (SSH 22) | PERMIT | PERMIT | PC-VENTAS-VLAN10 → Command Prompt → ping 192.168.20.10 |
| ✅ | `ANTES-T5` VLAN 10 Usuarios → Internet (HTTP 80), ida y retorno | PERMIT · retorno PERMIT | PERMIT · retorno PERMIT | PC-VENTAS-VLAN10 → Web Browser → http://8.8.8.8 |
| ✅ | `ANTES-T5b` Sin 'permit tcp any any established' la ida pasa pero la respuesta se descarta | ida PERMIT · retorno DENY | ida PERMIT · retorno DENY | PC-VENTAS-VLAN10: el ping funciona pero la web a 8.8.8.8 no carga |
| ✅ | `E3-PLAN-C` Consultor de excepciones aprueba el Plan C de salida a Internet | EXCEPCION_VALIDA | EXCEPCION_VALIDA | — |
| ✅ | `E4-WHATIF` What-If con Plan A + Plan C: LAN → GESTION pasa a AISLADO | AISLADO | AISLADO | — |
| ✅ | `E4-POSTURA` Postura proyectada ≥ 70 | ≥ 70 | 79 | — |
| ✅ | `DESPUES-SCORE` Postura final óptima (≥ 90/100) | ≥ 90 | 95 | — |
| ✅ | `DESPUES-HALLAZGOS` 0 hallazgos tras la remediación | 0 | 0 | — |
| ✅ | `DESPUES-BATFISH` 0 reglas sombreadas o redundantes (Batfish) | 0 | 0 | — |
| ✅ | `DESPUES-AISLAMIENTO` Matriz de aislamiento: LAN → GESTION AISLADO | AISLADO | AISLADO | — |
| ✅ | `DESPUES-T1` WAN → Base de datos crítica (HTTPS 443) | DENY | DENY | PC-ATACANTE-WAN → Web Browser → https://172.16.10.50 |
| ✅ | `DESPUES-T2` WAN → Web pública legítima (HTTPS 443) | PERMIT | PERMIT | PC-ATACANTE-WAN → Web Browser → https://172.16.10.10 |
| ✅ | `DESPUES-T3` WAN → Telnet del router (TCP 23) | DENY | DENY | PC-ATACANTE-WAN → Command Prompt → telnet 200.45.112.18 |
| ✅ | `DESPUES-T4` VLAN 10 Usuarios → VLAN 20 Gestión (SSH 22) | DENY | DENY | PC-VENTAS-VLAN10 → Command Prompt → ping 192.168.20.10 |
| ✅ | `DESPUES-T5` VLAN 10 Usuarios → Internet (HTTP 80), ida y retorno | PERMIT · retorno PERMIT | PERMIT · retorno PERMIT | PC-VENTAS-VLAN10 → Web Browser → http://8.8.8.8 |

## Script de remediación generado por la aplicación (Plan A + Plan C)

```cisco
! Script consolidado de remediación (centro de decisiones What-If)
! Equipo: R-BORDE-CORP · 7 cambio(s) en orden top-down

! --- FW-DET-003 · Plan A · ACL_WAN_IN (CRITICA) ---
configure terminal
ip access-list extended ACL_WAN_IN
no 30
end

! --- FW-DET-002 · Plan A · ACL_WAN_IN (CRITICA) ---
configure terminal
ip access-list extended ACL_WAN_IN
no 10
no 20
10 deny tcp any host 172.16.10.50 eq 443
20 permit tcp any 172.16.10.0 0.0.0.255 eq 443
end

! --- FW-DET-006 · Plan A · line vty 0 4 (CRITICA) ---
configure terminal
ip access-list standard ACL_MGMT_VTY
10 permit 192.168.20.0 0.0.0.255
line vty 0 4
transport input ssh
access-class ACL_MGMT_VTY in
end

! --- FW-DET-004 · Plan A · ACL_WAN_IN (ALTA) ---
configure terminal
ip access-list extended ACL_WAN_IN
no 40
no 50
end

! --- FW-DET-005 · Plan C · ACL_LAN_IN (ALTA) ---
configure terminal
ip access-list extended ACL_LAN_IN
no 10
12 deny ip any 192.168.20.0 0.0.0.255 log
15 deny tcp any 172.16.10.0 0.0.0.255 eq 22 log
18 deny tcp any any eq 445 log
20 permit tcp 192.168.10.0 0.0.0.255 any eq 80
22 permit tcp 192.168.10.0 0.0.0.255 any eq 443
24 permit udp 192.168.10.0 0.0.0.255 any eq 53
26 permit icmp 192.168.10.0 0.0.0.255 any
30 deny ip any any log
end

! --- FW-DET-001 · Plan A · ACL_WAN_IN (BAJA) ---
configure terminal
ip access-list extended ACL_WAN_IN
no 70
end

! --- FW-DET-007 · Plan A · ACL_LEGACY_MIGRACION_2022 (BAJA) ---
configure terminal
no ip access-list extended ACL_LEGACY_MIGRACION_2022
end

write memory
```
