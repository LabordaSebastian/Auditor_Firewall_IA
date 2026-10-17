# Antipatrones Comunes en ACLs Cisco (IOS, IOS-XE y ASA)

Este documento detalla malas prácticas y vectores de riesgo típicos detectados en auditorías de firewalls Cisco.

## 1. Puertos Críticos Inseguros Expuestos

| Protocolo | Puerto / Transporte | Riesgo Asociado |
| :--- | :--- | :--- |
| **Telnet** | TCP 23 | Transmisión de credenciales en texto plano. Vulnerable a sniffing y MITM. |
| **HTTP** | TCP 80 (Gestión) | Autenticación web sin cifrado. Exposición de paneles de administración. |
| **FTP** | TCP 21 | Autenticación en texto plano, puertos dinámicos de datos. |
| **SNMP** | UDP 161 / 162 | Versiones v1 y v2c transmiten comunidades en claro (`public`, `private`). |
| **SMB / NetBIOS**| TCP 445, 139 | Vector crítico de ransomware (WannaCry, EternalBlue). No debe salir ni entrar a WAN. |
| **RDP** | TCP 3389 | Ataques continuos de fuerza bruta y explotación de vulnerabilidades RCE. |

## 2. Máscaras Wildcard Invertidas Excesivamente Amplias

En Cisco IOS, la máscara wildcard es el complemento binario de la máscara de subred:
* `0.0.0.0` = Host exacto (`host X.X.X.X`).
* `0.0.0.255` = Subred `/24` (256 hosts).
* `0.0.255.255` = Subred `/16` (65.536 hosts) -> **Riesgo ALTO si se apunta a servicios críticos**.
* `0.255.255.255` = Subred `/8` (16.777.216 hosts) -> **Riesgo CRÍTICO si está en interfaces internas sin segmentación**.

## 3. Peculiaridades de Cisco ASA 8.3+ y NAT

1. **Orden de Evaluación ACL vs NAT:**
   * En versiones ASA 8.3 en adelante, cuando el tráfico ingresa desde una interfaz de menor seguridad hacia una de mayor seguridad (ej. `outside` a `inside`), **la ACL debe hacer referencia a la IP privada real del servidor interno (pre-NAT)**, NO a la IP pública mapeada.
   * Regla de oro: Si la ACL usa la IP pública WAN como destino en tráfico entrante en ASA >= 8.3, el firewall descartará los paquetes porque la traducción NAT aún no ha ocurrido al evaluar el filtro de entrada.
2. **Grupos de Objetos (`object-group`):**
   * Objetos anidados sin documentar o con cientos de miembros oscurecen qué flujos están realmente autorizados.
   * La verificación formal de Batfish descompone y aplana estos objetos en expresiones booleanas exactas.
