# Mapeo de Controles Normativos (CIS Benchmark, DISA STIG, NIST CSF)

Este documento contiene la matriz de referencia para fundamentar los hallazgos de auditoría con estándares internacionales de ciberseguridad.

## 1. CIS Cisco IOS Benchmark v4.1.0 & Cisco ASA Benchmark v1.1.0

| ID Control CIS | Descripción del Requisito | Dialecto | Severidad Sugerida |
| :--- | :--- | :--- | :--- |
| **CIS-IOS-1.1.1** | Deshabilitar protocolos de gestión en texto plano (Telnet) y forzar SSHv2 | IOS / IOS-XE | CRÍTICA |
| **CIS-IOS-1.1.2** | Restringir el acceso a terminales virtuales (VTY) mediante ACL (`access-class in`) | IOS / IOS-XE | ALTA |
| **CIS-IOS-2.1.1** | Aplicar regla explícita de descarte con log al final de toda ACL (`deny ip any any log`) | IOS / IOS-XE | MEDIA |
| **CIS-IOS-2.2.3** | Prohibir el uso de `permit ip any any` en interfaces con tráfico no confiable | IOS / IOS-XE | CRÍTICA |
| **CIS-IOS-3.1.4** | Eliminar reglas huérfanas, reglas solapadas (*shadowed*) y comentarios vencidos | IOS / IOS-XE | BAJA / MEDIA |
| **CIS-ASA-1.2.1** | Restringir accesos administrativos SSH y HTTPS solo a subredes de gestión dedicadas | ASA | ALTA |
| **CIS-ASA-2.1.4** | Asegurar que toda ACL aplicada en interfaz de menor nivel (`security-level 0`) filtre puertos de gestión | ASA | CRÍTICA |
| **CIS-ASA-3.3.1** | Depurar grupos de objetos (`object-group`) no utilizados o con objetos redundantes | ASA | BAJA |

## 2. DISA STIG (Security Technical Implementation Guide) - Cisco Perimeter L3 / Firewall

* **NET-0405 (Rule Ordering & Shadowing):** Las listas de control de acceso deben configurarse de manera que las reglas más específicas precedan a las reglas generales para prevenir el enmascaramiento accidental de políticas restrictivas.
* **NET-0810 (Inbound Management Block):** Ningún paquete dirigido a puertos de gestión del router/firewall (SSH, Telnet, HTTP, SNMP) debe permitirse desde interfaces públicas o redes no confiables.
* **NET-0920 (Anti-Spoofing & RFC 1918):** El tráfico entrante por interfaces WAN no debe contener direcciones de origen privadas (RFC 1918) ni loopbacks (RFC 3330 / RFC 5735).
* **NET-1640 (Audit Logging of Denied Traffic):** Todo paquete descartado por el firewall perimetral debe ser registrado para auditoría y análisis de detección de intrusiones.

## 3. NIST Cybersecurity Framework (NIST CSF 2.0)

* **PR.AC-4 (Network Access Management):** El acceso a la red y a los flujos de comunicación está protegido, segmentado y restringido por listas de control de acceso basadas en el principio de mínimo privilegio.
* **PR.AC-5 (Network Integrity & Separation):** La integridad de la red está protegida mediante la separación del plano de control, plano de gestión y plano de datos.
* **PR.PT-4 (Communications & Data Protection):** Las comunicaciones y los canales de administración remota utilizan cifrado robusto y protegen la confidencialidad de la información en tránsito.
* **DE.CM-1 (Network Monitoring & Auditing):** La red es monitoreada para detectar eventos anómalos y anomalías en el tráfico mediante el registro continuo de conexiones y descartes.
