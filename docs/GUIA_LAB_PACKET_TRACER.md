# 🧪 Guía Paso a Paso (APB) — Laboratorio Empresarial en Cisco Packet Tracer

Esta guía te lleva desde un lienzo en blanco en **Cisco Packet Tracer** hasta una **red corporativa completa con VLANs (802.1Q Router-on-a-Stick), DMZ, WAN/ISP y políticas ACL vulnerables**, lista para copiar, pegar y validar el 100% de las funciones de **`cisco-ai-firewall-auditor`**.

---

## 🗺️ 1. Arquitectura de la Red a Construir

```text
                    [ ZONA WAN / INTERNET (Baja Confianza) ]
         PC-ATACANTE-WAN (8.8.8.66)          SRV-INTERNET (8.8.8.8)
                      \                         /
                       \--- [ SW-WAN (2960) ] -/
                                   | (Fa0/1)
                                   | (Gi0/1: 8.8.8.1/24)
                             [ R-ISP-WAN (2911) ]
                                   | (Gi0/0: 200.45.112.17/29)
                                   |
                                   | (Gi0/0: 200.45.112.18/29 - ACL_WAN_IN)
                        [ 🔥 R-BORDE-CORP (2911) ]
                         /                      \
     (Gi0/1 - Trunk 802.1Q)                      (Gi0/2: 172.16.10.1/24)
    + Gi0/1.10 (192.168.10.1/24 - ACL_LAN_IN)             |
    + Gi0/1.20 (192.168.20.1/24)                          |
              |                                    [ SW-DMZ (2960) ]
     [ SW-CORE-LAN (2960) ]                          /           \
        /              \                            /             \
  (VLAN 10)          (VLAN 20)             SRV-WEB-PUBLICO   SRV-DB-CRITICO
PC-VENTAS-VLAN10   PC-ADMIN-VLAN20          (172.16.10.10)   (172.16.10.50)
 (192.168.10.10)    (192.168.20.10)          [HTTP/HTTPS]    [HTTPS/RDP/DB]
```

### Tabla de Direccionamiento Rápido

| Zona | Dispositivo | Interfaz / VLAN | Dirección IP | Máscara | Gateway |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **WAN (Enlace ISP)** | `R-BORDE-CORP` | `GigabitEthernet0/0` | `200.45.112.18` | `255.255.255.248` (`/29`) | `200.45.112.17` |
| **WAN (Enlace ISP)** | `R-ISP-WAN` | `GigabitEthernet0/0` | `200.45.112.17` | `255.255.255.248` (`/29`) | — |
| **WAN (Internet)** | `R-ISP-WAN` | `GigabitEthernet0/1` | `8.8.8.1` | `255.255.255.0` (`/24`) | — |
| **WAN (Internet)** | `SRV-INTERNET` | `FastEthernet0` | `8.8.8.8` | `255.255.255.0` (`/24`) | `8.8.8.1` |
| **WAN (Internet)** | `PC-ATACANTE-WAN` | `FastEthernet0` | `8.8.8.66` | `255.255.255.0` (`/24`) | `8.8.8.1` |
| **DMZ** | `R-BORDE-CORP` | `GigabitEthernet0/2` | `172.16.10.1` | `255.255.255.0` (`/24`) | — |
| **DMZ** | `SRV-WEB-PUBLICO` | `FastEthernet0` | `172.16.10.10` | `255.255.255.0` (`/24`) | `172.16.10.1` |
| **DMZ** | `SRV-DB-CRITICO` | `FastEthernet0` | `172.16.10.50` | `255.255.255.0` (`/24`) | `172.16.10.1` |
| **LAN VLAN 10 (Usuarios)** | `R-BORDE-CORP` | `GigabitEthernet0/1.10` | `192.168.10.1` | `255.255.255.0` (`/24`) | — |
| **LAN VLAN 10 (Usuarios)** | `PC-VENTAS-VLAN10` | `FastEthernet0` (Access VLAN 10) | `192.168.10.10` | `255.255.255.0` (`/24`) | `192.168.10.1` |
| **LAN VLAN 20 (Admins IT)** | `R-BORDE-CORP` | `GigabitEthernet0/1.20` | `192.168.20.1` | `255.255.255.0` (`/24`) | — |
| **LAN VLAN 20 (Admins IT)** | `PC-ADMIN-VLAN20` | `FastEthernet0` (Access VLAN 20) | `192.168.20.10` | `255.255.255.0` (`/24`) | `192.168.20.1` |

---

## 🛠️ 2. Paso 1: Arrastrar Equipos y Conectar Cables (2 minutos)

> **Importante:** Usá específicamente el router modelo **`2911`** porque ya trae **3 puertos GigabitEthernet (`Gi0/0`, `Gi0/1`, `Gi0/2`)** de fábrica sin tener que apagarlo ni agregar módulos.

1. **Arrastrar al lienzo:**
   * En *Network Devices -> Routers*: arrastrá **2 routers `2911`** y nombrálos `R-BORDE-CORP` y `R-ISP-WAN`.
   * En *Network Devices -> Switches*: arrastrá **3 switches `2960`** y nombrálos `SW-CORE-LAN`, `SW-DMZ` y `SW-WAN`.
   * En *End Devices*:
     * Arrastrá **3 `PC-PT`**: `PC-VENTAS-VLAN10`, `PC-ADMIN-VLAN20` y `PC-ATACANTE-WAN`.
     * Arrastrá **3 `Server-PT`**: `SRV-WEB-PUBLICO`, `SRV-DB-CRITICO` y `SRV-INTERNET`.

2. **Conectar los cables exactamente en estos puertos:**
   * **Enlace WAN entre Routers (Cable Cruzado / Copper Cross-Over):**
     * `R-BORDE-CORP` (**`GigabitEthernet0/0`**) ➔ `R-ISP-WAN` (**`GigabitEthernet0/0`**)
   * **Zona WAN / Internet (Cable Directo / Copper Straight-Through):**
     * `R-ISP-WAN` (**`GigabitEthernet0/1`**) ➔ `SW-WAN` (**`FastEthernet0/1`**)
     * `SW-WAN` (**`FastEthernet0/2`**) ➔ `SRV-INTERNET` (**`FastEthernet0`**)
     * `SW-WAN` (**`FastEthernet0/3`**) ➔ `PC-ATACANTE-WAN` (**`FastEthernet0`**)
   * **Zona DMZ (Cable Directo):**
     * `R-BORDE-CORP` (**`GigabitEthernet0/2`**) ➔ `SW-DMZ` (**`FastEthernet0/1`**)
     * `SW-DMZ` (**`FastEthernet0/2`**) ➔ `SRV-WEB-PUBLICO` (**`FastEthernet0`**)
     * `SW-DMZ` (**`FastEthernet0/3`**) ➔ `SRV-DB-CRITICO` (**`FastEthernet0`**)
   * **Zona LAN Corporativa con VLANs (Cable Directo):**
     * `R-BORDE-CORP` (**`GigabitEthernet0/1`**) ➔ `SW-CORE-LAN` (**`GigabitEthernet0/1`**) *(Este será nuestro enlace Trunk 802.1Q)*
     * `SW-CORE-LAN` (**`FastEthernet0/10`**) ➔ `PC-VENTAS-VLAN10` (**`FastEthernet0`**) *(Puerto en VLAN 10)*
     * `SW-CORE-LAN` (**`FastEthernet0/20`**) ➔ `PC-ADMIN-VLAN20` (**`FastEthernet0`**) *(Puerto en VLAN 20)*

---

## 💻 3. Paso 2: Cómo Configurar las 3 PCs (por DHCP en 1 clic) y los 3 Servidores

Para que sea todavía más rápido y realista:
* **Las 3 PCs (`PC-VENTAS-VLAN10`, `PC-ADMIN-VLAN20` y `PC-ATACANTE-WAN`) toman su IP automáticamente por DHCP desde los routers** (gracias a los rangos `ip dhcp excluded-address` de los scripts del Paso 3, cada PC recibirá **exactamente** la IP `192.168.10.10`, `192.168.20.10` y `8.8.8.66` sin que tengas que tipear un solo número).
* **Los 3 Servidores (`SRV-WEB-PUBLICO`, `SRV-DB-CRITICO` y `SRV-INTERNET`) llevan IP Estática**, igual que en cualquier empresa real, porque las reglas de las ACLs apuntan a sus IPs fijas (`host 172.16.10.10` y `host 172.16.10.50`).

### 3.1. Configurar los 3 Servidores (IP Estática + Servicios HTTP/HTTPS y DNS)

#### A) Servidor 1: `SRV-WEB-PUBLICO` (Web Corporativa en la DMZ)
1. Hacé **un clic izquierdo** sobre el ícono de **`SRV-WEB-PUBLICO`**.
2. En la ventana que se abre, andá a la pestaña superior **`Desktop`** y hacé clic en el primer ícono: **`IP Configuration`**.
3. Dejá seleccionado **`Static`** y completá los 4 casilleros:
   * **IPv4 Address:** `172.16.10.10`
   * **Subnet Mask:** `255.255.255.0`
   * **Default Gateway:** `172.16.10.1`
   * **DNS Server:** `8.8.8.8`
4. Ahora pasá a la pestaña superior **`Services`** (al lado de *Desktop*):
   * En el menú izquierdo hacé clic en **`HTTP`** y verificá que tanto **`HTTP`** como **`HTTPS`** estén marcados en **`On`** (ya vienen en *On* por defecto en Packet Tracer).
   * *(Opcional para diferenciarlo visualmente)*: en la lista de archivos hacé clic en `(edit)` al lado de `index.html` y cambiá el título por `SERVIDOR WEB PUBLICO CORP (172.16.10.10)` y dale a **Save**.

#### B) Servidor 2: `SRV-DB-CRITICO` (Base de Datos / Backend Interno en la DMZ)
1. Hacé clic sobre **`SRV-DB-CRITICO`** ➔ pestaña **`Desktop`** ➔ **`IP Configuration`**.
2. Dejá **`Static`** y completá:
   * **IPv4 Address:** `172.16.10.50`
   * **Subnet Mask:** `255.255.255.0`
   * **Default Gateway:** `172.16.10.1`
   * **DNS Server:** `8.8.8.8`
3. Andá a la pestaña **`Services`** ➔ **`HTTP`**:
   * Verificá que **`HTTPS`** esté en **`On`** (lo usaremos para simular la consola administrativa HTTPS `TCP/443` de la base de datos que la regla 20 de la ACL intenta bloquear pero queda expuesta por *Shadowing*).
   * *(Opcional)*: editá su `index.html` para que diga `CONSOLA CRITICA BASE DE DATOS (172.16.10.50) - ACCESO RESTRINGIDO` y dale a **Save**.

#### C) Servidor 3: `SRV-INTERNET` (Servidor Público y DNS en Internet)
1. Hacé clic sobre **`SRV-INTERNET`** ➔ pestaña **`Desktop`** ➔ **`IP Configuration`**.
2. Dejá **`Static`** y completá:
   * **IPv4 Address:** `8.8.8.8`
   * **Subnet Mask:** `255.255.255.0`
   * **Default Gateway:** `8.8.8.1`
   * **DNS Server:** `8.8.8.8`
3. *(Opcional — Activar DNS real)*: Andá a la pestaña **`Services`** ➔ **`DNS`**:
   * Poné **DNS Service** en **`On`**.
   * Agregá dos registros tipo `A Record`:
     * **Name:** `web.corp.com` | **Address:** `172.16.10.10` ➔ clic en **Add**.
     * **Name:** `google.com` | **Address:** `8.8.8.8` ➔ clic en **Add**.

---

### 3.2. Configurar las 3 PCs por DHCP (¡Hacelo DESPUÉS de pegar los scripts del Paso 3!)

Una vez que hayas pegado los scripts de `SW-CORE-LAN`, `R-ISP-WAN` y `R-BORDE-CORP` del **Paso 3** (y adelantado el reloj con `Fast Forward Time`):

1. Abrí **`PC-VENTAS-VLAN10`** ➔ pestaña **`Desktop`** ➔ **`IP Configuration`** ➔ seleccioná el circulito **`DHCP`**.
   * En 2 segundos dirá *`DHCP request successful`* y le asignará automáticamente:
     **IP:** `192.168.10.10` | **Mask:** `255.255.255.0` | **Gateway:** `192.168.10.1` | **DNS:** `8.8.8.8`.
2. Abrí **`PC-ADMIN-VLAN20`** ➔ **`Desktop`** ➔ **`IP Configuration`** ➔ seleccioná **`DHCP`**.
   * Recibirá automáticamente:
     **IP:** `192.168.20.10` | **Mask:** `255.255.255.0` | **Gateway:** `192.168.20.1` | **DNS:** `8.8.8.8`.
3. Abrí **`PC-ATACANTE-WAN`** ➔ **`Desktop`** ➔ **`IP Configuration`** ➔ seleccioná **`DHCP`**.
   * Recibirá automáticamente desde `R-ISP-WAN`:
     **IP:** `8.8.8.66` | **Mask:** `255.255.255.0` | **Gateway:** `8.8.8.1` | **DNS:** `8.8.8.8`.

---

## 📋 4. Paso 3: Scripts CLI Listos para Pegar en Switch y Routers (Con DHCP incluido)

> Si al abrir la pestaña **CLI** de un router o switch te pregunta `Would you like to enter the initial configuration dialog? [yes/no]:`, escribí **`no`** y presioná **Enter**.

### 4.1. Pegar en `SW-CORE-LAN` (Creación de VLAN 10, VLAN 20 y Trunk 802.1Q)

Abrí `SW-CORE-LAN` ➔ pestaña **CLI** ➔ clic en **Paste** con este bloque:

```cisco
enable
configure terminal
hostname SW-CORE-LAN
!
vlan 10
 name LAN_USUARIOS
vlan 20
 name LAN_ADMINS_IT
exit
!
interface GigabitEthernet0/1
 description TRUNK_HACIA_R_BORDE_CORP
 switchport mode trunk
 switchport trunk allowed vlan 10,20
 no shutdown
!
interface FastEthernet0/10
 description PUESTO_VENTAS_VLAN10
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 no shutdown
!
interface FastEthernet0/20
 description PUESTO_ADMIN_SECOPS_VLAN20
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 no shutdown
!
end
write memory
```

---

### 4.2. Pegar en `R-ISP-WAN` (Simulador de Proveedor de Internet + DHCP WAN)

Abrí `R-ISP-WAN` ➔ pestaña **CLI** ➔ escribí `no` si pregunta ➔ clic en **Paste**:

```cisco
enable
configure terminal
hostname R-ISP-WAN
!
ip dhcp excluded-address 8.8.8.1 8.8.8.65
!
ip dhcp pool POOL_WAN_INTERNET
 network 8.8.8.0 255.255.255.0
 default-router 8.8.8.1
 dns-server 8.8.8.8
!
interface GigabitEthernet0/0
 description ENLACE_CLIENTE_CORP
 ip address 200.45.112.17 255.255.255.248
 no shutdown
!
interface GigabitEthernet0/1
 description RED_PUBLICA_INTERNET
 ip address 8.8.8.1 255.255.255.0
 no shutdown
!
ip route 172.16.10.0 255.255.255.0 200.45.112.18
ip route 192.168.10.0 255.255.255.0 200.45.112.18
ip route 192.168.20.0 255.255.255.0 200.45.112.18
!
end
write memory
```

---

### 4.3. Pegar en `R-BORDE-CORP` (Firewall/Router Empresarial con DHCP para VLAN 10/20 + ACLs Vulnerables)

Abrí `R-BORDE-CORP` ➔ pestaña **CLI** ➔ escribí `no` si pregunta ➔ clic en **Paste**:

```cisco
enable
configure terminal
no service password-encryption
hostname R-BORDE-CORP
!
enable password claveinsegura
username admin privilege 15 secret AdminSec2025!
ip domain-name corp.local
!
ip dhcp excluded-address 192.168.10.1 192.168.10.9
ip dhcp excluded-address 192.168.20.1 192.168.20.9
!
ip dhcp pool POOL_VLAN10_USUARIOS
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 8.8.8.8
!
ip dhcp pool POOL_VLAN20_ADMINS
 network 192.168.20.0 255.255.255.0
 default-router 192.168.20.1
 dns-server 8.8.8.8
!
interface GigabitEthernet0/0
 description WAN_INTERNET_ISP
 ip address 200.45.112.18 255.255.255.248
 ip access-group ACL_WAN_IN in
 no shutdown
!
interface GigabitEthernet0/1
 description TRUNK_LAN_CORE_8021Q
 no ip address
 no shutdown
!
interface GigabitEthernet0/1.10
 description LAN_VLAN10_USUARIOS
 encapsulation dot1Q 10
 ip address 192.168.10.1 255.255.255.0
 ip access-group ACL_LAN_IN in
!
interface GigabitEthernet0/1.20
 description GESTION_VLAN20_ADMINS_IT
 encapsulation dot1Q 20
 ip address 192.168.20.1 255.255.255.0
!
interface GigabitEthernet0/2
 description DMZ_SERVIDORES_PUBLICOS
 ip address 172.16.10.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 200.45.112.17
!
ip access-list extended ACL_WAN_IN
 10 permit tcp any 172.16.10.0 0.0.0.255 eq 443
 20 deny tcp any host 172.16.10.50 eq 443
 30 permit tcp any host 200.45.112.18 eq 23
 40 remark Acceso temporal proveedor Ticket-9981 vencido
 50 permit tcp host 190.210.45.88 host 172.16.10.50 eq 3389
 60 permit tcp any host 172.16.10.10 eq 80
 70 permit tcp any host 172.16.10.10 eq 80
 75 permit tcp any any established
 80 permit icmp any any
!
ip access-list extended ACL_LAN_IN
 10 permit ip any any
!
ip access-list extended ACL_LEGACY_MIGRACION_2022
 10 permit ip any 10.99.0.0 0.0.255.255
!
snmp-server community public RO
!
line vty 0 4
 login local
 transport input telnet ssh
!
end
write memory
```

> 💡 **Adelantá el reloj de Spanning-Tree:** En Packet Tracer, apretá 2 veces el botón **`Fast Forward Time` (`Alt + D`)** abajo a la izquierda para que todos los triangulitos naranjas de los switches pasen a verde al instante.

---

## 🔬 5. Plan Maestro de Pruebas Espejo (App ↔ Packet Tracer) — Guion Listo para Demo en el Trabajo

La lógica de esta validación es **1 a 1 (Espejo)**: cada prueba de tráfico que hacés en las herramientas formales de la aplicación la replicás en **Cisco Packet Tracer**, corregís los errores con el script generado por la app, y al re-auditar comprobás que tanto el simulador como la aplicación pasan a verde (**Score 95/100 y 0 hallazgos**).

---

### ETAPA 1 — Ingesta `Ctrl+C` / `Ctrl+V` y Radiografía Pre-Flight
1. En Packet Tracer, abrí **`R-BORDE-CORP` ➔ CLI** y ejecutá:
   ```cisco
   terminal length 0
   show running-config
   ```
2. Seleccioná desde `version 15.1` hasta `end`, hacé clic en **Copy** y en la pantalla de inicio de tu app (`http://127.0.0.1:8000`) presioná **`Ctrl+V`** y clic en **"Previsualizar texto pegado"**.
3. **Qué mostrar en la Demo (Pre-Flight):**
   * **Detección automática de Topología y VLANs:** Identifica `R-BORDE-CORP`, dialecto `Cisco IOS / IOS-XE`, las **5 interfaces** (incluyendo las subinterfaces `Gi0/1.10` VLAN 10 Usuarios y `Gi0/1.20` VLAN 20 Gestión), **2 ACLs activas** (`ACL_WAN_IN`, `ACL_LAN_IN`) y **1 ACL huérfana** (`ACL_LEGACY_MIGRACION_2022`).
   * **Protocolo Zero-Leak (Original vs. Sanitizado):** Mostrá con el conmutador cómo la IP pública `200.45.112.18` se convierte a bloque de documentación RFC 5737 (`192.0.2.x`) y las claves (`claveinsegura`, `AdminSec2025!`, `public`) a `<REDACTED_*>` antes de tocar la IA.
   * **Validador Gramatical Batfish (`bf.q.initIssues`):** Cartel verde `✅ Batfish parseó toda la configuración sin líneas no reconocidas`.
4. Hacé clic en **"Confirmar y ejecutar auditoría"**.

---

### ETAPA 2 — Auditoría Inicial (Estado Vulnerable) y Uso de Todas las Herramientas

Al terminar la primera auditoría vas a ver un **Score de Seguridad bajo (~15/100 — Crítico)** y **7 hallazgos**. Ahora recorré las 5 pestañas haciendo las **Pruebas Espejo**:

#### A) Pestaña 3 (*Topología & simulación*) y Pestaña 4 (*Herramientas Batfish*) ↔ Packet Tracer

| # | Flujo a Probar | Prueba en tu App (Traceroute / TestFilters) | Prueba idéntica en Packet Tracer | Resultado Inicial (Vulnerable) |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Ataque WAN ➔ Base de Datos Crítica (`HTTPS 443`)** | Origen `WAN` (`8.8.8.66`) ➔ Destino `172.16.10.50` ➔ `TCP 443` | En `PC-ATACANTE-WAN` ➔ *Web Browser* ➔ `https://172.16.10.50` | **🚨 PERMITIDO (Brecha por Shadowing):** La app muestra que la regla `10 permit tcp any 172.16.10.0/24 eq 443` deja pasar el paquete y anula la regla `20 deny`. En Packet Tracer carga la web de la base de datos. |
| **2** | **Tráfico Legítimo WAN ➔ Web Pública (`HTTPS 443`)** | Origen `WAN` (`8.8.8.66`) ➔ Destino `172.16.10.10` ➔ `TCP 443` | En `PC-ATACANTE-WAN` ➔ *Web Browser* ➔ `https://172.16.10.10` | **✅ PERMITIDO:** Carga el servidor web público. |
| **3** | **Ataque WAN ➔ Telnet del Router (`TCP 23`)** | Origen `WAN` (`8.8.8.66`) ➔ Destino `200.45.112.18` ➔ `TCP 23` | En `PC-ATACANTE-WAN` ➔ *Command Prompt* ➔ `telnet 200.45.112.18` | **🚨 PERMITIDO (Brecha Crítica):** La regla `30` y las VTY sin `access-class` permiten login Telnet en texto plano desde Internet. |
| **4** | **Movimiento Lateral VLAN 10 Usuarios ➔ VLAN 20 Gestión** | Origen `LAN` (`192.168.10.10`) ➔ Destino `192.168.20.10` ➔ `ICMP / TCP 22` | En `PC-VENTAS-VLAN10` ➔ *Command Prompt* ➔ `ping 192.168.20.10` | **🚨 PERMITIDO (Fuga entre VLANs):** Porque `ACL_LAN_IN` tiene `10 permit ip any any`. En la **Matriz de Aislamiento** la celda `LAN ➔ GESTION` aparece en rojo (**`FUGA`**). |
| **5** | **Salida Legítima VLAN 10 Usuarios ➔ Internet** | Origen `LAN` (`192.168.10.10`) ➔ Destino `8.8.8.8` ➔ `TCP 80 / 443` | En `PC-VENTAS-VLAN10` ➔ *Web Browser* ➔ `http://8.8.8.8` | **✅ PERMITIDO:** Los usuarios de Ventas navegan a Internet. |

* **En la Pestaña 4 (*Herramientas Batfish*), mostrá además los 6 botones formales:**
  1. **Reglas pisadas y redundantes (`filterLineReachability`):** Certifica matemáticamente el `CRITICAL_SHADOWING` de la línea 20 y la redundancia (`REDUNDANT`) de la línea 70 con la 60.
  2. **Puertos críticos expuestos (`searchFilters`):** Detecta formalmente **Telnet (`TCP/23`)**, **RDP (`TCP/3389`)** y **HTTP (`TCP/80`)** abiertos en `ACL_WAN_IN`.
  3. **Búsqueda simbólica (`reachability`):** Probá desde `WAN` hacia `DMZ` en puertos `23,80,443,3389`.
  4. **Modelo de red en Batfish:** Muestra las 5 interfaces modeladas y la tabla de enrutamiento con las VLANs `192.168.10.0/24`, `192.168.20.0/24`, `172.16.10.0/24` y la ruta default `0.0.0.0/0`.
  5. **Reemplazos de sanitización:** Muestra la tabla de mapeo y el diff línea por línea de lo que se ocultó a la nube.

---

### ETAPA 3 — Criterio de Zonas y Generación del Plan C en Vivo (Pestaña 1)

1. Volvé a la **Pestaña 1 (*Postura & hallazgos*)**.
2. Abrí el hallazgo de **`ACL_LAN_IN` (`Permisividad Excesiva - 10 permit ip any any`)**:
   * Mostrá el cuadro de **Criterio Arquitectónico de Zonas**: explica por qué en sentido **`LAN (Zona Segura) ➔ WAN (Zona Menos Segura)`** sí es razonable mantener **`any` en el destino** para navegar a Internet, a diferencia del sentido entrante `WAN ➔ DMZ`.
3. Hacé clic en la sub-pestaña **`🧠 Consultar excepción / Plan C (IA)`**, escribí con tus propias palabras:
   > *"La VLAN 10 de usuarios necesita salir a Internet con destino any para navegar, pero quiero bloquear el acceso lateral hacia la VLAN 20 de Gestión y la DMZ."*
4. Hacé clic en **"🧠 Evaluar excepción y generar Plan C"**:
   * La app aprueba la excepción con controles compensatorios, genera los comandos del **Plan C** (bloquea tráfico hacia `192.168.20.0/24`, `172.16.10.0/24` y `SMB/445`, pero permite a `192.168.10.0/24` salir hacia `any` en `80, 443, 53, ICMP`) y **lo selecciona automáticamente en el Centro de Decisiones What-If**.

---

### ETAPA 4 — Simulación What-If y Aplicación de la Remediación en Packet Tracer (Pestaña 2)

1. Pasá a la **Pestaña 2 (*Decisiones What-If*)**:
   * Vas a ver todos los hallazgos ordenados *top-down* con **Plan A** seleccionado y el hallazgo de `ACL_LAN_IN` con **`🧠 Plan C`** seleccionado.
2. Hacé clic en **"🔬 Simular selección en Batfish"**:
   * La postura proyectada salta de **15 ➔ ~79-95 pts**.
   * En la tabla **"Cambios en la matriz de aislamiento"**, Batfish certifica que **`LAN ➔ GESTION`** pasa de **`FUGA` ➔ `AISLADO`**.
   * Aparece el diff sintáctico completo de la configuración candidata.
3. **Aplicar la remediación en Packet Tracer:**
   * Descargá o copiá el script desde **"🛠️ Descargar remediación consolidada (.cli)"** (o copiá este bloque consolidado que une los Planes A + tu Plan C) y pegalo en la CLI de **`R-BORDE-CORP`**:

```cisco
enable
configure terminal
!
! 1. Remediación de ACL_WAN_IN (Resuelve Shadowing de línea 20, cierra Telnet 23, quita temporal 3389 y duplicada 70)
ip access-list extended ACL_WAN_IN
 no 10
 no 20
 no 30
 no 40
 no 50
 no 70
 10 deny tcp any host 172.16.10.50 eq 443
 20 permit tcp any 172.16.10.0 0.0.0.255 eq 443
!
! 2. Plan C en ACL_LAN_IN (Aísla VLAN 20 Gestión y SMB, pero permite destino 'any' a Internet para VLAN 10)
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
!
! 3. Hardening del plano de gestión VTY (Solo SSH desde VLAN 20 Gestión)
ip access-list standard ACL_MGMT_VTY
 10 permit 192.168.20.0 0.0.0.255
line vty 0 4
 transport input ssh
 access-class ACL_MGMT_VTY in
 exit
!
! 4. Eliminación de ACL Huérfana
no ip access-list extended ACL_LEGACY_MIGRACION_2022
!
end
write memory
```

---

### ETAPA 5 — Segunda Auditoría y Prueba Espejo Final (¡El Éxito de la Demo!)

1. **Primero comprobalo en Packet Tracer:**
   * Desde **`PC-ATACANTE-WAN` (`8.8.8.66`)**:
     * Abrí *Web Browser* ➔ `https://172.16.10.50` (Base de Datos) ➔ **`Request Timeout` (¡Bloqueado por la nueva regla 10!)**.
     * Abrí *Web Browser* ➔ `https://172.16.10.10` (Web Pública) ➔ **¡Carga perfecto! (Servicio público intacto)**.
     * Abrí *Command Prompt* ➔ `telnet 200.45.112.18` ➔ **`Connection timed out` (¡Telnet bloqueado!)**.
   * Desde **`PC-VENTAS-VLAN10` (`192.168.10.10`)**:
     * Abrí *Command Prompt* ➔ `ping 192.168.20.10` (intento de tocar la VLAN 20 de Admins) ➔ **`Destination host unreachable` (¡Bloqueado por el Plan C!)**.
     * Abrí *Web Browser* ➔ `http://8.8.8.8` (salida a Internet con destino `any`) ➔ **¡Carga Internet sin problemas!**.

2. **Ahora hacé la Segunda Auditoría en tu App (`Ctrl+C` / `Ctrl+V`):**
   * En la CLI de **`R-BORDE-CORP`**, volvé a ejecutar:
     ```cisco
     show running-config
     ```
   * Copiá la configuración remediada, hacé clic en **"📂 Cambiar archivo"** arriba a la derecha en la app, pegala con **`Ctrl+V`** y ejecutá la auditoría.
   * **Resultado en la App:**
     * **Score de Seguridad:** Salta de **15/100 ➔ 95/100 (Postura Óptima / Hardened)**.
     * **Anomalías Matemáticas en Batfish (`filterLineReachability`):** **0 reglas sombreadas, 0 redundancias**.
     * **Simulador de Paquetes (`TestFilters` / `Traceroute`):**
       * `8.8.8.66 ➔ 172.16.10.50 (TCP 443)` = **`⛔ DENY`** (coincide 100% con el `Request Timeout` de Packet Tracer).
       * `8.8.8.66 ➔ 172.16.10.10 (TCP 443)` = **`✅ PERMIT`** (coincide 100% con el navegador de Packet Tracer).
       * `192.168.10.10 ➔ 192.168.20.10 (TCP 22 / ICMP)` = **`⛔ DENY`** (coincide 100% con el bloqueo entre VLANs en Packet Tracer).
       * `192.168.10.10 ➔ 8.8.8.8 (TCP 80 / 443)` = **`✅ PERMIT`** (coincide 100% con la navegación web de la VLAN 10).
   * Por último, entrá a la **Pestaña 5 (*Reporte ejecutivo*)** y hacé clic en **"📑 Descargar PDF"** para mostrar el informe gerencial limpio del antes y el después.
