"""
Guías pedagógicas de los laboratorios demo (RF-10: vista previa pre-flight).

Contenido estático y curado: documenta qué vulnerabilidades se inyectaron a propósito en cada
configuración de laboratorio y en qué líneas, para que el usuario sepa qué esperar ANTES de
ejecutar la auditoría. No es un análisis: la verificación formal sigue delegada a Batfish.
"""
from typing import Any, Dict, List, Optional

DEMO_GUIDES: Dict[str, Dict[str, Any]] = {
    "ios": {
        "titulo": "Laboratorio Cisco IOS / IOS-XE — Router de borde corporativo",
        "descripcion": (
            "Router de borde con tres zonas (WAN, LAN y DMZ) y una colección de malas prácticas "
            "inyectadas a propósito para poner a prueba el motor de auditoría."
        ),
        "vulnerabilidades": [
            {
                "severidad": "CRITICA", "lineas": [43, 44],
                "titulo": "Shadowing crítico: un permit anula un deny",
                "explicacion": (
                    "La regla 10 permite todo el HTTPS hacia la DMZ /24 antes de que la regla 20 intente "
                    "bloquear el servidor 172.16.10.50. Cisco evalúa de arriba hacia abajo, por lo que el deny nunca se ejecuta."
                ),
                "riesgo": "El servidor que se quiso proteger queda expuesto a Internet.",
            },
            {
                "severidad": "CRITICA", "lineas": [46],
                "titulo": "Telnet (TCP/23) expuesto a Internet",
                "explicacion": "La regla 30 permite Telnet desde cualquier origen hacia la IP pública del router.",
                "riesgo": "Telnet viaja en texto plano: credenciales y sesión pueden ser capturadas o atacadas por fuerza bruta.",
            },
            {
                "severidad": "ALTA", "lineas": [48, 49],
                "titulo": "Regla temporal vencida sin retirar (RDP)",
                "explicacion": "Un acceso RDP (TCP/3389) para soporte externo cuyo ticket expiró en diciembre de 2023 sigue activo.",
                "riesgo": "Acceso remoto olvidado hacia un servidor de la DMZ desde un tercero.",
            },
            {
                "severidad": "ALTA", "lineas": [58],
                "titulo": "ACL de LAN con permit ip any any",
                "explicacion": "La ACL de la red de usuarios permite cualquier tráfico hacia cualquier destino.",
                "riesgo": "Sin segmentación ni filtrado de salida: facilita movimiento lateral y exfiltración de datos.",
            },
            {
                "severidad": "ALTA", "lineas": [72, 73, 75, 76],
                "titulo": "Líneas VTY con Telnet y sin access-class",
                "explicacion": "Las líneas de administración remota aceptan Telnet y no restringen quién puede conectarse.",
                "riesgo": "Cualquier host con alcance IP puede intentar autenticarse en el plano de gestión.",
            },
            {
                "severidad": "ALTA", "lineas": [5, 13],
                "titulo": "Secretos débiles: enable password y sin cifrado de contraseñas",
                "explicacion": "Se define un enable password en texto claro y el servicio password-encryption está desactivado.",
                "riesgo": "Cualquiera con acceso de lectura a la configuración obtiene credenciales privilegiadas.",
            },
            {
                "severidad": "MEDIA", "lineas": [66],
                "titulo": "Comunidad SNMP simple sin ACL",
                "explicacion": "La comunidad SNMP v2c de solo lectura no está limitada a estaciones de gestión autorizadas.",
                "riesgo": "Divulgación de inventario y topología a quien conozca o adivine la comunidad.",
            },
            {
                "severidad": "MEDIA", "lineas": [51, 52],
                "titulo": "Regla redundante duplicada",
                "explicacion": "Las reglas 60 y 70 son idénticas: la segunda nunca aporta nada.",
                "riesgo": "No abre ninguna brecha, pero ensucia la política y dificulta las auditorías.",
            },
            {
                "severidad": "BAJA", "lineas": [61, 62, 63],
                "titulo": "ACL huérfana (declarada y nunca aplicada)",
                "explicacion": "ACL_LEGACY_MIGRACION_2022 existe en la configuración pero ninguna interfaz la usa.",
                "riesgo": "Deuda técnica: puede aplicarse por error en el futuro con reglas ya obsoletas.",
            },
            {
                "severidad": "BAJA", "lineas": [53],
                "titulo": "Falta un deny explícito con log al final de la ACL WAN",
                "explicacion": "El tráfico no coincidente cae en el deny implícito, que no deja registro.",
                "riesgo": "Sin visibilidad de intentos de intrusión bloqueados.",
            },
        ],
    },
    "asa": {
        "titulo": "Laboratorio Cisco ASA 9.8 — Firewall perimetral con object-groups",
        "descripcion": (
            "Firewall ASA con interfaces outside / inside / dmz, objetos y grupos de objetos, "
            "e inconsistencias de política inyectadas a propósito."
        ),
        "vulnerabilidades": [
            {
                "severidad": "CRITICA", "lineas": [39, 40],
                "titulo": "Shadowing: permit ip any anula el bloqueo de MySQL",
                "explicacion": (
                    "La línea 39 permite todo IP hacia la DMZ 172.16.50.0/24. La línea 40, que bloquea "
                    "MySQL (TCP/3306) al servidor de base de datos, queda inalcanzable."
                ),
                "riesgo": "La base de datos de la DMZ queda expuesta a Internet.",
            },
            {
                "severidad": "ALTA", "lineas": [42],
                "titulo": "SSH (TCP/22) abierto a Internet sobre la IP del firewall",
                "explicacion": "Se permite SSH desde cualquier origen hacia la IP pública del ASA.",
                "riesgo": "Superficie de ataque directa sobre el plano de gestión del perímetro.",
            },
            {
                "severidad": "ALTA", "lineas": [52, 53, 54],
                "titulo": "Gestión ASDM/SSH habilitada desde cualquier red por outside",
                "explicacion": "http y ssh aceptan 0.0.0.0/0 en la interfaz outside.",
                "riesgo": "Cualquier host de Internet puede intentar autenticarse en la administración del firewall.",
            },
            {
                "severidad": "ALTA", "lineas": [44],
                "titulo": "Regla temporal olvidada (TCP/8080)",
                "explicacion": "Acceso puntual de un host externo hacia la DMZ que no fue retirado.",
                "riesgo": "Acceso residual de un tercero hacia un servidor interno.",
            },
            {
                "severidad": "MEDIA", "lineas": [56],
                "titulo": "Comunidad SNMP en texto claro dentro de la configuración",
                "explicacion": "La comunidad SNMP queda visible en la configuración y sin restricción de origen.",
                "riesgo": "Divulgación de información de gestión.",
            },
            {
                "severidad": "BAJA", "lineas": [49],
                "titulo": "ACL huérfana con permit ip any any",
                "explicacion": "ACL_TEST_ORPHAN no se aplica a ninguna interfaz, pero contiene un permit total.",
                "riesgo": "Riesgo latente: si alguien la aplica por error, anula toda la protección de esa interfaz.",
            },
        ],
    },
}


def get_demo_guide(sample_id: str) -> Optional[Dict[str, Any]]:
    """Devuelve la guía pedagógica del laboratorio demo, o None si no existe."""
    return DEMO_GUIDES.get(sample_id)


def guide_lines(guide: Optional[Dict[str, Any]]) -> Dict[int, str]:
    """Mapa línea -> severidad más alta que la afecta, para resaltar el visor de configuración."""
    order = ["CRITICA", "ALTA", "MEDIA", "BAJA"]
    result: Dict[int, str] = {}
    if not guide:
        return result
    for v in guide["vulnerabilidades"]:
        for ln in v["lineas"]:
            current = result.get(ln)
            if current is None or order.index(v["severidad"]) < order.index(current):
                result[ln] = v["severidad"]
    return result


def list_guides_ids() -> List[str]:
    return sorted(DEMO_GUIDES)
