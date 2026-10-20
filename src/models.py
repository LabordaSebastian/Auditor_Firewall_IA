from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SeveridadEnum(str, Enum):
    CRITICA = "CRITICA"
    ALTA = "ALTA"
    MEDIA = "MEDIA"
    BAJA = "BAJA"


class NivelImpactoEnum(str, Enum):
    NULO = "NULO (Cambio Seguro / Regla Inalcanzable)"
    BAJO = "BAJO (Solo agrega trazabilidad o limpia objetos huérfanos)"
    MEDIO = "MEDIO (Restringe puertos/subredes; requiere verificar contadores)"
    ALTO = "ALTO (Bloquea flujos permisivos activos; riesgo de corte si no se audita antes)"


class OpcionDecision(BaseModel):
    nombre_plan: str = Field(description="Ej: Plan A (Hardening Estricto) o Plan B (Transición con Monitoreo)")
    descripcion_accion: str
    efecto_en_red: str
    comandos_cli_implementacion: List[str]
    comandos_cli_rollback: List[str]


class HallazgoFirewall(BaseModel):
    id_hallazgo: str = Field(description="Identificador único, ej: FW-CISCO-001")
    acl_o_componente: str = Field(description="Nombre de la ACL, interfaz o línea VTY afectada")
    linea_o_regla_afectada: str = Field(description="Comando o ACE exacto donde reside el problema")
    severidad: SeveridadEnum
    categoria_problema: str = Field(
        description="Ej: Shadowed Rule, Critical Shadowing (Permit sobre Deny), Exposición WAN, Permisividad Excesiva, Higiene/Regla Temporal, Falta de Logging, Management Plane"
    )
    confirmado_por_batfish: bool = Field(description="True si fue validado matemáticamente por Batfish")
    controles_normativos: List[str] = Field(
        description=(
            "Lista de controles normativos en formato claro para todo público (APB): "
            "'CODIGO - Nombre Corto: Explicación sencilla de qué exige la norma'. "
            "Ej: 'DISA STIG NET-0405 - Orden de Reglas: Exige que las reglas específicas precedan a las generales para no anular bloqueos.' "
            "NUNCA devolver solo siglas secas sin explicación."
        )
    )
    diagnostico_tecnico: str = Field(description="Explicación detallada de por qué la regla es vulnerable o ineficiente")
    como_mejora_la_red: str = Field(description="Beneficio directo de seguridad o rendimiento al corregir esta regla")
    nivel_impacto_operativo: NivelImpactoEnum
    analisis_blast_radius: str = Field(description="Qué flujos, usuarios o servicios podrían verse afectados al aplicar el cambio")
    plan_a_recomendado: OpcionDecision
    plan_b_conservador: OpcionDecision


class ResumenEjecutivo(BaseModel):
    hostname_detectado: str
    dialecto_cisco: str = Field(description="Cisco IOS / IOS-XE / Cisco ASA")
    score_seguridad_actual: int = Field(ge=0, le=100)
    score_seguridad_proyectado: int = Field(ge=0, le=100)
    total_hallazgos: int
    resumen_gerencial: str
    orden_prioridad_implementacion: List[str] = Field(
        description="Lista ordenada de IDs de hallazgos sugiriendo qué aplicar primero (empezando por impacto operativo NULO/BAJO)"
    )


class ReporteAuditoriaFirewall(BaseModel):
    resumen: ResumenEjecutivo
    hallazgos: List[HallazgoFirewall]


# Modelos para datos internos de topología y análisis matemático
class ReglaACL(BaseModel):
    numero_linea: int
    texto_crudo: str
    accion: str  # permit / deny / remark
    protocolo: Optional[str] = None
    origen: Optional[str] = None
    destino: Optional[str] = None
    puertos: Optional[str] = None
    comentario: Optional[str] = None
    hit_count: Optional[int] = None


class ContextoInterfaz(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    ip_address: Optional[str] = None
    security_level: Optional[int] = None  # Para Cisco ASA
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None


class ContextoTopologia(BaseModel):
    hostname: str
    dialecto: str
    interfaces: Dict[str, ContextoInterfaz] = Field(default_factory=dict)
    acls_activas: List[str] = Field(default_factory=list)
    acls_huerfanas: List[str] = Field(default_factory=list)
    vty_access_class: Optional[str] = None
    vty_transport_input: Optional[str] = None
    total_lineas_config: int = 0


class HallazgoMatematico(BaseModel):
    tipo: str  # SHADOWED, REDUNDANT, CRITICAL_SHADOWING, UNREACHABLE
    filtro_nombre: str
    linea_afectada: str
    indice_linea: int
    linea_bloqueadora: Optional[str] = None
    indice_bloqueadora: Optional[int] = None
    descripcion: str
