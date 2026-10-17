import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from pybatfish.client.session import Session
from pybatfish.exception import BatfishException
from src.config import BATFISH_HOST, BATFISH_PORT
from src.models import HallazgoMatematico


class BatfishUnavailableError(Exception):
    """Excepción lanzada cuando el servicio Batfish no está respondiendo en el puerto configurado."""
    pass


class BatfishAnalyzer:
    """
    Cliente para verificación formal matemática de ACLs y topología Cisco mediante Batfish.
    """

    def __init__(self, host: str = BATFISH_HOST, port: int = BATFISH_PORT):
        self.host = host
        self.port = port
        self.session: Optional[Session] = None

    def connect(self) -> None:
        """Establece conexión con el coordinador de Batfish."""
        try:
            self.session = Session(host=self.host)
            # Prueba de conectividad simple
            self.session.list_networks()
        except Exception as e:
            raise BatfishUnavailableError(
                f"No se pudo conectar a Batfish en {self.host}:{self.port}. "
                f"Verifica que el contenedor Docker 'batfish/allinone' esté ejecutándose. Detalle: {e}"
            ) from e

    def analyze_snapshot(self, sanitized_config_text: str, config_filename: str = "firewall.cfg", network_name: str = "cisco_auditor") -> List[HallazgoMatematico]:
        """
        Empaqueta la configuración en un snapshot temporal, la carga en Batfish
        y ejecuta consultas de alcanzabilidad de filtros (filterLineReachability).
        """
        if not self.session:
            self.connect()

        findings: List[HallazgoMatematico] = []
        temp_dir = Path(tempfile.mkdtemp(prefix="batfish_snap_"))

        try:
            configs_dir = temp_dir / "configs"
            configs_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = configs_dir / config_filename
            cfg_file.write_text(sanitized_config_text, encoding="utf-8")

            # Inicializar red y snapshot en Batfish
            self.session.set_network(network_name)
            snap_name = f"snap_{Path(config_filename).stem}"
            self.session.init_snapshot(str(temp_dir), name=snap_name, overwrite=True)

            # Consulta formal: filterLineReachability
            reachability_df = self.session.q.filterLineReachability().answer().frame()

            for _, row in reachability_df.iterrows():
                filter_name = str(row.get("Filter_Name", "ACL_DESCONOCIDA"))
                line_content = str(row.get("Line", ""))
                line_index = int(row.get("Line_Index", 0))
                action = str(row.get("Action", ""))
                reasons = row.get("Unreachable_Line_Action", "UNREACHABLE")
                blocking_lines = row.get("Blocking_Lines", [])

                tipo = "SHADOWED"
                if "REDUNDANT" in str(reasons).upper():
                    tipo = "REDUNDANT"

                blocking_desc = ""
                indice_bloqueadora = None
                linea_bloqueadora = None

                if blocking_lines and len(blocking_lines) > 0:
                    first_blocker = blocking_lines[0]
                    linea_bloqueadora = str(first_blocker)
                    blocking_desc = f" Bloqueada por regla superior: {linea_bloqueadora}."

                # Si es un Permit bloqueando un Deny posterior, es Critical Shadowing
                if action.lower() == "deny" and tipo == "SHADOWED":
                    tipo = "CRITICAL_SHADOWING"

                findings.append(
                    HallazgoMatematico(
                        tipo=tipo,
                        filtro_nombre=filter_name,
                        linea_afectada=line_content,
                        indice_linea=line_index,
                        linea_bloqueadora=linea_bloqueadora,
                        indice_bloqueadora=indice_bloqueadora,
                        descripcion=f"Verificado por Batfish: Regla {tipo.lower()} en {filter_name}.{blocking_desc}",
                    )
                )

        except Exception as e:
            if isinstance(e, BatfishUnavailableError):
                raise
            raise BatfishException(f"Error procesando snapshot en Batfish: {e}") from e
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return findings
