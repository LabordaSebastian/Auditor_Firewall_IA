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


    # ------------------------------------------------------------------
    # MEJ-05: consultas interactivas para el dashboard (Digital Twin)
    # ------------------------------------------------------------------
    SUCCESS_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK", "DELIVERED_TO_INSIDE"}

    CRITICAL_SERVICES: List[Tuple[str, str, str]] = [
        ("FTP", "TCP", "21"),
        ("SSH", "TCP", "22"),
        ("Telnet", "TCP", "23"),
        ("HTTP", "TCP", "80"),
        ("SMB", "TCP", "445"),
        ("RDP", "TCP", "3389"),
        ("SNMP", "UDP", "161"),
        ("TFTP", "UDP", "69"),
    ]
    CRITICAL_TCP_PORTS = "21-23,80,445,3389"

    def _load_snapshot(self, config_text: str, filename: str, snap_name: str, network_name: str) -> None:
        """Carga un snapshot temporal en Batfish y limpia el directorio local inmediatamente."""
        if not self.session:
            self.connect()
        temp_dir = Path(tempfile.mkdtemp(prefix="batfish_snap_"))
        try:
            configs_dir = temp_dir / "configs"
            configs_dir.mkdir(parents=True, exist_ok=True)
            (configs_dir / filename).write_text(config_text, encoding="utf-8")
            self.session.set_network(network_name)
            self.session.init_snapshot(str(temp_dir), name=snap_name, overwrite=True)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _first_node(self, snap_name: str) -> str:
        df = self.session.q.nodeProperties().answer(snapshot=snap_name).frame()
        return str(df.iloc[0]["Node"])

    @staticmethod
    def _step_info(step: Any) -> Dict[str, str]:
        return {"accion": str(getattr(step, "action", "")), "detalle": str(getattr(step, "detail", ""))}

    def simulate_packet(
        self,
        config_text: str,
        filename: str,
        start_interface: str,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        dst_port: Optional[int] = None,
        network_name: str = "cisco_auditor_web",
    ) -> Dict[str, Any]:
        """
        'Camino del Paquete': ejecuta bf.q.traceroute() y explica la decisión del filtro
        (testFilters) para identificar la regla exacta que permite o descarta el flujo.
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        snap = "snap_traceroute"
        self._load_snapshot(config_text, filename, snap, network_name)
        node = self._first_node(snap)
        proto = protocol.upper()

        header_kwargs: Dict[str, Any] = {"srcIps": src_ip, "dstIps": dst_ip, "ipProtocols": [proto]}
        if proto in {"TCP", "UDP"}:
            header_kwargs["srcPorts"] = "49152"
            if dst_port is not None:
                header_kwargs["dstPorts"] = str(dst_port)
        headers = HeaderConstraints(**header_kwargs)

        df = self.session.q.traceroute(
            startLocation=f"@enter({node}[{start_interface}])", headers=headers
        ).answer(snapshot=snap).frame()
        if df.empty or not df.iloc[0]["Traces"]:
            return {"permitido": False, "disposicion": "SIN_TRAZA", "hops": [], "regla": None, "bloqueado_en": None}

        trace = df.iloc[0]["Traces"][0]
        disposition = str(trace.disposition)
        hops: List[Dict[str, Any]] = []
        decisive: Optional[Dict[str, str]] = None
        for hop in trace.hops:
            steps = [self._step_info(s) for s in hop.steps]
            hops.append({"nodo": str(hop.node), "pasos": steps})
            for s in steps:
                if "_FILTER)" in s["detalle"] and s["accion"] in {"PERMITTED", "DENIED"}:
                    decisive = {"filtro": s["detalle"].split(" (")[0], "accion": s["accion"],
                                "direccion": "ENTRADA" if "INGRESS" in s["detalle"] else "SALIDA"}
                    if s["accion"] == "DENIED":
                        break

        rule_line: Optional[str] = None
        if decisive:
            try:
                tf = self.session.q.testFilters(
                    nodes=node, filters=decisive["filtro"], headers=headers
                ).answer(snapshot=snap).frame()
                if not tf.empty:
                    rule_line = str(tf.iloc[0]["Line_Content"])
            except Exception:
                rule_line = None

        permitted = disposition in self.SUCCESS_DISPOSITIONS
        return {
            "permitido": permitted,
            "disposicion": disposition,
            "nodo": node,
            "hops": hops,
            "filtro_decisivo": decisive,
            "regla": rule_line,
            "bloqueado_en": None if permitted else (decisive or {"filtro": None}),
        }

    def scan_exposed_ports(
        self,
        config_text: str,
        filename: str,
        acl_names: List[str],
        network_name: str = "cisco_auditor_web",
    ) -> List[Dict[str, Any]]:
        """
        Escaneo de puertos críticos: bf.q.searchFilters() busca, para cada ACL de entrada WAN,
        un flujo PERMITIDO hacia cada servicio de riesgo. Cada resultado es una exposición formal.
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        snap = "snap_exposure"
        self._load_snapshot(config_text, filename, snap, network_name)
        results: List[Dict[str, Any]] = []
        for acl in acl_names:
            for service, proto, port in self.CRITICAL_SERVICES:
                try:
                    df = self.session.q.searchFilters(
                        filters=acl,
                        headers=HeaderConstraints(ipProtocols=[proto], dstPorts=port),
                        action="permit",
                    ).answer(snapshot=snap).frame()
                except Exception:
                    continue
                for _, row in df.iterrows():
                    trace_txt = str(row.get("Trace", ""))
                    line = trace_txt.split("Matched line", 1)[-1].strip(" -\n") if "Matched line" in trace_txt else trace_txt
                    flow = str(row.get("Flow", ""))
                    results.append({
                        "acl": acl, "servicio": service, "protocolo": proto,
                        "puerto": int(port), "regla": line.splitlines()[0] if line else "", "flujo_ejemplo": flow,
                    })
        return results

    def check_zone_isolation(
        self,
        config_text: str,
        filename: str,
        zones: List[Dict[str, Any]],
        network_name: str = "cisco_auditor_web",
    ) -> List[Dict[str, Any]]:
        """
        Matriz de aislamiento: para cada par de zonas ejecuta bf.q.reachability() (tráfico
        cualquiera y tráfico a puertos críticos) y clasifica la celda:
        AISLADO / RESTRINGIDO / PERMITIDO / FUGA (puertos críticos abiertos desde zona menos confiable).
        `zones`: [{nombre, interfaz, subred, confianza}]
        """
        from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints

        snap = "snap_isolation"
        self._load_snapshot(config_text, filename, snap, network_name)
        node = self._first_node(snap)
        cells: List[Dict[str, Any]] = []

        def reachable(src: Dict[str, Any], dst: Dict[str, Any], critical: bool) -> bool:
            kwargs: Dict[str, Any] = {"dstIps": dst["subred"]}
            if src.get("subred") and src["nombre"] != "WAN":
                kwargs["srcIps"] = src["subred"]
            if critical:
                kwargs.update({"ipProtocols": ["TCP"], "dstPorts": self.CRITICAL_TCP_PORTS})
            df = self.session.q.reachability(
                pathConstraints=PathConstraints(startLocation=f"@enter({node}[{src['interfaz']}])"),
                headers=HeaderConstraints(**kwargs),
                actions="SUCCESS",
            ).answer(snapshot=snap).frame()
            return not df.empty

        for src in zones:
            for dst in zones:
                if src["nombre"] == dst["nombre"]:
                    continue
                try:
                    any_open = reachable(src, dst, critical=False)
                    crit_open = reachable(src, dst, critical=True) if any_open else False
                except Exception as exc:  # consulta fallida: se reporta como desconocido
                    cells.append({"origen": src["nombre"], "destino": dst["nombre"],
                                  "estado": "DESCONOCIDO", "detalle": f"Consulta no resuelta: {exc}"[:160]})
                    continue
                if not any_open:
                    estado, detalle = "AISLADO", "Batfish no encontró ningún flujo permitido."
                elif crit_open and src["confianza"] < dst["confianza"]:
                    estado = "FUGA"
                    detalle = f"Puertos críticos ({self.CRITICAL_TCP_PORTS}) alcanzables desde una zona menos confiable."
                elif crit_open:
                    estado, detalle = "PERMITIDO", "Zona más confiable con salida amplia (incluye puertos de gestión)."
                else:
                    estado, detalle = "RESTRINGIDO", "Hay flujos permitidos, pero sin puertos críticos expuestos."
                cells.append({"origen": src["nombre"], "destino": dst["nombre"], "estado": estado, "detalle": detalle})
        return cells

    def compare_candidate(
        self,
        base_config: str,
        candidate_config: str,
        filename: str,
        acl_names: List[str],
        network_name: str = "cisco_auditor_web",
    ) -> Dict[str, Any]:
        """
        Digital Twin diferencial: carga base y candidata como dos snapshots y ejecuta
        bf.q.compareFilters() por ACL. Devuelve los pares de líneas que tratan distinto un mismo flujo.
        """
        self._load_snapshot(base_config, filename, "snap_base", network_name)
        self._load_snapshot(candidate_config, filename, "snap_candidate", network_name)
        cambios: List[Dict[str, Any]] = []
        errores: List[str] = []
        for acl in acl_names:
            try:
                df = self.session.q.compareFilters(filters=acl).answer(
                    snapshot="snap_candidate", reference_snapshot="snap_base"
                ).frame()
            except Exception as exc:
                errores.append(f"{acl}: {str(exc).splitlines()[0][:100]}")
                continue
            for _, row in df.iterrows():
                cambios.append({
                    "acl": str(row.get("Filter_Name", acl)),
                    "accion_nueva": str(row.get("Line_Action", "")),
                    "linea_nueva": str(row.get("Line_Content", "")),
                    "linea_anterior": str(row.get("Reference_Line_Content", "")),
                })
        return {"cambios": cambios, "errores": errores, "total_cambios": len(cambios)}
