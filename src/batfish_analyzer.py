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

    # ------------------------------------------------------------------
    # Fase 2: resolución robusta de interfaces (fix ASA nameif)
    # ------------------------------------------------------------------
    @staticmethod
    def _split_interface(raw: Any) -> Tuple[str, str]:
        """'node[iface]' (o objeto Interface de pybatfish) -> (node, iface)."""
        hostname = getattr(raw, "hostname", None)
        iface = getattr(raw, "interface", None)
        if hostname is not None and iface is not None:
            return str(hostname), str(iface)
        text = str(raw)
        if "[" in text and text.endswith("]"):
            node, name = text[:-1].split("[", 1)
            return node, name
        return "", text

    def _interface_index(self, snap_name: str) -> List[Dict[str, Any]]:
        """Inventario de interfaces según el modelo de Batfish (nombre real, IP primaria, estado)."""
        df = self.session.q.interfaceProperties(
            properties="Primary_Address,Active,Description,Incoming_Filter_Name,Outgoing_Filter_Name"
        ).answer(snapshot=snap_name).frame()
        index: List[Dict[str, Any]] = []
        for _, row in df.iterrows():
            node, name = self._split_interface(row.get("Interface"))
            addr = row.get("Primary_Address")
            addr_txt = str(addr) if addr not in (None, "") and str(addr) != "None" else None
            index.append({
                "nodo": node, "interfaz": name,
                "ip": addr_txt.split("/")[0] if addr_txt else None, "prefijo": addr_txt,
                "activa": bool(row.get("Active")),
                "descripcion": None if row.get("Description") in (None, "None") else str(row.get("Description")),
                "acl_in": None if row.get("Incoming_Filter_Name") in (None, "None") else str(row.get("Incoming_Filter_Name")),
                "acl_out": None if row.get("Outgoing_Filter_Name") in (None, "None") else str(row.get("Outgoing_Filter_Name")),
            })
        return index

    def resolve_location(self, snap_name: str, config_iface: str, iface_ip: Optional[str] = None) -> Tuple[str, str]:
        """
        Traduce la interfaz de la configuración al nombre que usa Batfish.

        En IOS coincide (`GigabitEthernet0/0`), pero en ASA Batfish nombra las interfaces por su
        `nameif` (`outside`, `inside`, `dmz`). Se resuelve por nombre exacto y, si no coincide,
        por la IP primaria de la interfaz (dato invariante entre dialectos).
        Devuelve (nodo, interfaz_batfish). Lanza ValueError si no hay coincidencia.
        """
        index = self._interface_index(snap_name)
        for entry in index:
            if entry["interfaz"].lower() == config_iface.lower():
                return entry["nodo"], entry["interfaz"]
        if iface_ip:
            for entry in index:
                if entry["ip"] == iface_ip:
                    return entry["nodo"], entry["interfaz"]
        raise ValueError(
            f"Batfish no reconoce la interfaz '{config_iface}'"
            + (f" (IP {iface_ip})" if iface_ip else "")
            + ". Interfaces modeladas: " + ", ".join(e["interfaz"] for e in index)
        )

    def _start_location(self, snap_name: str, config_iface: str, iface_ip: Optional[str] = None) -> Tuple[str, str]:
        node, bf_iface = self.resolve_location(snap_name, config_iface, iface_ip)
        return node, f"@enter({node}[{bf_iface}])"

    @classmethod
    def _decisive_filter(cls, trace: Any) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, str]]]:
        """Extrae los saltos de una traza y el filtro (ACL) que decidió el destino del flujo."""
        hops: List[Dict[str, Any]] = []
        decisive: Optional[Dict[str, str]] = None
        for hop in trace.hops:
            steps = [cls._step_info(s) for s in hop.steps]
            hops.append({"nodo": str(hop.node), "pasos": steps})
            for s in steps:
                if "_FILTER)" in s["detalle"] and s["accion"] in {"PERMITTED", "DENIED"}:
                    if s["detalle"].startswith("~") and s["accion"] == "PERMITTED":
                        continue  # filtros sintéticos de Batfish (p. ej. ASA combinados) sin decisión real
                    decisive = {"filtro": s["detalle"].split(" (")[0], "accion": s["accion"],
                                "direccion": "ENTRADA" if "INGRESS" in s["detalle"] else "SALIDA"}
                    if s["accion"] == "DENIED":
                        return hops, decisive
        return hops, decisive

    @staticmethod
    def _flow_info(flow: Any) -> Dict[str, Any]:
        proto = str(getattr(flow, "ipProtocol", "") or "")
        port = getattr(flow, "dstPort", None)
        return {
            "src_ip": str(getattr(flow, "srcIp", "")), "dst_ip": str(getattr(flow, "dstIp", "")),
            "protocolo": proto,
            "puerto": int(port) if proto in {"TCP", "UDP"} and port is not None else None,
            "texto": str(flow),
        }

    @staticmethod
    def _rule_text(line: Any) -> Optional[str]:
        txt = str(line or "").strip()
        if not txt:
            return None
        return "deny implícito (ninguna regla coincide)" if txt.lower() == "no-match" else txt

    def check_syntax(
        self,
        config_text: str,
        filename: str,
        network_name: str = "cisco_auditor_web",
    ) -> List[Dict[str, Any]]:
        """
        Control de calidad de sintaxis: bf.q.initIssues() lista líneas no reconocidas, comandos
        no soportados y problemas de conversión que Batfish detectó al parsear la configuración.
        """
        snap = "snap_syntax"
        self._load_snapshot(config_text, filename, snap, network_name)
        df = self.session.q.initIssues().answer(snapshot=snap).frame()
        issues: List[Dict[str, Any]] = []
        for _, row in df.iterrows():
            lineas: List[int] = []
            for fl in row.get("Source_Lines") or []:
                raw = getattr(fl, "lines", None)
                if raw is None and isinstance(fl, dict):
                    raw = fl.get("lines")
                lineas.extend(int(n) for n in (raw or []) if str(n).isdigit())
            issues.append({
                "tipo": str(row.get("Type", "Desconocido")),
                "detalle": str(row.get("Details", ""))[:300],
                "linea_texto": str(row.get("Line_Text", "") or "")[:200],
                "lineas": sorted(set(lineas)),
            })
        return issues

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
        start_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        'Camino del Paquete': ejecuta bf.q.traceroute() y explica la decisión del filtro
        (testFilters) para identificar la regla exacta que permite o descarta el flujo.
        `start_ip` (IP de la interfaz de entrada) permite resolver el nombre real en ASA (nameif).
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        snap = "snap_traceroute"
        self._load_snapshot(config_text, filename, snap, network_name)
        node, location = self._start_location(snap, start_interface, start_ip)
        proto = protocol.upper()

        header_kwargs: Dict[str, Any] = {"srcIps": src_ip, "dstIps": dst_ip, "ipProtocols": [proto]}
        if proto in {"TCP", "UDP"}:
            header_kwargs["srcPorts"] = "49152"
            if dst_port is not None:
                header_kwargs["dstPorts"] = str(dst_port)
        headers = HeaderConstraints(**header_kwargs)

        df = self.session.q.traceroute(startLocation=location, headers=headers).answer(snapshot=snap).frame()
        if df.empty or not df.iloc[0]["Traces"]:
            return {"permitido": False, "disposicion": "SIN_TRAZA", "hops": [], "regla": None, "bloqueado_en": None}

        trace = df.iloc[0]["Traces"][0]
        disposition = str(trace.disposition)
        hops, decisive = self._decisive_filter(trace)

        rule_line: Optional[str] = None
        if decisive:
            try:
                tf = self.session.q.testFilters(
                    nodes=node, filters=decisive["filtro"], headers=headers
                ).answer(snapshot=snap).frame()
                if not tf.empty:
                    rule_line = self._rule_text(tf.iloc[0]["Line_Content"])
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
        cells: List[Dict[str, Any]] = []
        locations: Dict[str, str] = {}
        for z in zones:
            try:
                locations[z["nombre"]] = self._start_location(snap, z["interfaz"], z.get("ip"))[1]
            except ValueError:
                continue

        def reachable(src: Dict[str, Any], dst: Dict[str, Any], critical: bool) -> bool:
            kwargs: Dict[str, Any] = {"dstIps": dst["subred"]}
            if src.get("subred") and src.get("zona", src["nombre"]) != "WAN":
                kwargs["srcIps"] = src["subred"]
            if critical:
                kwargs.update({"ipProtocols": ["TCP"], "dstPorts": self.CRITICAL_TCP_PORTS})
            df = self.session.q.reachability(
                pathConstraints=PathConstraints(startLocation=locations[src["nombre"]]),
                headers=HeaderConstraints(**kwargs),
                actions="SUCCESS",
            ).answer(snapshot=snap).frame()
            return not df.empty

        for src in zones:
            for dst in zones:
                if src["nombre"] == dst["nombre"]:
                    continue
                if src["nombre"] not in locations:
                    cells.append({"origen": src["nombre"], "destino": dst["nombre"], "estado": "DESCONOCIDO",
                                  "detalle": f"Batfish no modela la interfaz {src['interfaz']}."})
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

    # ------------------------------------------------------------------
    # Fase 2: Reachability simbólica, testFilters y modelo de red
    # ------------------------------------------------------------------
    MAX_REACHABILITY_QUERIES = 40

    def symbolic_reachability(
        self,
        config_text: str,
        filename: str,
        start_interface: str,
        start_ip: Optional[str],
        destinations: List[Dict[str, str]],
        src_ips: Optional[str] = None,
        protocol: Optional[str] = None,
        port_specs: Optional[List[str]] = None,
        network_name: str = "cisco_auditor_web",
    ) -> Dict[str, Any]:
        """
        Reachability simbólica: para cada combinación (destino × servicio) ejecuta
        bf.q.reachability(actions=SUCCESS) sobre el espacio COMPLETO de paquetes que cumplen las
        restricciones. Un resultado vacío es una prueba formal de que ningún flujo llega; uno no
        vacío trae un flujo testigo con su traza y la ACL que lo permitió.
        `destinations`: [{"etiqueta": str, "ips": "cidr|ip"}]; `port_specs`: ["22", "80-90", ...].
        """
        from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints

        snap = "snap_reachability"
        self._load_snapshot(config_text, filename, snap, network_name)
        _, location = self._start_location(snap, start_interface, start_ip)
        proto = (protocol or "").upper() or None
        services: List[Optional[str]] = list(port_specs) if (port_specs and proto in {"TCP", "UDP"}) else [None]

        pairs = [(d, p) for d in destinations for p in services]
        if len(pairs) > self.MAX_REACHABILITY_QUERIES:
            raise ValueError(f"Demasiadas combinaciones ({len(pairs)}); máximo {self.MAX_REACHABILITY_QUERIES}.")

        resultados: List[Dict[str, Any]] = []
        for dest, port in pairs:
            kwargs: Dict[str, Any] = {"dstIps": dest["ips"]}
            if src_ips:
                kwargs["srcIps"] = src_ips
            if proto:
                kwargs["ipProtocols"] = [proto]
            if port:
                kwargs["dstPorts"] = port
            df = self.session.q.reachability(
                pathConstraints=PathConstraints(startLocation=location),
                headers=HeaderConstraints(**kwargs),
                actions="SUCCESS",
            ).answer(snapshot=snap).frame()
            row: Dict[str, Any] = {
                "destino": dest["etiqueta"], "destino_ips": dest["ips"],
                "protocolo": proto or "CUALQUIERA", "puertos": port or ("todos" if proto in {"TCP", "UDP", None} else "-"),
                "alcanzable": not df.empty, "flujo": None, "disposicion": None, "filtro_decisivo": None,
            }
            if not df.empty:
                first = df.iloc[0]
                row["flujo"] = self._flow_info(first["Flow"])
                traces = first.get("Traces") or []
                if traces:
                    row["disposicion"] = str(traces[0].disposition)
                    row["filtro_decisivo"] = self._decisive_filter(traces[0])[1]
            resultados.append(row)
        return {
            "origen": location, "total_consultas": len(resultados),
            "alcanzables": sum(1 for r in resultados if r["alcanzable"]), "resultados": resultados,
        }

    def test_filter(
        self,
        config_text: str,
        filename: str,
        acl: str,
        src_ip: str,
        dst_ip: str,
        protocol: str = "TCP",
        dst_port: Optional[int] = None,
        network_name: str = "cisco_auditor_web",
    ) -> Dict[str, Any]:
        """
        bf.q.testFilters(): evalúa un paquete hipotético contra UNA ACL aislada (sin enrutamiento
        ni interfaces) y devuelve la acción y la línea exacta que coincide.
        """
        from pybatfish.datamodel.flow import HeaderConstraints

        snap = "snap_testfilter"
        self._load_snapshot(config_text, filename, snap, network_name)
        proto = protocol.upper()
        kwargs: Dict[str, Any] = {"srcIps": src_ip, "dstIps": dst_ip, "ipProtocols": [proto]}
        if proto in {"TCP", "UDP"}:
            kwargs["srcPorts"] = "49152"
            if dst_port is not None:
                kwargs["dstPorts"] = str(dst_port)
        df = self.session.q.testFilters(filters=acl, headers=HeaderConstraints(**kwargs)).answer(snapshot=snap).frame()
        if df.empty:
            raise ValueError(f"Batfish no encontró la ACL '{acl}' en el snapshot.")
        row = df.iloc[0]
        action = str(row.get("Action", "")).upper()
        return {
            "acl": str(row.get("Filter_Name", acl)), "nodo": str(row.get("Node", "")),
            "accion": action, "permitido": action == "PERMIT",
            "regla": self._rule_text(row.get("Line_Content")),
            "flujo": self._flow_info(row.get("Flow")) if row.get("Flow") is not None else None,
            "traza": str(row.get("Trace", ""))[:600],
        }

    def network_model(
        self,
        config_text: str,
        filename: str,
        network_name: str = "cisco_auditor_web",
    ) -> Dict[str, Any]:
        """
        Modelo de red tal como lo entiende Batfish: tabla de enrutamiento (bf.q.routes()),
        adyacencias L3 (bf.q.layer3Edges()) e inventario de interfaces (interfaceProperties).
        """
        snap = "snap_model"
        self._load_snapshot(config_text, filename, snap, network_name)
        routes_df = self.session.q.routes().answer(snapshot=snap).frame()
        rutas = [{
            "nodo": str(r.get("Node", "")), "vrf": str(r.get("VRF", "")), "red": str(r.get("Network", "")),
            "next_hop": str(r.get("Next_Hop", "") or r.get("Next_Hop_IP", "")),
            "protocolo": str(r.get("Protocol", "")),
            "admin_distance": None if r.get("Admin_Distance") is None else int(r.get("Admin_Distance")),
            "metrica": None if r.get("Metric") is None else int(r.get("Metric")),
        } for _, r in routes_df.iterrows()]

        edges_df = self.session.q.layer3Edges().answer(snapshot=snap).frame()
        enlaces = []
        for _, e in edges_df.iterrows():
            ln, li = self._split_interface(e.get("Interface"))
            rn, ri = self._split_interface(e.get("Remote_Interface"))
            enlaces.append({"nodo": ln, "interfaz": li, "ips": [str(x) for x in (e.get("IPs") or [])],
                            "nodo_remoto": rn, "interfaz_remota": ri,
                            "ips_remotas": [str(x) for x in (e.get("Remote_IPs") or [])]})

        return {
            "rutas": rutas, "enlaces_l3": enlaces, "interfaces": self._interface_index(snap),
            "total_rutas": len(rutas), "total_enlaces": len(enlaces),
        }
