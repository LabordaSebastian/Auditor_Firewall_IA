import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.config import REPORTS_DIR, GEMINI_API_KEY, GEMINI_MODEL, BATFISH_HOST, BATFISH_PORT
from src.sanitizer import ConfigSanitizer
from src.topology_extractor import CiscoTopologyExtractor
from src.batfish_analyzer import BatfishAnalyzer, BatfishUnavailableError
from src.gemini_advisor import GeminiFirewallAdvisor
from src.report_builder import ReportBuilder

app = typer.Typer(
    name="cisco-ai-firewall-auditor",
    help="Auditor de Firewalls y Routers Cisco combinando Batfish con Inteligencia Artificial Semántica (Gemini).",
    add_completion=False,
)
console = Console()


@app.command()
def check_env():
    """Verifica el estado del entorno: Python, Docker, Batfish y Gemini API."""
    console.print(Panel.fit("[bold blue]Diagnóstico del Entorno del Sistema[/bold blue]", border_style="blue"))

    # 1. API Key
    if GEMINI_API_KEY:
        masked_key = f"{GEMINI_API_KEY[:6]}...{GEMINI_API_KEY[-4:]}"
        console.print(f"✅ [bold green]GEMINI_API_KEY:[/bold green] Configurada ({masked_key})")
        console.print(f"   Modelo objetivo: [cyan]{GEMINI_MODEL}[/cyan]")
    else:
        console.print("❌ [bold red]GEMINI_API_KEY:[/bold red] No encontrada en .env")

    # 2. Batfish
    try:
        analyzer = BatfishAnalyzer(host=BATFISH_HOST, port=BATFISH_PORT)
        analyzer.connect()
        console.print(f"✅ [bold green]Batfish:[/bold green] Conectado exitosamente en {BATFISH_HOST}:{BATFISH_PORT}")
    except Exception as e:
        console.print(f"❌ [bold red]Batfish:[/bold red] No disponible ({e})")
        console.print("   [bold yellow]Batfish es un requisito obligatorio del sistema.[/bold yellow]")
        console.print("   [dim]Inicia el servicio ejecutando:[/dim] [cyan]docker compose up -d[/cyan]")


@app.command()
def sanitize_preview(
    config_path: Path = typer.Argument(..., help="Ruta al archivo de configuración Cisco (.cfg)"),
):
    """Muestra una previsualización de qué IPs públicas y secretos serían enmascarados."""
    if not config_path.exists():
        console.print(f"[bold red]Error:[/bold red] El archivo {config_path} no existe.")
        raise typer.Exit(code=1)

    raw_text = config_path.read_text(encoding="utf-8")
    sanitizer = ConfigSanitizer()
    sanitized_text, lookup_map = sanitizer.sanitize(raw_text, source_filename=config_path.name)

    table = Table(title="Resumen de Sanitización (RFC 5737 y Secretos)")
    table.add_column("Tipo", style="cyan")
    table.add_column("Original / Real", style="red")
    table.add_column("Enmascarado / Sintético", style="green")

    for synth, real in lookup_map.get("ip_mappings", {}).items():
        table.add_row("IP Pública WAN", real, synth)

    for token, secret in lookup_map.get("secret_mappings", {}).items():
        table.add_row("Secreto Cisco", f"{secret[:4]}***" if len(secret) > 4 else "***", token)

    console.print(table)


@app.command()
def audit(
    config_path: Path = typer.Argument(..., help="Ruta al archivo de configuración Cisco (.cfg)"),
    sanitize: bool = typer.Option(True, "--sanitize/--no-sanitize", help="Activar sanitización reversible (Recomendado)"),
    output_dir: Path = typer.Option(REPORTS_DIR, "--output", "-o", help="Directorio para los reportes generados"),
):
    """
    Ejecuta la auditoría integral completa:
    Sanitización ➔ Topología ➔ Batfish Formal ➔ Gemini Cognitivo ➔ Reportes y Scripts CLI.
    """
    console.print(
        Panel.fit(
            f"[bold cyan]Cisco AI Firewall Auditor & Change Impact Advisor[/bold cyan]\n"
            f"[dim]Analizando:[/dim] [yellow]{config_path.name}[/yellow]",
            border_style="cyan",
        )
    )

    if not config_path.exists():
        console.print(f"[bold red]Error:[/bold red] El archivo {config_path} no existe.")
        raise typer.Exit(code=1)

    raw_config = config_path.read_text(encoding="utf-8")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Etapa 1: Sanitización
        task1 = progress.add_task("[cyan]Etapa 1: Sanitización reversible...", total=None)
        sanitizer = ConfigSanitizer()
        if sanitize:
            sanitized_config, lookup_map = sanitizer.sanitize(raw_config, source_filename=config_path.name)
            progress.update(
                task1,
                description=(
                    f"[green]Etapa 1: Sanitización lista.[/green] "
                    f"({lookup_map['metadata']['total_public_ips_masked']} IPs públicas enmascaradas, "
                    f"{lookup_map['metadata']['total_secrets_masked']} secretos protegidos)"
                ),
            )
        else:
            sanitized_config = raw_config
            lookup_map = {"ip_mappings": {}, "secret_mappings": {}}
            progress.update(task1, description="[yellow]Etapa 1: Sanitización desactivada por el usuario.[/yellow]")

        # Etapa 2: Extracción de Topología
        task2 = progress.add_task("[cyan]Etapa 2: Extrayendo contexto y topología Cisco...", total=None)
        topo_extractor = CiscoTopologyExtractor(sanitized_config)
        topology = topo_extractor.extract_topology()
        progress.update(
            task2,
            description=(
                f"[green]Etapa 2: Topología analizada.[/green] "
                f"Dispositivo: [bold]{topology.hostname}[/bold] ({topology.dialecto}). "
                f"{len(topology.interfaces)} interfaces, {len(topology.acls_activas)} ACLs activas, "
                f"{len(topology.acls_huerfanas)} ACLs huérfanas."
            ),
        )

        # Etapa 3: Verificación Formal Matemática con Batfish (Obligatorio)
        task3 = progress.add_task("[cyan]Etapa 3: Verificación formal matemática con Batfish...", total=None)
        try:
            batfish = BatfishAnalyzer(host=BATFISH_HOST, port=BATFISH_PORT)
            batfish.connect()
            math_findings = batfish.analyze_snapshot(sanitized_config, config_filename=config_path.name)
            progress.update(
                task3,
                description=f"[green]Etapa 3: Verificación formal Batfish completada.[/green] ({len(math_findings)} anomalías matemáticas confirmadas)",
            )
        except Exception as e:
            progress.stop()
            console.print("\n")
            console.print(
                Panel(
                    f"[bold red]Error Crítico en Etapa 3 (Batfish Requerido):[/bold red]\n\n"
                    f"No se pudo conectar a Batfish en [cyan]{BATFISH_HOST}:{BATFISH_PORT}[/cyan].\n"
                    f"Detalle: [dim]{e}[/dim]\n\n"
                    f"Para garantizar un análisis matemático formal con rigor de grado telecomunicaciones (sin alucinaciones),\n"
                    f"el servicio de Batfish es un componente obligatorio del sistema.\n\n"
                    f"👉 [bold green]Inicia el contenedor ejecutando:[/bold green] [cyan]docker compose up -d[/cyan]",
                    title="⚠️ Falla de Verificación Formal",
                    border_style="red",
                )
            )
            raise typer.Exit(code=1)

        # Etapa 4: Razonamiento Cognitivo con Gemini y Skill
        task4 = progress.add_task(f"[cyan]Etapa 4: Razonamiento semántico con Gemini ({GEMINI_MODEL})...", total=None)
        advisor = GeminiFirewallAdvisor()
        report = advisor.analyze(sanitized_config, topology, math_findings)
        progress.update(
            task4,
            description=f"[green]Etapa 4: Evaluación de Gemini completada.[/green] ({len(report.hallazgos)} hallazgos normativos y técnicos)",
        )

        # Etapa 5: De-sanitización y Generación de Entregables
        task5 = progress.add_task("[cyan]Etapa 5: Generando reportes y scripts CLI...", total=None)
        builder = ReportBuilder(output_dir=output_dir)
        base_name = config_path.stem
        paths = builder.generate_all(report, topology, lookup_map, base_name=base_name)
        progress.update(task5, description="[green]Etapa 5: Entregables generados con éxito.[/green]")

    # Mostrar tabla resumen en terminal
    console.print("\n")
    summary_table = Table(title=f"Resultados de la Auditoría - {report.resumen.hostname_detectado}")
    summary_table.add_column("ID", style="dim")
    summary_table.add_column("Componente", style="cyan")
    summary_table.add_column("Severidad", style="bold")
    summary_table.add_column("Problema", style="white")
    summary_table.add_column("Impacto Operativo (Blast Radius)", style="yellow")

    for h in report.hallazgos:
        color = "red" if h.severidad.value in {"CRITICA", "ALTA"} else "yellow" if h.severidad.value == "MEDIA" else "green"
        summary_table.add_row(
            h.id_hallazgo,
            h.acl_o_componente,
            f"[{color}]{h.severidad.value}[/{color}]",
            h.categoria_problema,
            h.nivel_impacto_operativo.value,
        )

    console.print(summary_table)

    # Postura de seguridad
    score_cur = report.resumen.score_seguridad_actual
    score_proj = report.resumen.score_seguridad_proyectado
    console.print(
        Panel(
            f"[bold]Puntaje de Postura de Seguridad Actual:[/bold] [bold red]{score_cur}/100[/bold red]\n"
            f"[bold]Puntaje Proyectado con Remediación:[/bold] [bold green]{score_proj}/100[/bold green]\n\n"
            f"[dim]Entregables listos en:[/dim]\n"
            f"  📄 [bold]Reporte Técnico/Ejecutivo:[/bold] [cyan]{paths['markdown']}[/cyan]\n"
            f"  🛠️ [bold]Script de Remediación:[/bold]      [cyan]{paths['remediation_cli']}[/cyan]\n"
            f"  ⏪ [bold]Script de Rollback:[/bold]         [cyan]{paths['rollback_cli']}[/cyan]\n"
            f"  📊 [bold]Datos en JSON:[/bold]              [cyan]{paths['json']}[/cyan]",
            title="🎯 Auditoría Finalizada",
            border_style="green",
        )
    )


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interfaz de escucha (por defecto solo local)"),
    port: int = typer.Option(8000, "--port", help="Puerto del dashboard"),
    open_browser: bool = typer.Option(False, "--open-browser", help="Abrir el navegador automáticamente"),
):
    """Lanza el dashboard web interactivo (grafo topológico, simulador Batfish, PDF)."""
    import threading
    import webbrowser

    import uvicorn

    url = f"http://{host}:{port}"
    console.print(
        Panel.fit(
            f"[bold cyan]Dashboard Cisco AI Firewall Auditor[/bold cyan]\n"
            f"[dim]URL:[/dim] [bold green]{url}[/bold green]\n"
            f"[dim]Batfish:[/dim] {BATFISH_HOST}:{BATFISH_PORT}   [dim]Modelo:[/dim] {GEMINI_MODEL}\n"
            f"[dim]Detener con Ctrl+C[/dim]",
            border_style="cyan",
        )
    )
    if host not in {"127.0.0.1", "localhost"}:
        console.print("[bold yellow]⚠️ El dashboard no tiene autenticación: no lo expongas fuera de redes de confianza.[/bold yellow]")
    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run("src.web.app:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()

