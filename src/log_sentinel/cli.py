import typer
from rich.console import Console
from rich.table import Table
from rich import box
from pathlib import Path

from log_sentinel.parser import parse_auth_log, normalize
from log_sentinel.analyzer import detect_anomalies, summarize_incidents

app = typer.Typer()
console = Console()

@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Ruta al archivo de log a analizar"),
):
    # Paso 1 - Parsear
    console.print("[bold cyan]Parseando log...[/bold cyan]")
    df = parse_auth_log(log_path)

    if df.empty:
        console.print("[bold red]No se encontraron eventos en el log.[/bold red]")
        raise typer.Exit()

    # Paso 2 - Normalizar
    console.print("[bold cyan]Normalizando...[/bold cyan]")
    df = normalize(df)

    # Paso 3 - Detectar anomalías
    console.print("[bold cyan]Detectando anomalías...[/bold cyan]")
    df = detect_anomalies(df)

    # Paso 4 - Tabla de anomalías
    anomalies = df[df["is_anomaly"] == True]

    table = Table(title="Anomalías detectadas", box=box.ROUNDED)
    table.add_column("IP origen", style="red")
    table.add_column("Tipo de evento", style="yellow")
    table.add_column("Score", style="magenta")
    table.add_column("Timestamp", style="white")

    for _, row in anomalies.iterrows():
        table.add_row(
            str(row["source_ip"]),
            str(row["event_type"]),
            str(row["anomaly_score"]),
            str(row["timestamp"]),
        )

    console.print(table)

    # Paso 5 - Resumen
    console.print("\n[bold green]Resumen del incidente:[/bold green]")
    console.print(summarize_incidents(df))

if __name__ == "__main__":
    app()