import typer
from rich.console import Console
from rich.table import Table
from rich import box
from pathlib import Path
from datetime import datetime

from log_sentinel.parser import parse_auth_log, normalize
from log_sentinel.analyzer import detect_anomalies, summarize_incidents
from log_sentinel.integrations import check_ip

app = typer.Typer()
console = Console()


def _get_abuse_score(ip: str) -> str:
    try:
        data = check_ip(ip)
        score = data.get("abuseConfidenceScore", None)
        return str(score) if score is not None else "-"
    except Exception:
        return "-"


def _export_markdown(anomalies, df, summary: str, log_path: Path, output_path: Path, enrich: bool):
    lines = [
        "# Log Sentinel — Incident Report",
        "",
        f"**Log file:** `{log_path}`  ",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Flagged IPs:** {anomalies['source_ip'].nunique()}",
        "",
        "## Anomalies",
        "",
    ]

    headers = ["IP", "Score", "Failed logins", "Invalid users"]
    if enrich:
        headers.append("Abuse score")
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for _, row in anomalies.iterrows():
        ip = str(row["source_ip"])
        ip_rows = df[df["source_ip"] == ip]
        score = f"{float(row['anomaly_score']):.1%}"
        failed = str((ip_rows["event_type"] == "failed_login").sum())
        invalid = str((ip_rows["event_type"] == "invalid_user").sum())
        cols = [ip, score, failed, invalid]
        if enrich:
            cols.append(_get_abuse_score(ip))
        lines.append("| " + " | ".join(cols) + " |")

    lines += ["", "## Summary", "", summary, ""]
    output_path.write_text("\n".join(lines), encoding="utf-8")


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
    table.add_column("Fallos", style="yellow")
    table.add_column("Usuarios inválidos", style="yellow")
    if enrich:
        table.add_column("Abuse score", style="cyan")

    for _, row in anomalies.iterrows():
        ip = str(row["source_ip"])
        ip_rows = df[df["source_ip"] == ip]
        failed = str((ip_rows["event_type"] == "failed_login").sum())
        invalid = str((ip_rows["event_type"] == "invalid_user").sum())
        score = f"{float(row['anomaly_score']):.1%}"
        cols = [ip, score, failed, invalid]
        if enrich:
            cols.append(_get_abuse_score(ip))
        table.add_row(*cols)

    console.print(table)

    # Paso 5 - Resumen
    console.print("\n[bold green]Resumen del incidente:[/bold green]")
    console.print(summarize_incidents(df))

if __name__ == "__main__":
    app()