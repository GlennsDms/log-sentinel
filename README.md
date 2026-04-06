# log-sentinel

`log-sentinel` is a command-line tool that parses SSH authentication logs, detects anomalous behavior using machine learning, and generates a plain-English incident summary. No dashboards. No subscriptions. No sending your logs to external servers.

Built as a learning project at the intersection of security operations and applied ML.

---

## The problem it solves

An auth log has hundreds of lines. Distinguishing a slow brute force from legitimate failed traffic is hard at a glance. Static rules fall short when an attacker varies the pace or rotates usernames.

This project combines two approaches:

- An **autoencoder** trained on the behavioral features of every IP in the log. IPs whose behavior is hard to reconstruct get high anomaly scores.
- **Deterministic rules** running in parallel to catch cases the model might miss: brute force thresholds, invalid user counts, etc.

At the end, a local LLM turns the results into a human-readable summary.

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) running locally

```bash
ollama pull llama3.2:3b
```

---

## Setup

```bash
git clone https://github.com/<your-username>/log-sentinel.git
cd log-sentinel

uv venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

cp .env.example .env
```

---

## Usage

```bash
# basic analysis
log-sentinel path/to/auth.log

# adjust model sensitivity (default: 60)
log-sentinel path/to/auth.log --threshold 75

# enrich flagged IPs against AbuseIPDB
log-sentinel path/to/auth.log --enrich

# export report to markdown
log-sentinel path/to/auth.log --output report.md

# combined
log-sentinel path/to/auth.log --threshold 70 --enrich --output reports/2026-04-05.md
```

### About `--threshold`

Controls the percentile cutoff for the anomaly model. A value of `60` flags the top 40% of IPs by reconstruction error. Higher values are more conservative (fewer false positives), lower values are more aggressive.

---

## Example output

```
              Detected anomalies
╭────────────────┬────────┬────────┬─────────────────╮
│ Source IP      │ Score  │ Failed │ Invalid users   │
├────────────────┼────────┼────────┼─────────────────┤
│ 185.220.101.47 │ 100.0% │ 18     │ 7               │
│ 92.118.160.11  │ 66.9%  │ 4      │ 0               │
│ 45.141.84.200  │ 39.0%  │ 5      │ 3               │
╰────────────────┴────────┴────────┴─────────────────╯

Summary:
Three external IPs were flagged showing clear brute-force SSH patterns.
185.220.101.47 is the most aggressive, with 18 failed attempts across
multiple sessions targeting root and common usernames. Risk level: High.
```

---

## How anomaly detection works

The autoencoder learns what normal behavior looks like by training on the features of every IP in the log. IPs that are hard to reconstruct are statistically rare within the analyzed file.

Scores are normalized between 0 and 1 using min-max scaling across all IPs in the log, so the score always reflects relative anomalousness within that specific file.

Internal (RFC 1918) IPs are handled separately: the model score alone is never enough to flag them. They only appear in results if deterministic rules fire explicitly.

---

## Tests

```bash
pytest tests/ -v
```

---

## Tech stack

| Tool | Role |
|---|---|
| `pandas` | Log parsing and feature aggregation |
| `PyTorch` | Autoencoder for unsupervised anomaly detection |
| `scikit-learn` | Feature scaling |
| `Ollama` + `llama3.2:3b` | Local LLM for incident summarization |
| `typer` + `rich` | CLI and terminal output |
| `requests` | AbuseIPDB integration |

---

## Project structure

```
src/log_sentinel/
├── cli.py          # entrypoint and report export
├── parser.py       # log parsing and normalization
├── analyzer.py     # anomaly detection + LLM summarization
└── integrations.py # AbuseIPDB integration
```

---

## Known limitations

- The model trains from scratch on each run. Very short logs (fewer than 10 unique IPs) reduce reliability.
- Only supports `auth.log`-style SSH logs currently.
- No persistence between runs: each analysis is independent.

---

## Roadmap

- **Additional log formats** — Apache/Nginx, Windows Event Logs, firewall logs
- **Real-time mode** — tail a live log file and alert on anomalies as they happen
- **Pre-trained model** — using the [Loghub SSH dataset](https://github.com/logpai/loghub) as a baseline before seeing the target log
- **Model persistence** — save and load weights for incremental fine-tuning
- **Cross-session tracking** — correlate anomalies across multiple log files to detect slow attacks that stay under per-session thresholds
- **JSON export** — for piping results into SIEMs or other downstream tools