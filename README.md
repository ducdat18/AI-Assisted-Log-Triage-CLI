# loglens 🔍

**AI-assisted log triage for operational and incident diagnostics.**

`loglens` ingests raw application/server logs, automatically detects errors and
anomalies, clusters them by similarity, and uses an LLM to produce a
human-readable incident report — one-paragraph summary, most likely root cause,
affected components, and concrete remediation steps. The goal is to cut the
manual effort engineers spend digging through logs during an incident.

The LLM backend is **pluggable**. It ships with a fully-local, free default
(Ollama) and an optional hosted free-tier backend (Gemini). Nothing is sent
anywhere unless you choose a remote provider — and even then a `--redact` flag
scrubs PII/secrets first.

---

## What it does

- **Auto-detects** plaintext *and* JSON-lines log formats.
- **Clusters** repetitive errors into distinct failure signatures (so 5,000
  near-identical timeouts become one ranked cluster).
- **Ranks** clusters by a blend of severity and frequency, so the most
  important problems surface first.
- **Triages** the top clusters with an LLM and generates:
  1. a one-paragraph incident summary,
  2. the most likely root cause,
  3. affected components,
  4. concrete, prioritized remediation steps.
- **Outputs** a clean Markdown report *and* a colored terminal summary.
- **Watches** a live log file and surfaces anomalies in near-real-time.
- **Redacts** emails, IPs, tokens, JWTs, and API keys before anything leaves
  your machine (`--redact`).
- **Token-aware** hierarchical summarization so large logs never overflow the
  model's context window.
- **Ships to Grafana Loki** (`loglens ship`) with per-line severity and error-cluster
  labels, plus a one-command Grafana dashboard for visual triage.

---

## Install

Requires **Python 3.11+**.

```bash
git clone <repo-url> loglens
cd loglens
pip install -e .
# or, with test dependencies:
pip install -e ".[dev]"
```

This installs the `loglens` command.

### Set up the default backend (Ollama — free & local)

`loglens` defaults to [Ollama](https://ollama.com), which runs models locally
with no API key and no data leaving your machine.

1. Install Ollama: download from <https://ollama.com/download> (macOS, Windows,
   Linux).
2. Start the server (it usually runs automatically after install):
   ```bash
   ollama serve
   ```
3. Pull the default model:
   ```bash
   ollama pull llama3.2
   ```

That's it — `loglens analyze` now works offline.

### Optional: Gemini backend (hosted free tier)

1. Get a free API key at <https://aistudio.google.com/apikey>.
2. Export it:
   ```bash
   export GEMINI_API_KEY="your-key-here"      # Windows PowerShell: $env:GEMINI_API_KEY="..."
   ```
3. Select it per-run with `--provider gemini`, or set a default:
   ```bash
   export LOGLENS_PROVIDER=gemini
   ```

> ⚠️ Gemini sends log content to Google. Pair it with `--redact` when logs may
> contain sensitive data.

---

## Usage

### Analyze a log file

```bash
loglens analyze sample_logs/game_server.log
```

Force a provider / model, scrub secrets, and save the Markdown report:

```bash
loglens analyze sample_logs/api_server.jsonl \
  --provider ollama --model llama3.2 \
  --redact \
  --top 6 \
  --output incident.report.md
```

Key flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--provider, -p` | `ollama` | LLM backend (`ollama`, `gemini`). Also `$LOGLENS_PROVIDER`. |
| `--model, -m` | provider default | Override the model name. |
| `--format, -f` | auto | Force `text` or `json`. |
| `--top, -n` | `8` | How many top clusters to send to the LLM. |
| `--min-level, -l` | `WARNING` | Minimum severity to include. |
| `--redact` | off | Strip PII/secrets before any LLM call. |
| `--output, -o` | — | Write the Markdown report to a file. |
| `--token-budget` | `6000` | Context budget; triggers hierarchical summarization. |

### Sample output

Running against the bundled game-server log prints a ranked cluster table
followed by the colored report panels:

```
Parsed 31 lines · 24 at/above WARNING · 7 clusters shown

                              Top error clusters
┏━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity  ┃ Count ┃ Signature                                               ┃
┡━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ERROR     │     8 │ [persistence] Failed to flush player state uid=<NUM>: …  │
│ ERROR     │     7 │ [db] Connection to <IP> failed: timeout after <NUM>      │
│ CRITICAL  │     2 │ [persistence] Write-ahead log backlog <NUM> entries, …   │
│ CRITICAL  │     1 │ [worldsim] Shard <NUM> unresponsive for <NUM>, …         │
│ WARNING   │     3 │ [worldsim] Tick budget exceeded: <NUM> (target <NUM>) …  │
└───────────┴───────┴─────────────────────────────────────────────────────────┘

──────────────────────────── Incident Report ────────────────────────────
╭───────────────────────────── Incident Summary ─────────────────────────────╮
│ The primary Postgres node at 10.0.4.21 stopped accepting connections,       │
│ exhausting the persistence connection pool. Player-state flushes failed en  │
│ masse, the write-ahead log backed up to its 50k cap, and world shard 7      │
│ went unresponsive and failed over. Service recovered after an operator      │
│ promoted replica 10.0.4.30.                                                 │
╰─────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────── Most Likely Root Cause ─────────────────────────╮
│ Loss of the primary database (10.0.4.21) caused connection-pool exhaustion  │
│ that cascaded into persistence and world-simulation failures.               │
╰─────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────── Affected Components ───────────────────────────╮
│ - db (primary 10.0.4.21)                                                    │
│ - persistence / write-ahead log                                             │
│ - worldsim (shard 7)                                                        │
│ - matchmaker (queue backpressure)                                           │
╰─────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────── Remediation Steps ────────────────────────────╮
│ 1. Confirm replica 10.0.4.30 is now primary and healthy.                    │
│ 2. Raise the persistence DB pool size and add a circuit breaker.            │
│ 3. Add health-check-driven automatic failover for the DB primary.           │
│ 4. Alert on WAL backlog before it reaches the 50k drop threshold.           │
╰─────────────────────────────────────────────────────────────────────────────╯
```

*(Exact wording varies by model; structure is fixed.)*

### Watch a live log

```bash
loglens watch /var/log/app.log --min-level ERROR --redact
```

Tails the file from its end and prints each new error/warning as it arrives,
marking the first occurrence of each distinct signature with `NEW`. Stop with
`Ctrl+C`.

### Visualize in Grafana (Loki)

`loglens ship` pushes parsed log entries to [Grafana Loki](https://grafana.com/oss/loki/),
labelling each line with its **severity** (`level`) and a stable **cluster**
signature. The cluster label is loglens's value-add over a plain shipper: in
Grafana you can collapse thousands of near-identical errors into one series.

One-command demo stack (Grafana + Loki, pre-provisioned):

```bash
docker compose -f deploy/docker-compose.yml up -d        # starts Loki :3100 + Grafana :3000
loglens ship sample_logs/game_server.log
loglens ship sample_logs/api_server.jsonl --redact
# open http://localhost:3000  → dashboard "loglens — incident triage" is pre-loaded
```

Useful LogQL queries (Explore → Loki):

```logql
# volume by severity over time
sum by (level) (count_over_time({job="loglens"} [$__auto]))

# top error clusters (collapse near-identical errors by signature)
topk(10, sum by (cluster, level) (count_over_time({job="loglens", level=~"error|critical"} [$__range])))

# just the error/critical lines
{job="loglens", level=~"error|critical"}
```

Ship flags: `--loki-url/-u` (default `http://localhost:3100`), `--source/-s`
(label, defaults to file name), `--min-level/-l` (ship only at/above a
severity), `--redact` (scrub PII/secrets before shipping), `--format/-f`.

> The bundled Grafana uses anonymous admin access and Loki accepts old/out-of-order
> samples — both are **demo conveniences**, not production settings.

---

## Architecture

```
        ┌──────────┐   ┌────────────┐   ┌──────────────┐   ┌──────────┐
 logs → │  parser  │ → │ clustering │ → │  summarize    │ → │  report  │ → Markdown
        │ (detect, │   │ (normalize,│   │ (token-aware, │   │ (prompt, │    + terminal
        │  text/   │   │  rank by   │   │  hierarchical)│   │  parse,  │
        │  json)   │   │  severity) │   │      │        │   │  render) │
        └──────────┘   └────────────┘   └──────┼────────┘   └────┬─────┘
                                               │                 │
                            ┌──────────────────┴─────────────────┘
                            ▼
                      ┌───────────┐     redact (optional, pre-flight PII/secret scrub)
                      │   llm/    │
                      │  factory  │──► LLMProvider (abstract)
                      └───────────┘        ├── OllamaProvider  (default, local)
                                           └── GeminiProvider  (hosted free tier)
```

Module layout (`src/loglens/`):

| Module | Responsibility |
|--------|----------------|
| `parser.py` | Format auto-detection; plaintext & JSON-lines parsing into immutable `LogEntry` objects. |
| `clustering.py` | Normalize messages to templates, group into `Cluster`s, rank by severity × frequency. |
| `redact.py` | Regex-based PII/secret scrubbing (emails, IPs, JWTs, tokens, API keys). |
| `summarize.py` | Cheap token estimation + token-aware hierarchical (map-reduce) summarization. |
| `report.py` | Builds the triage prompt, parses the structured response, renders Markdown + Rich panels. |
| `llm/base.py` | The `LLMProvider` abstract interface + `LLMError`. |
| `llm/providers/` | `OllamaProvider`, `GeminiProvider`. |
| `llm/factory.py` | Resolves provider from `--provider` flag → `LOGLENS_PROVIDER` → default. |
| `exporters/loki.py` | Pushes severity- and cluster-labelled entries to Grafana Loki. |
| `cli.py` | Typer CLI: `analyze`, `watch`, and `ship`. |

### The LLM backend is pluggable

The entire pipeline depends only on the abstract `LLMProvider` interface
(`generate(prompt, system) -> str`). Adding a new backend is two steps:

1. Subclass `LLMProvider` in `src/loglens/llm/providers/`.
2. Register it in `llm/factory.py`'s `_REGISTRY`.

No analysis code changes. Provider selection precedence is
**`--provider` flag → `LOGLENS_PROVIDER` env → `ollama` (default)**.

---

## Development & tests

```bash
pip install -e ".[dev]"
pytest                # run the suite
pytest --cov          # with coverage
```

Unit tests cover the parser, clustering/ranking, redaction, and report
generation. The LLM is mocked in tests, so the suite runs fully offline and
deterministically with no model or network required.

---

## Sample logs

`sample_logs/` contains two realistic incident traces for a quick demo:

- `game_server.log` — plaintext; a database-primary outage cascading into
  persistence and world-simulation failures.
- `api_server.jsonl` — JSON-lines; a payments database outage cascading into
  checkout `502`s, with circuit-breaker and cached-fallback behavior.

---

## License

MIT.
