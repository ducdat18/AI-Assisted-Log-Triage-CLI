# loglens 🔍

**AI-assisted log triage for operational and incident diagnostics.**

`loglens` ingests raw application/server logs and runs a **deterministic
analytics engine** over them: it clusters errors by similarity, detects *when*
an incident began (statistical change-point on the error rate), reconstructs the
**cause → effect cascade** between components from timing alone, and flags
bursty failure signatures. An LLM is then *optional* — it narrates over the
computed evidence rather than guessing it. With `--no-llm` the tool produces a
full incident report with no model at all.

This is the key design point: **the intelligence is computed, not prompted.**
The onset time, the trigger component, and the cascade chain are real numbers
derived from timestamps — not an LLM's best guess. The model only turns those
facts into prose.

The LLM backend (when used) is **pluggable**: a fully-local, free default
(Ollama) and an optional hosted free-tier backend (Gemini). Nothing is sent
anywhere unless you choose a remote provider — and even then `--redact` scrubs
PII/secrets first.

---

## What it does

- **Auto-detects** plaintext *and* JSON-lines log formats.
- **Clusters** repetitive errors into distinct failure signatures (so 5,000
  near-identical timeouts become one ranked cluster) — via hand-tuned regex
  templates *or* the [Drain](#drain-template-mining) parse-tree miner (`--drain`).
- **Ranks** clusters by a blend of severity and frequency, so the most
  important problems surface first.
- **Detects incident onset** with a statistical change-point: error counts are
  bucketed over time and scored against an adaptive EWMA baseline (z-score), so
  loglens tells you *when* things broke, not just *that* they did.
- **Reconstructs the cascade**: temporal co-occurrence (Jaccard overlap) between
  clusters infers which failure *triggered* which, building a cause → effect
  chain and naming the likely trigger component — all from timestamps, no LLM.
- **Flags bursts**: clusters whose events pile into a short window (a cascading
  fault) are separated from steady background noise.
- **Runs offline with `--no-llm`**: a complete, reproducible incident report
  built purely from the analytics above — no model, no network.
- **Triages** the top clusters with an LLM (optional) and generates:
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
| `--no-llm` | off | Skip the LLM; build the report from deterministic analytics only. |
| `--drain` | off | Cluster with the Drain template miner instead of regex templates. |
| `--semantic` | off | Merge synonym-split clusters by embedding similarity (local TF-IDF default). |
| `--baseline` | — | A healthy log to learn the expected (seasonal) error rate from. |
| `--infer-severity` | off | Infer a level for unlabeled lines from their text. |

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

### The analytics engine (no LLM required)

Before any model is involved, loglens prints a **Temporal & Cascade Analysis**
computed entirely from timestamps and counts:

```
Onset 09:03:12 · baseline ~0.0 -> peak 4 errors/10s · 2 spike(s)

                    Incident timeline (by first appearance)
 Time     Lvl     Comp          Signature
 09:02:31 WARN    worldsim      Tick budget exceeded: <NUM> on shard <NUM>
 09:03:14 ERRO *  db            Connection to <IP> failed: timeout after <NUM>
 09:03:25 ERRO    persistence   Failed to flush player state uid=<NUM>: db pool…
 09:03:40 CRIT    persistence   Write-ahead log backlog <NUM> entries, dropping…
 09:03:55 CRIT    worldsim      Shard <NUM> unresponsive for <NUM>, failover

Inferred cascade
  db -> persistence (+11s, overlap=0.375)
  persistence -> worldsim (+30s, overlap=0.2)
  persistence -> matchmaker (+23s, overlap=0.2)
```

The `*` marks the inferred **trigger** (earliest severe root). Run with
`--no-llm` and the incident report itself is templated from these facts — fully
deterministic and reproducible. How each piece is computed:

- **Onset (change-point):** error counts are bucketed into adaptive time windows
  and scored one-step-ahead against an EWMA mean *and* EWMA variance (West's
  incremental algorithm). The first bucket exceeding the z-score threshold is the
  onset — a spike inflates neither its own baseline nor its variance.
- **Cascade:** each cluster's event times are projected onto a shared bucket grid;
  pairwise Jaccard overlap measures temporal correlation. A `cause → effect` link
  is proposed when two clusters overlap **and** the cause precedes the effect
  within a lag bound. The earliest severe cluster that is a cause-but-never-effect
  is surfaced as the trigger.
- **Bursts:** a two-pointer sweep finds each cluster's densest single window;
  clusters concentrating ≥60% of their events there are flagged as bursty.

#### Drain template mining

`--drain` swaps the hand-written regex templating for the **Drain** algorithm
(He et al., 2017) — a fixed-depth parse tree that learns templates structurally:
group by token count, descend on leading tokens, then merge similar messages,
collapsing varying positions to `<*>`. It adapts to message shapes the regex
rules don't cover, with no per-format rule maintenance.

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
        ┌──────────┐   ┌────────────┐   ┌──────────────────────────┐
 logs → │  parser  │ → │ clustering │ → │   incident (analytics)    │
        │ (detect, │   │ (regex OR  │   │  ┌─────────┐ ┌──────────┐ │
        │  text/   │   │  Drain;    │   │  │ anomaly │ │correlation│ │
        │  json)   │   │  rank by   │   │  │ onset,  │ │ cascade,  │ │
        └──────────┘   │  severity) │   │  │ bursts  │ │ trigger   │ │
                       └────────────┘   │  └─────────┘ └──────────┘ │
                                        └───────────┬──────────────┘
                                                    │  findings (deterministic)
                          ┌─────────────────────────┼───────────────┐
                          ▼                          ▼               │
                   ┌─────────────┐           ┌──────────────┐        │
                   │ --no-llm    │           │  report +    │ ◄──────┘ evidence
                   │ deterministic│          │  summarize   │   grounds the LLM
                   │ report      │           │  (LLM)       │
                   └─────────────┘           └──────┬───────┘
                                                    ▼
                                            ┌───────────┐  redact (optional scrub)
                                            │   llm/    │
                                            │  factory  │──► LLMProvider (abstract)
                                            └───────────┘    ├── OllamaProvider (local)
                                                             └── GeminiProvider (hosted)
```

Module layout (`src/loglens/`):

| Module | Responsibility |
|--------|----------------|
| `parser.py` | Format auto-detection; plaintext & JSON-lines parsing into immutable `LogEntry` objects (strips leading timestamp/level so templates stay clean). |
| `clustering.py` | Normalize messages to templates (regex or Drain), group into `Cluster`s, rank by severity × frequency, extract the emitting component. |
| `drain.py` | Online fixed-depth-tree (Drain) log template miner — structural clustering with no regex rules. |
| `anomaly.py` | Time-bucketing, EWMA z-score spike detection, incident-onset change-point, per-cluster burst detection. **No LLM.** |
| `correlation.py` | Temporal co-occurrence (Jaccard) between clusters → cause→effect cascade links + trigger inference. **No LLM.** |
| `incident.py` | Ties anomaly + correlation into `IncidentFindings`; builds the deterministic (`--no-llm`) report and the evidence block that grounds the LLM. |
| `redact.py` | Regex-based PII/secret scrubbing (emails, IPs, JWTs, tokens, API keys). |
| `summarize.py` | Cheap token estimation + token-aware hierarchical (map-reduce) summarization. |
| `report.py` | Builds the triage prompt (grounded on computed evidence), parses the structured response, renders Markdown + Rich panels. |
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
pytest --cov          # with coverage (CI gate: >=80%)

ruff check src tests  # lint
black --check src tests  # formatting
mypy src              # type checking
bandit -q -c pyproject.toml -r src  # security scan
```

CI (`.github/workflows/ci.yml`) runs all of the above on Python 3.11 and 3.12.
Optional ML extras (`pip install -e ".[ml]"`) enable heavier analytics backends;
the core falls back to pure-Python implementations when they are absent.

Unit tests cover the parser, clustering/ranking, redaction, report generation,
and the full analytics engine — Drain mining, anomaly/onset detection,
cascade correlation, and the deterministic incident report. The LLM is mocked,
so the suite runs fully offline and deterministically with no model or network
required.

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
