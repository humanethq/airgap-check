# ![airgap-check](docs/banner.png)

Find out what your AI app downloads, or tries to reach, when the network goes away.

![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## Why

A common assumption: point the LLM base URL at a local vLLM or Ollama instance and the app is ready for an offline network (an air-gapped VPC, a hospital or defense network, a container with no internet). In practice, many libraries fetch something on first use: tokenizer ranks, ONNX embedding weights, corpora, price maps, or telemetry. Offline, these calls either fail at first use or hang for tens of seconds on retry backoff.

None of this is a bug in those libraries. They download once and cache. It only becomes visible when the network is gone. airgap-check tries to surface it before you deploy.

## What it does

- **Structural manifest & lockfile graph scan.** Structurally parses `requirements*.txt`, `pyproject.toml` (ignoring `[dependency-groups]`, `dev`/`test`/`lint`/`docs` groups, and extra key names), `Pipfile`, `package.json` (skipping `devDependencies`), `Cargo.toml`, `go.mod`, and `Gemfile`. Walks `uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and `Cargo.lock` via BFS from production roots so transitive weight/telemetry dependencies are found with explicit scope tags (`prod`, `transitive_lockfile`, `optional_extra`).
- **Known + universal behavioral source analysis.** Detects known runtime fetch calls (`nltk.download()`, `from_pretrained()`, `tiktoken.get_encoding()`, `whisper.load_model()`, `easyocr.Reader()`, `RapidOCR()`, `PaddleOCR()`, `FlagModel`/`FlagReranker`, `TextEmbedding()`, `next/font/google`) while respecting comments and `local_files_only=True`. Also flags unknown-library patterns generically: remote weight/archive/cost-map URLs (`.onnx`, `.safetensors`, `.gguf`, `.pth`, `model_prices_and_context_window.json`), `urlretrieve()`, runtime `subprocess`/`pip install`/`ollama pull`, Python `requests`/`urllib` calls omitting `timeout=`, and hardcoded `~/.cache` writes.
- **Multi-runtime `--run`.** Runs your app or probe inside `docker run --rm --network none` with an isolated loopback sinkhole (`UDP:53` DNS, `TCP:443` TLS `ClientHello` SNI, `TCP:80` HTTP Host/Path with query strings stripped, plus `HTTP_PROXY` fallback) and Python/Node socket hooks — supporting both Python (`runner.py`) and pure Node.js (`runner.js`) containers without package rules.
- **`--fix` & `.airgap-check.json`.** Prints Dockerfile lines (offline `ENV` flags and build-time pre-warming commands) tailored to detected ecosystems, and lets repositories extend or suppress rules via `.airgap-check.json` or `--rules`.
- **`.env` key classification.** Inspects `.env*` key names and `git ls-files` status only; secret values are never read or logged.

Go standard library only. `--run` requires Docker.

## Install

```bash
# macOS and Linux
curl -fsSL https://raw.githubusercontent.com/humanethq/airgap-check/main/install.sh | sh

# With Go 1.22+ (also works on Windows)
go install github.com/humanethq/airgap-check/cmd/airgap-check@latest

# From source
git clone https://github.com/humanethq/airgap-check.git
cd airgap-check && make build && ./bin/airgap-check --help
```

## Usage

```bash
# static scan
airgap-check /path/to/repo

# static scan plus a Dockerfile snippet
airgap-check --fix /path/to/repo

# run in a container with no network
airgap-check --run /path/to/repo

# auto-build the repo's Dockerfile first, then run inside --network none
airgap-check --run --build --run-cmd "python3 -m pytest tests/smoke_test.py" /path/to/repo

# use your own image, NXDOMAIN DNS mode, or a custom rules file
airgap-check --run --dns-action nxdomain --image my-app:latest --run-cmd "node server.js" /path/to/repo
airgap-check --rules ./airgap.custom.json /path/to/repo

# machine-readable output (flags may appear before or after the path)
airgap-check /path/to/repo --json
```

### Example `--fix` output (abridged)

Read this before applying it: if your app loads Hugging Face models, pre-warm them at build time before setting `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`. Without a warm cache the app fails at startup instead of hanging.

```dockerfile
# --- BEGIN AIR-GAP & TELEMETRY REMEDIATION ---
ENV DO_NOT_TRACK=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    ANONYMIZED_TELEMETRY=False \
    CHROMA_TELEMETRY_IMPL=none \
    SCARF_NO_ANALYTICS=true \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    LANGCHAIN_TRACING_V2=false \
    LANGFUSE_ENABLED=false \
    CREWAI_DISABLE_TELEMETRY=true \
    OTEL_SDK_DISABLED=true \
    DD_TRACE_ENABLED=false \
    WANDB_MODE=offline \
    WANDB_DISABLED=true \
    GRADIO_ANALYTICS_ENABLED=False \
    LITELLM_LOCAL_MODEL_COST_MAP=True \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    XDG_CACHE_HOME=/app/.cache \
    TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken \
    HF_HOME=/app/.cache/huggingface \
    NLTK_DATA=/app/.cache/nltk_data \
    EASYOCR_MODULE_PATH=/app/.cache/easyocr \
    TORCH_HOME=/app/.cache/torch \
    PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright \
    PUPPETEER_CACHE_DIR=/app/.cache/puppeteer
RUN mkdir -p /app/.cache/tiktoken /app/.cache/huggingface /app/.cache/nltk_data /app/.cache/easyocr /app/.cache/torch /app/.cache/ms-playwright /app/.cache/puppeteer

# Pre-warm Python tiktoken encodings at build time
RUN TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken python3 -c "import tiktoken; [tiktoken.get_encoding(e) for e in ('cl100k_base', 'o200k_base')]"

# Pre-warm ChromaDB's default ONNX embedding model at build time
RUN HOME=/app XDG_CACHE_HOME=/app/.cache python3 -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ef = ONNXMiniLM_L6_V2(); ef(['airgap-warmup'])"
# --- END AIR-GAP & TELEMETRY REMEDIATION ---
```

## How `--run` works, and where it stops

`--run` starts a container with `--network none`, mounts your repository read-only, and injects an isolated loopback observer (`runner.py` in Python containers, or `runner.js` in Node-only containers; pass `--build` to build the repo's `Dockerfile` first):

- **Loopback DNS sinkhole (`127.0.0.1:53/udp`)** with `/etc/resolv.conf` updated inside the ephemeral container. In the default `sinkhole` mode (`--dns-action sinkhole`), `A` queries resolve to `127.0.0.1` so outbound connections continue to our loopback TLS/HTTP listeners rather than dying at DNS before showing their HTTP path or SNI hostname. Pass `--dns-action nxdomain` to fail immediately at DNS resolution.
- **TLS `ClientHello` SNI (`127.0.0.1:443`) & HTTP (`127.0.0.1:80`) sinkholes**, plus an `HTTP_PROXY`/`HTTPS_PROXY` loopback `CONNECT` fallback when running as a non-root container user without bind privileges on ports `< 1024`. Query strings are stripped from captured URLs.
- **Python (`sitecustomize.py`) & Node (`node_preload.js`) socket hooks** recording `socket.getaddrinfo`, `socket.connect`, `dns.lookup`, and `net.Socket.connect`.

Limits:

- Loopback sinkholes (`runner.py` and `runner.js`) were validated in real `docker run --network none` containers for both Python (`python:3.12-slim-bookworm`) and pure Node.js (`node:20-bookworm-slim`). Other runtimes without Python or Node fall back to `shell_only` error URL extraction and are not separately validated.
- Traffic to hardcoded external IP addresses (not hostnames) fails with `ENETUNREACH` in the kernel without hitting loopback SNI/HTTP listeners, though `sitecustomize.py`/`node_preload.js` capture literal connect targets in Python/Node. DNS-over-HTTPS traffic skips the system resolver unless SNI reveals the DoH provider.
- Non-root containers running compiled Go/Rust binaries that ignore `HTTP_PROXY` and cannot bind ports 53/80/443 inside the unprivileged user namespace will log `ENETUNREACH` rather than SNI unless run as root inside the throwaway test container.
- Only the code paths you exercise are tested. Use `--run-cmd` to run a smoke test that covers the paths you care about.
- The sinkhole answers immediately. In a real enclave, packets may be dropped instead, so hangs can be longer than the times below.

## Benchmark

We ran airgap-check on 20 open-source Python and TypeScript AI repositories in two phases. Phase 1 (10 repos) was used to find failure modes and tune the rules. Phase 2 (10 repos) is a held-out set: the rules were frozen at commit `8ce2f11` before we ran it.

These are probe-based tests: we did not start the applications themselves. Under `--network none`, we executed probe calls exercising the specific library functions flagged by the static scan (for example, `tiktoken.get_encoding('cl100k_base')` for `gpt-engineer`, ChromaDB collection creation and insertion for `mem0` and `vanna`, Hugging Face model resolution for `docling` and `quivr`, and a baseline probe for `chat-langchain`). Exact probe commands, upstream URLs, and commit SHAs are documented in [`benchmark/REPOS.md`](benchmark/REPOS.md).

### What the libraries do offline

| Library / call | Behaviour with no network | Host it tries | Observed |
| :--- | :--- | :--- | :--- |
| `fastembed` `TextEmbedding()` | Retries 3 times (3 s, 9 s, 27 s), then raises `ValueError: Could not load model` | `huggingface.co` | ~39 s |
| `huggingface_hub` `hf_hub_download()` | Retries metadata checks with backoff, then raises `LocalEntryNotFoundError` | `huggingface.co` | ~23.5 s |
| `chromadb` `collection.add()` | Default embedding function downloads the `all-MiniLM-L6-v2` ONNX model | `chroma-onnx-models.s3.amazonaws.com` | fails in under 1 s |
| `tiktoken` (Python) `get_encoding()` | Fetches the BPE rank file on first use | `openaipublic.blob.core.windows.net` | fails in under 1 s |
| `nltk` `nltk.download()` | Tries to fetch the index and corpus | `raw.githubusercontent.com` | fails in under 1 s |
| `playwright` `chromium.launch()` | Fails if the browser binary was not baked into the image | `playwright.azureedge.net` | fails in under 1 s |
| `litellm` | Fetches its model price map at startup unless `LITELLM_LOCAL_MODEL_COST_MAP=True` | `raw.githubusercontent.com` | fallback warning |
| `crewai`, `chromadb` | Background telemetry threads on startup unless disabled | `telemetry.crewai.com:4319`, `us.i.posthog.com` | background timeouts |

Times were measured in a container with no network and an immediately refusing DNS sinkhole (see limits above). Browser-side telemetry, such as `posthog-js` in a frontend bundle, is a separate case: server environment variables do not silence it, because the requests leave from the user's browser.

### Held-out results (10 repos, rules frozen)

| Repository | Probe result under `--network none` | TP | FP | FN |
| :--- | :--- | :-: | :-: | :-: |
| `gpt-engineer` | exit 1 (`tiktoken`) | 1 | 0 | 0 |
| `gpt-researcher` | exit 1 (`tiktoken`, `nltk`) | 4 | 0 | 0 |
| `llama_index` | exit 1 (`tiktoken`) | 8 | 0 | 2 |
| `mem0` | exit 1 (`chromadb` ONNX) | 6 | 0 | 0 |
| `vanna` | exit 1 (`chromadb` ONNX) | 4 | 0 | 0 |
| `quivr` | exit 1 (`huggingface.co`, ~23.5 s of retries) | 3 | 0 | 0 |
| `docling` | exit 1 (`huggingface.co`) | 3 | 1 | 2 |
| `litellm` | exit 1 (`raw.githubusercontent.com`) | 3 | 1 | 1 |
| `pydantic-ai` | exit 1 (`tiktoken`) | 3 | 2 | 0 |
| `chat-langchain` | exit 0, no asset downloads | – | 0 | 0 |

These are probe-based tests: we did not start the applications themselves. A “true positive” means the flagged library fetches something when its call runs offline; it does not prove the repository reaches that call in normal operation. Telemetry findings (for example langsmith, posthog or sentry in several repos) are not scored in the metrics below.

At component level: 35 true positives, 4 false positives, 5 false negatives. That is 89.7% precision and 87.5% recall. This is a small sample, so treat the numbers as rough. At repository level, all 9 repositories with first-use downloads were flagged, and `chat-langchain` was correctly flagged as clean.

False positives (all 4 in v0.1.0): `pyproject.toml` was scanned as plain text, so dev and test dependency groups (`playwright` in `docling`, `litellm`, `pydantic-ai`) and an optional extra named `posthog` triggered warnings.

False negatives (all 5 in v0.1.0): OCR weight downloaders (`easyocr`, `rapidocr`, `paddleocr`), `FlagEmbedding`, and LiteLLM's startup fetch of `model_prices_and_context_window.json` were not in the frozen rule table.

### What changed in v0.2.0 (re-run on the same pinned commits)

Re-running `v0.2.0` on the exact same 10 held-out commits:

- Eliminates all 4 v0.1.0 dev-group / key-name false positives (`0` dev/lint/key-name false positives; optional extras such as `format-html-render` in `docling` or `[extra: playwright]` in `pydantic_ai_harness` are tagged explicitly as `optional_extra` rather than `prod`).
- Closes all 5 v0.1.0 false negatives (`FlagEmbedding`, `paddleocr`, `easyocr`, `rapidocr`, and `litellm`'s startup `model_prices_and_context_window.json` fetch — the latter caught generically by the behavioral URL scanner without requiring a package rule).
- Surfaces transitive air-gap dependencies via lockfile BFS (`huggingface-hub` via `datasets` in `gpt-engineer`'s `poetry.lock`, `spacy` and `rapidocr` via `uv.lock` in `llama_index`, `@huggingface/transformers` via `pnpm-lock.yaml` in `mem0`, `tiktoken` via `uv.lock` in `pydantic-ai`) and runtime `pip install` / `ollama pull` subprocess calls (`gpt-researcher`, `litellm`, `mem0`).

Per-repository v0.2.0 scan timings and detailed breakdowns (0.01 s – 3.40 s across the 10 held-out repos, including 715 manifests / 602 lockfiles in `llama_index` in 1.65 s and 5,732 source files in `litellm` in 3.40 s) are recorded in [`benchmark/REPOS.md`](benchmark/REPOS.md).

## Supported checks

| Category | Pattern | Host(s) | `--fix` |
| :--- | :--- | :--- | :--- |
| Runtime download | `tiktoken` (Python & `tiktoken-rs`) | `openaipublic.blob.core.windows.net` | pre-warms `cl100k_base`, `o200k_base` |
| Runtime download | `chromadb` default embedder | `chroma-onnx-models.s3.amazonaws.com` | pre-warms `ONNXMiniLM_L6_V2` |
| Runtime download | `fastembed`, `TextEmbedding()` | `huggingface.co`, `cdn-lfs.hf.co` | pre-warms the model cache |
| Runtime download | `sentence-transformers`, `transformers`, `@huggingface/transformers`, `from_pretrained()`, `hf_hub_download()`, `snapshot_download()` | `huggingface.co`, `cdn-lfs.hf.co` | sets offline `ENV` flags; prints model snapshot template (skips if `local_files_only=True`) |
| Runtime download | `FlagEmbedding` (`FlagModel`, `FlagReranker`, `BGEM3FlagModel`) | `huggingface.co`, `cdn-lfs.hf.co` | sets offline `ENV` flags; prints snapshot template |
| Runtime download | `easyocr`, `rapidocr*`, `paddleocr` | `github.com`, `releases.jaided.ai`, `huggingface.co`, `modelscope.cn`, `paddleocr.bj.bcebos.com` | pre-warms OCR weights / `EASYOCR_MODULE_PATH` |
| Runtime download | `whisper.load_model()` / `faster-whisper` / `mlx-whisper` | `openaipublic.azureedge.net`, `huggingface.co` | pre-warms the checkpoint |
| Runtime download | `litellm` startup cost map | `raw.githubusercontent.com` | sets `LITELLM_LOCAL_MODEL_COST_MAP=True` |
| Runtime download | `playwright`, `puppeteer` | `playwright.azureedge.net`, `storage.googleapis.com` | installs Chromium (`python3 -m playwright` / `npx playwright` / `npx puppeteer`) |
| Runtime download | `nltk.download()`, `spacy.cli.download()` | `raw.githubusercontent.com` | pre-downloads corpora / model wheel at build time |
| Runtime download | `torch.hub.load()`, `timm`, `ultralytics`, `unstructured`, `surya-ocr`, `docling-ibm-models`, `kokoro` | `github.com`, `download.pytorch.org`, `huggingface.co` | flagged + `TORCH_HOME` / `HF_HOME` setup |
| Build-time download | `next/font/google` | `fonts.googleapis.com`, `fonts.gstatic.com` | flagged only; suggests `next/font/local` |
| Behavioral heuristics | Remote `.onnx`/`.safetensors`/`.gguf`/cost-map URLs, `urlretrieve()`, archive fetch+unpack, runtime `subprocess` (`pip install`, `curl`, `wget`, `ollama pull`), Python HTTP calls omitting `timeout=`, hardcoded `~/.cache` writes | dynamic / inferred hosts | hints detected hosts & explicit `timeout=(2, 10)` action |
| Server telemetry | `chromadb`, `crewai`, `langsmith`, `langfuse`, `wandb`, `opentelemetry-exporter-otlp`, `ddtrace`, `gradio`, `scarf` | PostHog, `telemetry.crewai.com`, `api.smith.langchain.com`, `cloud.langfuse.com`, `api.wandb.ai`, Datadog, `api.gradio.app`, `scarf.sh` | sets the matching disable flags |
| Browser telemetry | `posthog-js`, `@sentry/*`, frontend `langsmith` | PostHog, Sentry, LangSmith | flagged only; disable the SDK in your frontend code |
| `.env` keys | `OPENAI_*`, `ANTHROPIC_*`, `GEMINI_*`, `STRIPE_*`, `JWT_*`, `CLOUDINARY_*`, `AWS_SECRET*` and others | n/a | flagged only; classifies key names and git tracking status |

### Custom rules (`.airgap-check.json` / `--rules`)

Drop `.airgap-check.json` in your repository root (or pass `--rules path/to/rules.json`) to add internal packages or suppress known-good components/hosts:

```json
{
  "rules": [
    {
      "package_or_pattern": "internal-embedder",
      "component": "internal-embedder-sdk",
      "category": "runtime_model_asset",
      "severity": "CRITICAL",
      "hosts": ["models.internal.corp"],
      "impact": "Fetches internal weights at boot.",
      "mitigation": "Bake weights into /app/models during build.",
      "python_only": true
    }
  ],
  "ignore_components": ["gradio"],
  "ignore_hosts": ["api.gradio.app"]
}
```

## Design principles

- Secret values are never read, stored or logged. `.env` files are inspected for key names, non-empty presence, and `git ls-files` status.
- `--run` mounts your repository read-only.

airgap-check is not a security certification. It reports what it observed; a clean result does not prove that your application is safe to run in an isolated network.

## Contributing

Found a library that quietly phones home, or a false positive on your repo? Open an issue with the package name, the call, and the host it tries to reach, and we will add or fix the rule.

## About

Open-sourced by [Humanet](https://humanet.dev), which is also building Frame, an early-stage hosting platform.

## License

MIT
