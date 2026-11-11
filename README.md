# ![Humanet airgap-check](docs/banner.png)

Find out what your AI app downloads, or tries to reach, when the network goes away.

![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## Why

A common assumption: point the LLM base URL at a local vLLM or Ollama instance and the app is ready for an offline network (an air-gapped VPC, a hospital or defense network, a container with no internet). In practice, many libraries fetch something on first use: tokenizer ranks, ONNX embedding weights, corpora, price maps, or telemetry. Offline, these calls either fail at first use or hang for tens of seconds on retry backoff.

None of this is a bug in those libraries. They download once and cache. It only becomes visible when the network is gone. Humanet airgap-check tries to surface it before you deploy.

## What it does

- **Manifest & lockfile scan.** Inspects `requirements*.txt`, `pyproject.toml`, `Pipfile`, `package.json`, `Cargo.toml`, `go.mod`, and `Gemfile` (promoting `[tool.uv] default-groups`, preserving `[tool.setuptools.dynamic.optional-dependencies]`, skipping `devDependencies` / `[dependency-groups]` `dev`/`test`/`lint`/`docs`, and suppressing `spacy` when a model wheel URL is pinned), and follows lockfiles (`uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml` v9 multi-doc including `peerDependenciesMeta` optional edges, `yarn.lock`, `Cargo.lock`) with explicit scope tags (`prod`, `transitive_lockfile`, `optional_extra`). Reads these files with a built-in minimal TOML/YAML reader (no external parser), so unusual formatting may be missed.
- **Source patterns & heuristics.** Flags known runtime fetch calls (`nltk.download()`, `spacy.load()`, `gtts.gTTS()`, `from_pretrained()`, `tiktoken.get_encoding()`, `whisper.load_model()`, `easyocr.Reader()`, `RapidOCR()`, `PaddleOCR()`, `FlagModel`/`FlagReranker`, `TextEmbedding()`, `next/font/google`), skipping comments, docstrings (without inverting on multiline string expressions), Vertex AI `TextEmbeddingModel.from_pretrained()`, non-runtime build/eval/test scripts (`conftest.py`), hash-verification tables, UI placeholders/links, and `local_files_only=True`. Also flags split-line asset URLs (`.onnx`, `.safetensors`, `.gguf`, `model_prices_and_context_window.json`), runtime pricing/update checks (`models.dev`, `pypi.org`, GitHub releases, `updates.*`), `urlretrieve()`, multiline `subprocess` installers (`pip install`, `curl`, `git clone`, `ollama pull`), hardcoded `~/.cache` writes, and direct stdlib telemetry endpoints (`eu.i.posthog.com`, `otel.*`, `/v1/traces/ingest`). Missing HTTP `timeout=` calls are reported separately as advisory `robustness_hints`.
- **Python and Node `--run`.** Runs your app or probe inside `docker run --rm --network none` (overriding baked `ENTRYPOINT`, logging to a `fsync`-backed bind-mounted host file with `docker rm -f` cleanup on timeout, and waiting briefly via `/proc` for detached `atexit` child senders) with a loopback sinkhole (`UDP:53` DNS, `TCP:443` TLS SNI, `TCP:80` HTTP Host/Path with query strings stripped, `HTTP_PROXY` fallback) and Python/Node socket hooks.
- **`--fix` & custom rules.** Prints Dockerfile `ENV` flags (including `OPENAI_AGENTS_DISABLE_TRACING=1`, `CHROMA_TELEMETRY_IMPL=none`) and pre-warming commands, and supports repo overrides via `.airgap-check.json` or `--rules`.
- **`.env` keys.** Classifies `.env*` key names and `git ls-files` status only (excluding non-secret LLM token-limit knobs); secret values are never read or logged.

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
# --- BEGIN HUMANET AIRGAP-CHECK REMEDIATION ---
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
    OPENAI_AGENTS_DISABLE_TRACING=1 \
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
# --- END HUMANET AIRGAP-CHECK REMEDIATION ---
```

## How `--run` works, and where it stops

`--run` starts a uniquely named ephemeral container (`--rm --network none --entrypoint ""`), mounts your repository read-only alongside a bind-mounted, `fsync`-flushed `attempts.jsonl` log, and injects an isolated loopback observer (`runner.py` in Python containers, or `runner.js` in Node-only containers; pass `--build` to build the repo's `Dockerfile` first):

- **Loopback DNS sinkhole (`127.0.0.1:53/udp`)** with `/etc/resolv.conf` updated inside the ephemeral container. In the default `sinkhole` mode (`--dns-action sinkhole`), `A` queries resolve to `127.0.0.1` so outbound connections continue to our loopback TLS/HTTP listeners rather than dying at DNS before showing their HTTP path or SNI hostname. Pass `--dns-action nxdomain` to fail immediately at DNS resolution.
- **TLS `ClientHello` SNI (`127.0.0.1:443`) & HTTP (`127.0.0.1:80`) sinkholes**, plus an `HTTP_PROXY`/`HTTPS_PROXY` loopback `CONNECT` fallback when running as a non-root container user without bind privileges on ports `< 1024`. Query strings are stripped from captured URLs.
- **Python (`sitecustomize.py`) & Node (`node_preload.js`) socket hooks** recording `socket.getaddrinfo` (including Python `bytes` hosts), `socket.connect`, `dns.lookup` / `dns.promises.lookup`, and `net.Socket.connect` (covering Node 20 `fetch()` / `http` / `https`).
- **Timeout & detached-process handling:** After the main process exits, the runner polls `/proc` briefly (up to 1 s) so detached `atexit` background telemetry processes finish writing before log collection. On host timeout (`TIMEOUT_EXCEEDED_IN_AIRGAP`), `airgap-check` runs `docker rm -f` on the named container and preserves attempts written prior to timeout via the bind-mounted log. Non-zero exit or caught silent egress sets `crashed_in_airgap` (with `SILENT_EGRESS_ATTEMPTED_AND_DROPPED` when a command exits `0` after attempting outbound egress). Error-text fallback URL extraction ignores traceback documentation links (`errors.pydantic.dev`, `cloud.google.com`, `sharp.pixelplumbing.com`, etc.).

Limits:

- Loopback sinkholes (`runner.py` and `runner.js`) were validated in real `docker run --network none` containers for Python (`python:3.12-slim-bookworm`), pure Node.js (`node:20-bookworm-slim`), and built `Dockerfile` images. Other runtimes without Python or Node fall back to `shell_only` error URL extraction and are not separately validated.
- `v0.2.2` `--run` hardening fixes (`--entrypoint ""` override, `bytes` host decoding, detached `atexit` child capture, `docker rm -f` timeout cleanup, and Node 20 `fetch()` tracking) were verified via real `docker run --rm --network none` integration tests in `go test -v ./...`; full upstream Benchmark v2 container runs were executed earlier on frozen `v0.2.1` (`47b2ddc`).
- Traffic to hardcoded external IP addresses (not hostnames) fails with `ENETUNREACH` in the kernel without hitting loopback SNI/HTTP listeners, though `sitecustomize.py`/`node_preload.js` capture literal connect targets in Python/Node. DNS-over-HTTPS traffic skips the system resolver unless SNI reveals the DoH provider.
- Non-root containers running compiled Go/Rust binaries that ignore `HTTP_PROXY` and cannot bind ports 53/80/443 inside the unprivileged user namespace will log `ENETUNREACH` rather than SNI unless run as root inside the throwaway test container.
- Only the code paths you exercise are tested. Use `--run-cmd` to run a smoke test that covers the paths you care about.
- The sinkhole answers immediately. In a real enclave, packets may be dropped instead, so hangs can be longer than the times below.

## Benchmark

We evaluated `airgap-check` across three probe-based phases (30 Python and TypeScript AI repositories documented in [`benchmark/REPOS.md`](benchmark/REPOS.md): Phase 1 calibration, Phase 2 held-out `v0.1.0` -> `v0.2.0` design, and Phase 3 out-of-sample `v0.2.1`) plus an independent quickstart/`strace` validation suite (**Benchmark v2**, 10 pre-registered repositories + Backup B1 `AutoGPT` documented in [`benchmark/REPOS2.md`](benchmark/REPOS2.md)):

- Phases 2 & 3 are probe-based tests: we did not start the applications themselves. A “true positive” means the flagged library fetches something when its call runs offline (or executes a runtime installer/download); it does not prove the repository reaches that call in normal operation. Telemetry findings (for example langsmith, posthog or sentry) and advisory `robustness_hints` (`timeout=` omissions) are not scored in precision/recall.
- Benchmark v2 removes that circularity by running **both** `(b)` documented application startup/import/CLI commands under `docker run --rm --network none` + raw `strace -f` (`ENETUNREACH` independent ground truth) **and** `(a)` static-derived probes against frozen `v0.2.1` (`47b2ddc`), before fixing the exposed bugs in `v0.2.2`.

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

Timings in the table above were measured with `v0.1.0` (immediate `NXDOMAIN`); `v0.2.0+` defaults to `sinkhole` mode (`127.0.0.1`), where connections reach a local loopback TLS/HTTP listener first and hit handshake/socket errors instead of immediate DNS errors, which changes retry behaviour across HTTP clients (for example, `huggingface_hub` on `smolagents` exited in `293 ms` under `sinkhole` vs `477 ms` under `--dns-action nxdomain`). Browser-side telemetry, such as `posthog-js` in a frontend bundle, is a separate case: server environment variables do not silence it, because the requests leave from the user's browser.

### Phase 2 held-out results (v0.1.0, rules frozen at `8ce2f11`)

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

At component level (`v0.1.0`): 35 true positives, 4 false positives, 5 false negatives. That is 89.7% precision and 87.5% recall. This is a small sample, so treat the numbers as rough. At repository level, all 9 repositories with first-use downloads were flagged, and `chat-langchain` was correctly flagged as clean.

False positives (all 4 in `v0.1.0`): `pyproject.toml` was scanned as plain text, so dev and test dependency groups (`playwright` in `docling`, `litellm`, `pydantic-ai`) and an optional extra named `posthog` triggered warnings.

False negatives (all 5 in `v0.1.0`): OCR weight downloaders (`easyocr`, `rapidocr`, `paddleocr`), `FlagEmbedding`, and LiteLLM's startup fetch of `model_prices_and_context_window.json` were not in the frozen `v0.1.0` rule table.

### v0.2.0 design fixes (same Phase 2 commits, not out-of-sample)

> These 10 Phase 2 repositories were used to design the `v0.2.0` fixes, so re-run numbers on them are no longer out-of-sample. See the fresh Phase 3 held-out set below for out-of-sample `v0.2.1` validation.

- Addresses all 4 `v0.1.0` dev-group / key-name false positives (`0` dev/lint/key-name false positives; optional extras such as `format-html-render` in `docling` or `[extra: playwright]` in `pydantic_ai_harness` are tagged explicitly as `optional_extra` rather than `prod`).
- Addresses the 5 `v0.1.0` false negatives (`FlagEmbedding`, `paddleocr`, `easyocr`, `rapidocr`, and `litellm`'s startup `model_prices_and_context_window.json` fetch — the latter caught generically by the behavioral URL scanner without requiring a package rule).
- Surfaces transitive air-gap dependencies via lockfile traversal (`huggingface-hub` via `datasets` in `gpt-engineer`'s `poetry.lock`, `spacy` and `rapidocr` via `uv.lock` in `llama_index`, `@huggingface/transformers` via `pnpm-lock.yaml` in `mem0`, `tiktoken` via `uv.lock` in `pydantic-ai`).

### Phase 3 held-out results (v0.2.1, rules frozen at `47b2ddc`)

To measure `v0.2.1` strictly out-of-sample, we froze all detection rules at commit `47b2ddc` before cloning 10 previously unseen AI repositories (`0.02 s` – `0.59 s` per scan):

| Repository | Probe result under `--network none` (`sinkhole`) | TP | FP | FN |
| :--- | :--- | :-: | :-: | :-: |
| `smolagents` | exit 1 (`huggingface.co`, 293 ms) | 6 | 1 | 0 |
| `crawl4ai` | exit 1 (`raw.githubusercontent.com`, `openaipublic.blob.core.windows.net`, 345 ms) | 10 | 0 | 2 |
| `aider` | exit 1 (`openaipublic.blob.core.windows.net`, 358 ms) | 7 | 0 | 1 |
| `open-webui` | exit 1 (`chroma-onnx-models.s3.amazonaws.com`, 557 ms) | 14 | 0 | 2 |
| `browser-use` | exit 1 (`openaipublic.blob.core.windows.net`, 212 ms) | 1 | 0 | 0 |
| `markitdown` | exit 0, no runtime downloads (163 ms; `magika` bundles weights locally) | 0 | 0 | 0 |
| `crewAI` | exit 1 (`chroma-onnx-models.s3.amazonaws.com`, 592 ms) | 13 | 3 | 2 |
| `openai-agents-python` | exit 0, core runtime clean (419 ms; `[extra: litellm]` flagged) | 1 | 0 | 0 |
| `servers` | exit 0, no runtime downloads (153 ms, `node:20-bookworm-slim`) | 0 | 0 | 0 |
| `instructor` | exit 0, core runtime clean (417 ms; `[extra: litellm]` flagged) | 1 | 0 | 0 |

At finding level (`v0.2.1`, out-of-sample): **53 true positives, 4 false positives, 7 false negatives** (**93.0% precision**, **88.3% recall**). All 8 repositories containing runtime downloaders or optional-extra downloads were flagged (while dev-only `playwright==1.63.0` inside `openai-agents-python`'s `[dependency-groups] dev` produced 0 false positives), and both clean repositories (`markitdown`, `servers`) were flagged clean. Separating missing `timeout=` calls out of `behavioral_findings` into advisory `robustness_hints` prevented 37 HTTP-timeout hints (`26` in `open-webui` alone) from dropping out-of-sample precision from 93.0% to 56.4%.

- **False positives (4)**: `smolagents` matched a docstring example (`>>> tokenizer = AutoTokenizer.from_pretrained(...)` in `_function_type_hints_utils.py`); `crewAI` matched Vertex AI SDK's `TextEmbeddingModel.from_pretrained(...)` (`genai_vertex_embedding.py`), a private maintenance script (`lib/devtools/src/crewai_devtools/litellm_catalog_update.py`), and `arxiv_paper_tool.py`'s user-triggered `urlretrieve(pdf_url)`.
- **False negatives (7)**: `crawl4ai/model_loader.py` has a multi-line `subprocess.run(["git", "clone", ...])` call (line-by-line regex missed it) and `spacy.load()`; `aider/models.py` splits `model_prices_and_context_window.json` across two adjacent string literals (though `litellm` in `requirements.txt` surfaced the host); `open-webui` missed `spacy` transitively under `unstructured` in `uv.lock` and `kokoro-js` in `package.json` (`kokoro.worker.ts` `from_pretrained()` was caught); `crewAI` missed `docling` (`[extra: docling]` + `DocumentConverter()`) and `spacy` under optional extras. Also note: `aider` maps `requirements-help.txt` and `requirements-playwright.txt` via `[tool.setuptools.dynamic.optional-dependencies]`, so the minimal TOML reader tagged those 4 extras as `prod` rather than `optional_extra`, and `browser-use` implements PostHog telemetry via raw stdlib `urllib` rather than the `posthog` PyPI package (unscored).

Per-repository SHAs, manifests, lockfiles, scan durations, and probe transcripts are recorded in [`benchmark/REPOS.md`](benchmark/REPOS.md).

### Benchmark v2 held-out + quickstart/`strace` validation (`v0.2.1`, rules frozen at `47b2ddc`)

To break probe circularity and test non-Python heavy apps, Node backends, Go rewrites, and negative controls (`openai-agents-python`, `LibreChat`), we froze `v0.2.1` at `47b2ddc`, pre-registered 10 target repos + Backup B1 `AutoGPT` in [`benchmark/REPOS2.md`](benchmark/REPOS2.md), and ran documented quickstarts/CLIs under raw `strace -f` inside `--network none` alongside static probes (`ragflow` was replaced dynamically by B1 `AutoGPT` because its multi-stage `Dockerfile` + multi-GB `ragflow_deps` image exceeded the 20-minute build cap):

| Repository | `(b)` Quickstart / CLI (`--network none` + `strace`) & `(a)` Probe | TP | FP | FN |
| :--- | :--- | :-: | :-: | :-: |
| `open-webui` | `uvicorn` boots & seeds SQLite (`22,481 ms`, exit `137`) trying HF embeddings (`13,067 ms`) & `api.github.com` release check; `(a)` crashes on `tiktoken`/`chromadb`/`faster-whisper`/`unstructured`/`playwright`/`spacy` (`rapidocr` blank-image clean) | 14 | 0 | 4 |
| `anything-llm` | Node `server/index.js` exits `0` (`SILENT_EGRESS`, `5,371 ms`) fetching **`models.dev`** & `raw.githubusercontent.com`; `(a)` `tesseract.js` (`cdn.jsdelivr.net`), `@xenova/transformers` fail; `js-tiktoken` clean | 4 | 0 | 3 |
| `dify` | `flask db --help` / `import app` clean; `check_version_update` hits **`updates.dify.ai`** (`9,572 ms`); telemetry hits `otel.dify.ai`; `(a)` `tiktoken`/`transformers`/`chromadb`/`nltk`/`spacy` fail | 7 | 1 | 2 |
| `ragflow` | *Container build blocked (>20 min `ragflow_deps` multi-stage).* Go backend (`localBpeLoader`) is disk-only in source; all 5 `v0.2.1` findings were FPs (build/eval scripts + Go hash map) | 0 | 5 | 0 |
| `haystack` | Default `DocumentSplitter()` clean aside from `eu.i.posthog.com` (`1,582 ms`); `split_by="sentence"` crashes (`nltk`); `(a)` `tiktoken`/`nltk` fail | 5 | 0 | 0 |
| `browser-use` | `--help` exits `0` cleanly (`187 ms`); `ProductTelemetry().flush()` hits **`eu.i.posthog.com`** (`1,831 ms`, `SILENT_EGRESS`); `(a)` `tiktoken` fails | 1 | 0 | 0 |
| `aider` | `aider --no-git --yes --exit --model gpt-4o` tries **`pypi.org`** (`versioncheck.py`) & **`raw.githubusercontent.com`** (`models.py` + `litellm`, `1,518 ms`); `(a)` `tiktoken` fails | 7 | 0 | 2 |
| `Flowise` | `bin/run start` clean for 28 s (`exit 137`); `(a)` **`langchainhub`** (`563 ms`, `api.hub.langchain.com`), `playwright`, `puppeteer` fail; `@dqbd/tiktoken` clean (`429 ms`) | 3 | 0 | 2 |
| `openai-agents-python` | **Negative control 1:** `Agent()` clean (`752 ms`); `Runner.run_sync()` emits background tracing to **`api.openai.com/v1/traces/ingest`** unless `OPENAI_AGENTS_DISABLE_TRACING=1` | 1 | 0 | 4 |
| `LibreChat` | **Negative control 2:** `countTokens()` clean (`1,518 ms`, 0 network syscalls); server connects only to loopback MongoDB (`127.0.0.1:27017`) | 0 | 0 | 0 |
| `AutoGPT` *(Backup B1)* | `autogpt --help` & `import` clean; `autogpt run` (`TELEMETRY_OPT_IN=true`) crashes via `sentry_sdk`->`tiktoken`; `gtts` hits `translate.google.com`; **`spacy` wheel pin clean** (`exit 0`) | 6 | 3 | 2 |

At finding level on frozen `v0.2.1` (`47b2ddc`, strictly out-of-sample):
- **Pre-registered Primary 10 (`#1–#10`, including `ragflow` static)**: `42 TP`, `6 FP`, `17 FN` (**87.5% precision**, **71.2% recall**)
- **Executable 10 (`#1–#3, B1, #5–#10`, substituting B1 `AutoGPT` for blocked `ragflow` container)**: `48 TP`, `4 FP`, `19 FN` (**92.3% precision**, **71.6% recall**)
- **All 11 Scanned (`#1–#10 + B1`)**: `48 TP`, `9 FP`, `19 FN` (**84.2% precision**, **71.6% recall**)

What independent `(b)` quickstarts/`strace` uncovered that static-only benchmarks missed:
- **False positives (`9`)**: `dify` pnpm v9 optional `peerDependenciesMeta` edge (`next@16.4.5` -> `@playwright/test`), `ragflow` build/dev scripts (`download_deps.py`, `gen_tokenizer_oracle.py`) + Go hash verification table (`expectedBpeHashes`), and `AutoGPT` eval CLI scripts (`eval/prefix.py`, `eval_corpus.py`) + pinned `en-core-web-sm` wheel URL.
- **False negatives (`19`)**: runtime API/update checks (`models.dev/api.json`, `pypi.org/pypi/.../json`, `api.github.com/.../releases`, `updates.dify.ai`), multiline Python expression strings (`MODEL_INFO_URL = """..."""`) inverting docstring masking in `aider`, `[tool.uv] default-groups`, `uv.lock` optional-extra BFS (`spacy` under `unstructured`, `huggingface-hub`/`tiktoken` under `litellm`), multiline `subprocess.run(["git", "clone", ...])`, `gtts`, `tesseract.js`, `kokoro-js`, and `langchainhub`.
- **Unscored telemetry & `--run` observer bugs**: custom stdlib senders without SDK packages (`browser-use`, `dify`, `haystack`, `openai-agents` `/v1/traces/ingest`), `ENTRYPOINT` hijack on pre-built images, Python `bytes` host formatting (`b'...'`), noisy traceback doc URLs (`errors.pydantic.dev`, `sharp.pixelplumbing.com`), and timeout / detached-`atexit` log races.

### `v0.2.2` post-diagnosis fixes (same Benchmark v2 commits, NOT out-of-sample)

> These 11 Benchmark v2 repositories were used to diagnose and design the `v0.2.2` fixes, so static re-scan numbers below are **in-sample verification**, **NOT** out-of-sample generalization metrics.

- Fixes all 9 `v0.2.1` Benchmark v2 false positives and all 19 false negatives on the pinned Benchmark v2 snapshots (`67 TP`, `0 FP`, `0 FN` on static re-scan; plus 3 `.env` token-limit FPs removed on `ragflow` and custom stdlib telemetry URLs surfaced in `browser-use`, `dify`, `haystack`, and `openai-agents-python` while filtering UI credential/placeholder forms and `conftest.py` test files).
- Fixes all 4 `--run` observer issues (`--entrypoint ""`, bind-mounted `fsync` log + `docker rm -f` on timeout, Python `bytes` decoding, `/proc` detached-child wait, and `runtime_error_url` error-context filtering). Verified via real `docker run --rm --network none` tests in `go test -v ./...` (`18/18` passing); the 46 upstream Benchmark v2 application containers were not re-run on `v0.2.2`. Full details and per-repo deltas are in [`benchmark/REPOS2.md`](benchmark/REPOS2.md).

## Supported checks

| Category | Pattern | Host(s) | `--fix` |
| :--- | :--- | :--- | :--- |
| Runtime download | `tiktoken` (Python & `tiktoken-rs`) | `openaipublic.blob.core.windows.net` | pre-warms `cl100k_base`, `o200k_base` |
| Runtime download | `chromadb` default embedder | `chroma-onnx-models.s3.amazonaws.com` | pre-warms `ONNXMiniLM_L6_V2` |
| Runtime download | `fastembed`, `TextEmbedding()` | `huggingface.co`, `cdn-lfs.hf.co` | pre-warms the model cache |
| Runtime download | `sentence-transformers`, `transformers`, `@huggingface/transformers`, `from_pretrained()`, `hf_hub_download()`, `snapshot_download()` | `huggingface.co`, `cdn-lfs.hf.co` | sets offline `ENV` flags; prints model snapshot template (skips `local_files_only=True` & Vertex AI SDK) |
| Runtime download | `FlagEmbedding` (`FlagModel`, `FlagReranker`, `BGEM3FlagModel`) | `huggingface.co`, `cdn-lfs.hf.co` | sets offline `ENV` flags; prints snapshot template |
| Runtime download | `easyocr`, `rapidocr*`, `paddleocr` | `github.com`, `releases.jaided.ai`, `huggingface.co`, `modelscope.cn`, `paddleocr.bj.bcebos.com` | pre-warms OCR weights / `EASYOCR_MODULE_PATH` |
| Runtime download | `tesseract.js` | `cdn.jsdelivr.net`, `tessdata.projectnaptha.com` | hints pre-baking `*.traineddata` & local `langPath` |
| Runtime download | `whisper.load_model()` / `faster-whisper` / `mlx-whisper` | `openaipublic.azureedge.net`, `huggingface.co` | pre-warms the checkpoint |
| Runtime download | `gtts`, `gtts.gTTS()`, `kokoro`, `kokoro-js` | `translate.google.com`, `huggingface.co`, `cdn-lfs.hf.co` | flags online TTS (`gtts`) or pre-bake requirement (`kokoro*`) |
| Runtime download | `litellm` startup cost map | `raw.githubusercontent.com` | sets `LITELLM_LOCAL_MODEL_COST_MAP=True` |
| Runtime download | `playwright`, `puppeteer` | `playwright.azureedge.net`, `storage.googleapis.com` | installs Chromium (`python3 -m playwright` / `npx playwright` / `npx puppeteer`) |
| Runtime download | `nltk.download()`, `spacy.cli.download()`, `spacy.load()` | `raw.githubusercontent.com` | pre-downloads corpora / model wheel (suppresses pinned wheel URLs) |
| Runtime download | `langchainhub` / `@langchain/hub` (`hub.pull()`), `torch.hub.load()`, `timm`, `ultralytics`, `unstructured`, `surya-ocr`, `docling-ibm-models` | `api.smith.langchain.com`, `github.com`, `download.pytorch.org`, `huggingface.co` | vendor prompt templates or pre-bake `TORCH_HOME` / `HF_HOME` |
| Build-time download | `next/font/google` | `fonts.googleapis.com`, `fonts.gstatic.com` | flagged only; suggests `next/font/local` |
| Behavioral heuristics | Remote `.onnx`/`.safetensors`/`.gguf`/cost-map URLs (incl. split-line strings), runtime update/pricing URLs (`models.dev`, `pypi.org`, GitHub releases, `updates.*`), `urlretrieve()`, archive fetch+unpack, runtime `subprocess` (`pip install`, `curl`, `wget`, `git clone`, `ollama pull`), hardcoded `~/.cache` writes | dynamic / inferred hosts | hints detected hosts (skips hash-verification tables) |
| Robustness hints (advisory) | Python `requests`/`urllib` HTTP calls omitting `timeout=` | — | separated into `robustness_hints`; suggests `timeout=(2, 10)` |
| Server telemetry | `chromadb`, `crewai`, `langsmith`, `langfuse`, `wandb`, `opentelemetry-exporter-otlp`, `ddtrace`, `gradio`, `scarf`, `openai-agents` (`/v1/traces/ingest`), direct stdlib PostHog/OTLP URLs | PostHog, `telemetry.crewai.com`, `otel.*`, `api.smith.langchain.com`, `cloud.langfuse.com`, `api.wandb.ai`, Datadog, `api.gradio.app`, `scarf.sh`, `api.openai.com` | sets matching disable flags (`OPENAI_AGENTS_DISABLE_TRACING=1`, `CHROMA_TELEMETRY_IMPL=none`, etc.) |
| Browser telemetry | `posthog-js`, `@sentry/*`, frontend `langsmith` / direct URLs under `frontend/` / `web/` / `packages/ui/` | PostHog, Sentry, LangSmith | flagged only; disable the SDK in frontend code (UI placeholders/links ignored) |
| `.env` keys | `OPENAI_*`, `ANTHROPIC_*`, `GEMINI_*`, `STRIPE_*`, `JWT_*`, `CLOUDINARY_*`, `AWS_SECRET*` and others | n/a | flagged only; classifies key names & git tracking status (excludes token-limit knobs) |

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

Humanet airgap-check is not a security certification. It reports what it observed; a clean result does not prove that your application is safe to run in an isolated network.

## Contributing

Found a library that quietly phones home, or a false positive on your repo? Open an issue with the package name, the call, and the host it tries to reach, and we will add or fix the rule.

## About

Open-sourced by [Humanet](https://humanet.dev), which is also building Frame, an early-stage hosting platform.

## License

MIT
