# `airgap-check` — Offline (`--network none`), Telemetry & Secret Auditor for AI Repositories

[![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://go.dev)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)](#installation)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**What happens when you deploy a modern Python or TypeScript AI application into an air-gapped VPC, SCIF, hospital network, or `--network none` container?**

Even when your application points at a local LLM (vLLM, Ollama) or an internal enterprise gateway, **popular AI libraries silently phone home at runtime** to fetch tokenizer ranks, ONNX embedding weights, corpus zip files, cost maps, or background OTLP telemetry—causing immediate `ConnectError` crashes or **23s–39s retry hangs** per request.

`airgap-check` is a standalone, zero-dependency CLI that:
1. **Statically audits** manifests (`requirements.txt`, `pyproject.toml`, `package.json`, `Cargo.toml`), source code (`nltk.download()`, `from_pretrained()`, `tiktoken.get_encoding()`, `whisper.load_model()`, `next/font/google`), and `.env` credential types (**never reading or logging secret values**).
2. **Dynamically executes (`--run`)** your repository inside `docker run --rm --network none` with an in-container **UDP:53 DNS sinkhole (`127.0.0.1:53`)** plus Python/Node socket hooks—capturing outbound DNS queries from **any language or native C/C++/Rust extension** (`onnxruntime`, `tokenizers`, `libcurl`, `getent`) before they fail closed.
3. **Generates a ready-to-paste `Dockerfile` fix (`--fix`)** with hermetic `ENV` flags and build-time `RUN` pre-warming commands (`tiktoken`, `chromadb` ONNX `all-MiniLM-L6-v2`, `fastembed`, `huggingface_hub`, `nltk`, `spacy`, `whisper`, `playwright`) that works in any standard Docker or Kubernetes pipeline.

---

## Empirical Benchmark: We Ran 20 Open-Source AI Repositories Under `docker run --network none`

To avoid overfitting static rules to a single codebase, we evaluated `airgap-check` in two phases:
- **Phase 1 (Calibration Set — 10 Repositories):** Used to discover real runtime failure modes and calibrate false-positive filters (`devDependencies` vs `dependencies`, Python-only `tiktoken` vs bundled JS `js-tiktoken`, local signing keys vs wire API keys).
- **Phase 2 (Out-of-Sample Holdout Set — 10 Unseen Repositories):** Rules were **frozen** (`commit 8ce2f11`) and tested against 10 new, unseen AI repositories alongside real `docker run --rm --network none` execution.

### Top Runtime Surprises Observed Under `--network none`

| Library / Call | What Happens in `--network none` | Hidden Egress Destination | Measured Failure Time |
| :--- | :--- | :--- | :--- |
| **`fastembed` (`TextEmbedding()`)** | Hangs on 3 exponential retries (`3s + 9s + 27s`) before raising `ValueError: Could not load model` | `huggingface.co:443` / `storage.googleapis.com` | **39,200 ms** (hang + crash) |
| **`huggingface_hub` (`hf_hub_download()`)** | Retries HTTP metadata checks with backoff before raising `LocalEntryNotFoundError` | `huggingface.co:443` | **23,523 ms** (hang + crash) |
| **`chromadb` (`collection.add()`)** | Default embedding function downloads `all-MiniLM-L6-v2` (`onnx.tar.gz`) via `httpx` | `chroma-onnx-models.s3.amazonaws.com:443` | **581–662 ms** (`ConnectError` crash) |
| **`tiktoken` (`get_encoding("cl100k_base")`)** | Fetches `.tiktoken` BPE rank file over HTTPS on first tokenization call | `openaipublic.blob.core.windows.net:443` | **343–557 ms** (`ConnectionError` crash) |
| **`nltk` (`nltk.download("punkt")`)** | Attempts to fetch XML index & corpus zip at runtime | `raw.githubusercontent.com:443` | **477 ms** (`False` / `LookupError` crash) |
| **`playwright` (`chromium.launch()`)** | Fails immediately if headless browser binary was not baked into `PLAYWRIGHT_BROWSERS_PATH` | `playwright.azureedge.net:443` | **702 ms** (`Error: Executable doesn't exist`) |
| **`litellm` (`get_model_cost_map()`)** | Pulls live model pricing JSON from GitHub unless `LITELLM_LOCAL_MODEL_COST_MAP=True` | `raw.githubusercontent.com:443` | **234 ms** (fallback warning / delay) |
| **`crewai` / `chromadb` telemetry** | Spawns background OTLP / PostHog threads on startup unless disabled via `ENV` | `telemetry.crewai.com:4319`, `us.i.posthog.com:443` | Background thread timeout |

---

### Out-of-Sample Holdout Evaluation (10 Unseen AI Repositories, Frozen Rules)

After freezing the rule set, we ran `airgap-check` against 10 unseen repositories (`chat-langchain`, `docling`, `gpt-engineer`, `gpt-researcher`, `litellm`, `llama_index`, `mem0`, `pydantic-ai`, `quivr`, `vanna`) and compared static predictions against ground-truth manifest inspection and `docker run --rm --network none` execution:

| Holdout Repository | Scanned Scope | Static Crash Findings (Frozen Rules) | `--network none` Dynamic Verification (`UDP:53` + Socket Capture) | Component-Level Classification (TP / FP / FN) |
| :--- | :--- | :--- | :--- | :--- |
| **`gpt-engineer`** | 1 manifest, 61 src files | `tiktoken` (`pyproject.toml`, `token_usage.py`) | `exit=1` (**343 ms**) — `dns_udp53` & `dns_getaddrinfo` -> `openaipublic.blob.core.windows.net` | **1 TP**, 0 FP, 0 FN |
| **`gpt-researcher`** | 14 manifests, 317 src files | `tiktoken`, `nltk`, `playwright`, `next/font/google` (+ `langsmith` telemetry) | `exit=1` (**477 ms**) — `dns_udp53` -> `raw.githubusercontent.com`, `openaipublic.blob.core.windows.net` | **4 TP**, 0 FP, 0 FN |
| **`llama_index`** | 722 manifests, 2,175 src files | `tiktoken`, `nltk`, `fastembed`, `sentence-transformers`, `transformers`, `chromadb`, `whisper`, `playwright` | `exit=1` (**557 ms**) — `dns_udp53` -> `openaipublic.blob.core.windows.net` | **8 TP**, 0 FP, **2 FN** (`flagembedding`, `paddleocr` in integration packages) |
| **`mem0`** | 24 manifests, 709 src files | `chromadb`, `fastembed`, `sentence-transformers`, `transformers`, `spacy`, `next/font/google` (+ `posthog` telemetry) | `exit=1` (**662 ms**) — `dns_udp53` -> `chroma-onnx-models.s3.amazonaws.com` | **6 TP**, 0 FP, 0 FN |
| **`vanna`** | 3 manifests, 316 src files | `chromadb`, `fastembed`, `transformers`, `from_pretrained()` | `exit=1` (**581 ms**) — `dns_udp53` -> `chroma-onnx-models.s3.amazonaws.com` | **4 TP**, 0 FP, 0 FN |
| **`quivr`** | 41 manifests, 785 src files | `from_pretrained/hf_hub_download`, `sentence-transformers`, `transformers` | `exit=1` (**23,523 ms**) — `dns_udp53` -> `huggingface.co` (exponential retry hang) | **3 TP**, 0 FP, 0 FN |
| **`docling`** | 3 manifests, 416 src files | `from_pretrained/snapshot_download`, `transformers`, `whisper`, `playwright` | `exit=1` (**400 ms**) — `dns_udp53` -> `huggingface.co` | **3 TP**, **1 FP** (`playwright` in dev group), **2 FN** (`easyocr`, `rapidocr` model downloads) |
| **`litellm`** | 90 manifests, 7,169 src files | `tiktoken`, `from_pretrained()`, `next/font/google`, `playwright` (+ `sentry-sdk`) | `exit=1` (**234 ms**) — `dns_udp53` -> `raw.githubusercontent.com` | **3 TP**, **1 FP** (`playwright` in proxy extras), **1 FN** (`model_prices_and_context_window.json` fetch) |
| **`pydantic-ai`** | 10 manifests, 1,485 src files | `tiktoken`, `sentence-transformers`, `transformers`, `playwright` (+ `langsmith`, `posthog`) | `exit=1` (**357 ms**) — `dns_udp53` -> `openaipublic.blob.core.windows.net` | **3 TP**, **2 FP** (`playwright` in dev group; `posthog` extra name in harness), 0 FN |
| **`chat-langchain`** | 2 manifests, 50 src files | 0 local asset crash risks (+ `langsmith` browser & server telemetry) | `exit=0` (**137 ms**) — 0 local asset downloads | **1 TN** (crash), **2 TP** (telemetry), 0 FP, 0 FN |

#### Holdout Summary Metrics (Component-Level Crash & Telemetry Detection)
- **Repository-Level Offline Crash Detection:** **9 / 9** repositories with offline runtime downloaders identified (**100% repo-level recall**), **1 / 1** true negative (`chat-langchain`).
- **Component-Level True Positives (TP):** **35** verified runtime downloader / telemetry components across the 10 unseen repositories.
- **Component-Level False Positives (FP):** **4** (`89.7%` precision).
  - *Root cause of all 4 FPs:* While `package.json` is parsed into AST to strip `devDependencies`, `pyproject.toml` was scanned as text, causing dev/test dependency groups (`playwright` in `docling` and `pydantic-ai`) or optional extras names (`posthog = ["pydantic-ai-slim[mcp]"]`) to trigger static warnings.
- **Component-Level False Negatives (FN):** **5** (`87.5%` component-level recall).
  - *Root cause of the 5 FNs:* OCR weight downloaders (`easyocr`, `rapidocr`, `paddleocr`), `FlagEmbedding`, and LiteLLM's startup GitHub JSON fetch (`model_prices_and_context_window.json`) were not in the frozen static rule table—demonstrating why **dynamic `--run` verification (`UDP:53` DNS capture)** is essential alongside static scanning.

---

## Installation

```bash
# Install with Go 1.22+ (zero external dependencies)
go install github.com/humanethq/airgap-check/cmd/airgap-check@latest

# Or build from source
git clone https://github.com/humanethq/airgap-check.git
cd airgap-check
make build
./bin/airgap-check --help
```

---

## Usage

### 1. Static Audit + Ready-to-Paste `Dockerfile` Remediation (`--fix`)
```bash
airgap-check --fix /path/to/your/repo
```
Generates a complete report of runtime downloaders, server vs. browser telemetry (`posthog-js` in frontend vs. `posthog`/`chromadb` in Python), `.env` credential classifications (`wire_api_key` vs. `local_signing_or_internal` like `JWT_SECRET_KEY` vs. `signed_request_flow` like `CLOUDINARY_API_SECRET`), and prints a **100% standalone `Dockerfile` block**:

```dockerfile
# --- BEGIN AIR-GAP & TELEMETRY REMEDIATION (paste into your Dockerfile) ---
# 1. Silence background SDK telemetry & enforce writable offline cache paths
ENV DO_NOT_TRACK=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    ANONYMIZED_TELEMETRY=False \
    CHROMA_TELEMETRY_IMPL=none \
    SCARF_NO_ANALYTICS=true \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    LANGCHAIN_TRACING_V2=false \
    CREWAI_DISABLE_TELEMETRY=true \
    OTEL_SDK_DISABLED=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    XDG_CACHE_HOME=/app/.cache \
    TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken \
    HF_HOME=/app/.cache/huggingface \
    NLTK_DATA=/app/.cache/nltk_data \
    PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright
RUN mkdir -p /app/.cache/tiktoken /app/.cache/huggingface /app/.cache/nltk_data /app/.cache/ms-playwright

# Pre-warm Python tiktoken BPE encodings (cl100k_base & o200k_base) at build time
RUN TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken python3 -c "import tiktoken; [tiktoken.get_encoding(e) for e in ('cl100k_base', 'o200k_base')]"

# Pre-warm ChromaDB default ONNX embedding model (all-MiniLM-L6-v2) at build time
RUN HOME=/app XDG_CACHE_HOME=/app/.cache python3 -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ef = ONNXMiniLM_L6_V2(); ef(['airgap-warmup'])"
# --- END AIR-GAP & TELEMETRY REMEDIATION ---
```

### 2. Dynamic Verification Inside `docker run --rm --network none` (`--run`)
```bash
# Run with default ecosystem image or pass your built application image:
airgap-check --run --image my-app:latest --run-cmd "python3 -m pytest tests/smoke_test.py" /path/to/repo
```

#### How Dynamic Capture Works (and Its Exact Boundaries)
When `--run` is invoked, `airgap-check` launches a container with **kernel-isolated `--network none`** (zero external network interfaces) and mounts a read-only observer into `/tmp/airgap_hook`:
- **Language-Agnostic `UDP:53` DNS Sinkhole (`127.0.0.1:53`):** Binds `127.0.0.1:53/udp` inside the container network namespace and points `/etc/resolv.conf` to `nameserver 127.0.0.1`. Any DNS lookup—whether from Python, Node.js, Go, Rust, C/C++ native extensions (`onnxruntime`, `libcurl`), or subprocesses (`curl`, `getent`)—is recorded (`dns_udp53`) and immediately answered with `NXDOMAIN` so it fails fast and visibly.
- **Language Socket Hooks:** Injects `sitecustomize.py` (`socket.getaddrinfo`, `socket.connect`) and `node_preload.js` (`dns.lookup`, `net.Socket.connect`) to capture socket-level metadata.
- **Explicit Limitation:** Only code paths exercised by `--run-cmd` are dynamically tested, and raw hardcoded-IP TCP connections from static non-Python/Node binaries that bypass DNS require a custom `--internal` bridge.

---

## Security & Privacy Guarantees
- **Secret values are never read, stored, or logged.** `.env` files are inspected solely for key names, non-empty presence, and `git ls-files` tracking status.
- **Read-only workspace mount:** `airgap-check --run` mounts your repository `:ro` (`-v $PWD:/workspace:ro`) inside `--network none`.

---

## Built by the Team Behind [Frame by Humanet](https://humanet.dev)

`airgap-check` is open-sourced by [Humanet](https://humanet.dev). Move your AI apps into air-gapped environments using the `--fix` `Dockerfile` generator above in any standard Docker/Kubernetes stack.

If you want **zero-config Firecracker microVM isolation**, **automatic build-time cache sealing**, and **wire-level Phantom Secret injection** (where real API keys never enter guest VM memory and are swapped at the host proxy only for allowlisted hosts and HTTP methods), check out **[Frame](https://humanet.dev)**.
