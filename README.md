# Humanet airgap-check

Find out what your AI app downloads, or tries to reach, when the network goes away.

![airgap-check](docs/banner.png)

![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

## Why

A common assumption: point the LLM base URL at a local vLLM or Ollama instance and the app is ready for an offline network (an air-gapped VPC, a hospital or defense network, a container with no internet). In practice, many libraries fetch something on first use: tokenizer ranks, ONNX embedding weights, corpora, price maps, or telemetry. Offline, these calls either fail at first use or hang for tens of seconds on retry backoff.

None of this is a bug in those libraries. They download once and cache. It only becomes visible when the network is gone. airgap-check tries to surface it before you deploy.

## What it does

- **Static scan.** Reads manifests (`requirements.txt`, `pyproject.toml`, `package.json`, `Cargo.toml`), looks for code patterns (`nltk.download()`, `from_pretrained()`, `tiktoken.get_encoding()`, `whisper.load_model()`, `next/font/google`) and classifies `.env` keys. It reads key names only; secret values are never read or logged.
- **`--run`.** Runs your app in `docker run --rm --network none` with a DNS sinkhole and socket hooks, and logs every lookup and connection attempt.
- **`--fix`.** Prints Dockerfile lines (offline `ENV` flags and build-time pre-warming commands) that you can adapt for your own image.

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

# use your own image and a smoke test that exercises your code paths
airgap-check --run --image my-app:latest --run-cmd "python3 -m pytest tests/smoke_test.py" /path/to/repo

# machine-readable output
airgap-check --json /path/to/repo
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
    CREWAI_DISABLE_TELEMETRY=true \
    OTEL_SDK_DISABLED=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    XDG_CACHE_HOME=/app/.cache \
    TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken \
    HF_HOME=/app/.cache/huggingface \
    NLTK_DATA=/app/.cache/nltk_data \
    PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright
RUN mkdir -p /app/.cache/tiktoken /app/.cache/huggingface /app/.cache/nltk_data /app/.cache/ms-playwright

# Pre-warm Python tiktoken encodings at build time
RUN TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken python3 -c "import tiktoken; [tiktoken.get_encoding(e) for e in ('cl100k_base', 'o200k_base')]"

# Pre-warm ChromaDB's default ONNX embedding model at build time
RUN HOME=/app XDG_CACHE_HOME=/app/.cache python3 -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ef = ONNXMiniLM_L6_V2(); ef(['airgap-warmup'])"
# --- END AIR-GAP & TELEMETRY REMEDIATION ---
```

## How `--run` works, and where it stops

`--run` starts a container with `--network none`, mounts your repository read-only, and mounts a small observer:

- A DNS sinkhole on `127.0.0.1:53/udp`. `/etc/resolv.conf` points to it, so lookups that go through the container's resolver are recorded and answered with `NXDOMAIN`.
- Python (`sitecustomize.py`) and Node (`node_preload.js`) hooks that record socket-level attempts.

Limits:

- We validated `--run` on Python and Node targets. Other runtimes should be caught if they use the system resolver, but we have not verified that.
- Traffic to hardcoded IP addresses, or DNS-over-HTTPS, skips the resolver and is not caught.
- Only the code paths you exercise are tested. Use `--run-cmd` to run a smoke test that covers the paths you care about.
- The sinkhole refuses immediately. In a real enclave, packets may be dropped instead, so hangs can be longer than the times below.

## Benchmark

We ran airgap-check on 20 open-source Python and TypeScript AI repositories in two phases. Phase 1 (10 repos) was used to find failure modes and tune the rules. Phase 2 (10 repos) is a held-out set: the rules were frozen at commit `8ce2f11` before we ran it.

Under `--network none`, we executed each repository's core entrypoint or probe call exercising its declared dependencies (for example, `tiktoken.get_encoding('cl100k_base')` on `gpt-engineer`, default ChromaDB collection creation & insertion on `mem0` and `vanna`, Hugging Face model resolution on `docling` and `quivr`, and a baseline startup probe on `chat-langchain`). Exact commands, upstream URLs, and commit SHAs are documented in [`benchmark/REPOS.md`](benchmark/REPOS.md).

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

| Repository | Result under `--network none` | TP | FP | FN |
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

`chat-langchain` also had two telemetry findings, which are counted separately and are not part of the crash and download metrics below.

At component level: 35 true positives, 4 false positives, 5 false negatives. That is 89.7% precision and 87.5% recall. This is a small sample, so treat the numbers as rough. At repository level, all 9 repositories with first-use downloads were flagged, and `chat-langchain` was correctly flagged as clean.

False positives (all 4): `pyproject.toml` is scanned as text, so dev and test dependency groups (`playwright` in `docling`, `litellm`, `pydantic-ai`) and an optional extra named `posthog` triggered warnings. `package.json` is parsed, so its `devDependencies` are skipped.

False negatives (all 5): OCR weight downloaders (`easyocr`, `rapidocr`, `paddleocr`), `FlagEmbedding`, and LiteLLM's startup fetch of `model_prices_and_context_window.json` were not in the frozen rule table. `--run` is meant to catch this kind of miss, but only on the paths it exercises.

## Supported checks

| Category | Pattern | Host(s) | `--fix` |
| :--- | :--- | :--- | :--- |
| Runtime download | `tiktoken` (Python) | `openaipublic.blob.core.windows.net` | pre-warms `cl100k_base`, `o200k_base` |
| Runtime download | `chromadb` default embedder | `chroma-onnx-models.s3.amazonaws.com` | pre-warms `ONNXMiniLM_L6_V2` |
| Runtime download | `fastembed` | `huggingface.co`, `cdn-lfs.hf.co` | pre-warms the model cache |
| Runtime download | `sentence-transformers`, `transformers`, `from_pretrained()` | `huggingface.co`, `cdn-lfs.hf.co` | sets offline `ENV` flags; prints model snapshot template |
| Runtime download | `whisper.load_model()` | `openaipublic.azureedge.net` | pre-warms the checkpoint |
| Runtime download | `playwright` | `playwright.azureedge.net` | installs the browser into `PLAYWRIGHT_BROWSERS_PATH` |
| Runtime download | `nltk.download()` | `raw.githubusercontent.com` | pre-downloads corpora into `NLTK_DATA` |
| Runtime download | `spacy.cli.download()` | `raw.githubusercontent.com` | installs the model wheel at build time |
| Runtime download | `torch.hub.load()` | `github.com`, `download.pytorch.org` | flagged only; pre-populate `TORCH_HOME` manually |
| Build-time download | `next/font/google` | `fonts.googleapis.com`, `fonts.gstatic.com` | flagged only; suggests `next/font/local` |
| Server telemetry | `chromadb`, `crewai`, `langsmith`, `scarf` | PostHog, `telemetry.crewai.com`, `api.smith.langchain.com`, `scarf.sh` | sets the matching disable flags |
| Browser telemetry | `posthog-js`, `@sentry/*` in frontend code | PostHog, Sentry | flagged only; disable the SDK in your frontend code |
| `.env` keys | `OPENAI_*`, `ANTHROPIC_*`, `GEMINI_*`, `STRIPE_*`, `JWT_*`, `CLOUDINARY_*`, `AWS_SECRET*` and others | n/a | flagged only; classifies key names and git tracking status |

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
