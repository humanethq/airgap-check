# Benchmark Repositories & Execution Details

## Phase 1 & Phase 2 (`v0.1.0`, rules frozen at `8ce2f11`)

Tested on: **November 9, 2026**  
Rules frozen at commit: [`8ce2f11`](https://github.com/humanethq/airgap-check/commit/8ce2f11e5f411e18d8137217dd3b0f3727b4e12d)

### Phase 1: Calibration Set (10 Repositories)

Used during initial development to identify failure modes and calibrate false-positive filters (e.g. ignoring `devDependencies` in `package.json`, restricting `tiktoken` to Python, separating wire API keys from local signing secrets).

| Repository | Upstream URL | Commit SHA | Date Tested | Ecosystem |
| :--- | :--- | :--- | :--- | :--- |
| `ai-chatbot` | `https://github.com/vercel/ai-chatbot.git` | `a8989b522fa3672a2ae52f053105e40993b36ca1` | 2026-11-03 | Next.js / TypeScript |
| `chat-ui` | `https://github.com/huggingface/chat-ui.git` | `cdf3781e0a19bc6f451e5a234d6dc8d4c28ef37b` | 2026-11-05 | SvelteKit / TypeScript |
| `cookbook` | `https://github.com/chainlit/cookbook.git` | `218e4f9a1837a46fcaaf40b3ca3033d71b7fe66e` | 2025-08-25 | Python |
| `courses` | `https://github.com/anthropics/courses.git` | `f4dbb137d7b02dddaf3cc73e32e20a702d3b5e77` | 2025-11-13 | Python / Jupyter |
| `crewAI-examples` | `https://github.com/crewAIInc/crewAI-examples.git` | `da94a91e691e1cf5b3151416bb15b5b62729bea8` | 2026-04-20 | Python |
| `firecrawl-app-examples` | `https://github.com/mendableai/firecrawl-app-examples.git` | `d87799964f7bc78bf4784615d7fabc53af022b19` | 2026-01-13 | TypeScript / Python |
| `langchain-nextjs-template`| `https://github.com/langchain-ai/langchain-nextjs-template.git` | `dfc6ce4e7a8ce4b7934ec6d0b0f5a7820b8aaa3b` | 2026-11-07 | Next.js / TypeScript |
| `llm-examples` | `https://github.com/streamlit/llm-examples.git` | `7cf260745675e41f92e72e7436d3777aafdab9dad9f` | 2025-12-08 | Streamlit / Python |
| `openai-realtime-console` | `https://github.com/openai/openai-realtime-console.git` | `ab8b8f5852b47ec1b9ef73bf566851d0eeafddbb` | 2025-08-28 | React / TypeScript |
| `rags` | `https://github.com/run-llama/rags.git` | `4bec27023950c078fe0d559e1720d757d0024c93` | 2023-12-04 | Streamlit / Python |

### Phase 2: Held-Out Evaluation Set (v0.1.0, 10 Repositories)

`v0.1.0` rules were frozen prior to evaluating these repositories. Each repository was scanned statically with `airgap-check` (`8ce2f11`) and dynamically executed inside a container with `--network none` (`NXDOMAIN` DNS refusal) using `airgap-eval-py:latest` running a probe call exercising the flagged library functions.

| Repository | Upstream URL | Commit SHA | Probe Command Executed Under `--network none` | Probe Result & Measured Time (`v0.1.0`, `NXDOMAIN`) | Intercepted Host(s) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gpt-engineer` | `https://github.com/gpt-engineer-org/gpt-engineer.git` | `a90fcd543eedcc0ff2c34561bc0785d2ba83c47e` | `python3 -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"` | exit 1 (343 ms) | `openaipublic.blob.core.windows.net` |
| `gpt-researcher` | `https://github.com/assafelovic/gpt-researcher.git` | `b81060b2d5f382b30a0ea9d95bf799fd9835c34e` | `python3 -c "import tiktoken, nltk; nltk.download('punkt'); tiktoken.get_encoding('cl100k_base')"` | exit 1 (477 ms) | `raw.githubusercontent.com`, `openaipublic.blob.core.windows.net` |
| `llama_index` | `https://github.com/run-llama/llama_index.git` | `444fdf0684707de62ebb447d658dba137dd9cb99` | `python3 -c "import tiktoken, nltk; tiktoken.get_encoding('cl100k_base')"` | exit 1 (557 ms) | `openaipublic.blob.core.windows.net` |
| `mem0` | `https://github.com/mem0ai/mem0.git` | `f1791daa86d469249c9b002f62644d58a1eb96a0` | `python3 -c "import chromadb; c = chromadb.Client(); col = c.create_collection('mem0_col'); col.add(documents=['hello'], ids=['1'])"` | exit 1 (662 ms) | `chroma-onnx-models.s3.amazonaws.com` |
| `vanna` | `https://github.com/vanna-ai/vanna.git` | `365d0617c1a4567ffee1b19b40c27feb4206bfcf` | `python3 -c "import chromadb; c = chromadb.Client(); col = c.create_collection('vanna_col'); col.add(documents=['sql'], ids=['1'])"` | exit 1 (581 ms) | `chroma-onnx-models.s3.amazonaws.com` |
| `quivr` | `https://github.com/QuivrHQ/quivr.git` | `bb1b19ecf4094dbd1e309e521ce8b5fed4fb539f` | `python3 -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='BAAI/bge-small-en-v1.5', filename='config.json')"` | exit 1 (23,523 ms) | `huggingface.co` (retry timeout) |
| `docling` | `https://github.com/DS4SD/docling.git` | `896f2fd973d0b0b43b2adfd73e2f51c75210ddd2` | `python3 -c "from huggingface_hub import snapshot_download; snapshot_download('ds4sd/docling-models')"` | exit 1 (400 ms) | `huggingface.co` |
| `litellm` | `https://github.com/BerriAI/litellm.git` | `2f430873aead937b9112e683703956eb1ab179af` | `python3 -c "import urllib.request; urllib.request.urlopen('https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json', timeout=3)"` | exit 1 (234 ms) | `raw.githubusercontent.com` |
| `pydantic-ai` | `https://github.com/pydantic/pydantic-ai.git` | `c9c896e9f097362c69cabf5312d345155aec9625` | `python3 -c "import tiktoken; tiktoken.encoding_for_model('gpt-4o')"` | exit 1 (357 ms) | `openaipublic.blob.core.windows.net` |
| `chat-langchain` | `https://github.com/langchain-ai/chat-langchain.git` | `1a5fbe967b47bdc5d5f142c515fd8bc0b185bd81` | `python3 -c "print('chat-langchain-offline-probe')"` | exit 0 (137 ms) | None (clean of runtime downloads) |

### Phase 2 v0.2.0 Re-Run (Design Verification Only, Not Out-of-Sample)

> **Note:** These 10 Phase 2 repositories were used to design the `v0.2.0` fixes, so the measurements below are in-sample checks on the design set rather than out-of-sample scores. See **Phase 3** below for fresh out-of-sample validation.

| Repository | Scan Time | Source Files | Manifests / Lockfiles | Runtime Crash Findings (`prod` / `transitive_lockfile` / `source_call`) | Optional Extras (`optional_extra`) | Behavioral Findings (beyond rule table) | Telemetry Findings |
| :--- | :-: | :-: | :-: | :--- | :--- | :--- | :--- |
| `gpt-engineer` | 0.01 s | 41 | 2 / 1 | `tiktoken` (`prod`, `source_call`), `huggingface-hub` (`transitive_lockfile` via `datasets`) | — | — | `langsmith` (`transitive_lockfile`) |
| `gpt-researcher` | 0.09 s | 294 | 11 / 0 | `tiktoken`, `nltk`, `litellm`, `huggingface-hub`, `ml-weight-downloader`, `next/font/google` | `playwright` (`[extra: requirements-txt]`) | `pip install` subprocess (`llm_provider/generic/base.py:415`) | `langsmith` (`prod`) |
| `llama_index` | 1.65 s | 2,133 | 715 / 602 | `tiktoken`, `nltk`, `fastembed`, `sentence-transformers`, `huggingface-hub`, `litellm`, `transformers`, `FlagEmbedding`, `chromadb`, `ml-weight-downloader`, `paddleocr`, `playwright`, `whisper`, `spacy` (`transitive_lockfile`), `rapidocr` (`transitive_lockfile`) | — | `huggingface.co` GGUF URL (`llama_cpp/base.py:78`), `~/.cache` write (`legacy_office/reader.py`) | `langfuse`, `wandb`, `chromadb`, `langsmith`, `sentry-sdk`, `opentelemetry-exporter-otlp`, `gradio`, `posthog` |
| `mem0` | 0.35 s | 589 | 18 / 11 | `fastembed`, `huggingface_hub`, `transformers` (`mem0-ts/pnpm-lock.yaml`) | `spacy`, `chromadb`, `litellm`, `sentence-transformers`, `fastembed` | `ollama pull` subprocess (`_setup.py:386`) | `posthog` (`prod`), `langsmith` (`transitive_lockfile`), `chromadb` (`optional_extra`) |
| `vanna` | 0.13 s | 290 | 2 / 0 | `fastembed`, `huggingface_hub` (`source_call`) | `chromadb`, `fastembed`, `transformers` (`[extra: all]`) | — | `chromadb` (`[extra: all]`) |
| `quivr` | 0.31 s | 755 | 36 / 2 | `huggingface-hub`, `sentence-transformers`, `transformers` | — | — | — |
| `docling` | 0.21 s | 338 | 3 / 1 | `huggingface-hub`, `whisper`, `easyocr.Reader()`, `RapidOCR()`, `ml-weight-downloader`, `rapidocr` (`transitive_lockfile`), `transformers` (`transitive_lockfile`) | `playwright`, `whisper`, `easyocr` | — | — |
| `litellm` | 3.40 s | 5,732 | 85 / 5 | `tiktoken` (`Cargo.toml` + `pyproject.toml` + `source_call`), `huggingface-hub`, `next/font/google` | — | `raw.githubusercontent.com` cost map (`litellm/__init__.py:411`, `policy.rs:20`), `pip install` (`supabase.py:24`, `litellm_logging.py:5591`) | `langfuse`, `opentelemetry-exporter-otlp`, `ddtrace`, `sentry-sdk` (`[extra: proxy-runtime]`) |
| `pydantic-ai` | 0.98 s | 1,130 | 8 / 2 | `tiktoken` (`uv.lock` via `pydantic-ai-slim[openai]`) | `huggingface-hub`, `sentence-transformers`, `playwright` (`pydantic_ai_harness`) | — | `opentelemetry-exporter-otlp` (`uv.lock`) |
| `chat-langchain` | 0.03 s | 92 | 2 / 1 | — (0 runtime downloads) | — | — | `langsmith` (`browser_client` + `server_runtime`) |

---

## Phase 3: Fresh Out-of-Sample Held-Out Set (`v0.2.1`, rules frozen at `47b2ddc`)

Tested on: **November 10, 2026**  
Rules frozen BEFORE cloning or scanning any repository: [`47b2ddc`](https://github.com/humanethq/airgap-check/commit/47b2ddccb1c243c100f86e6579a07e75fb130721)

### Phase 3 Static Breakdown & Scoring (`47b2ddc`)

| Repository | Upstream URL | Commit SHA | Scan Time | Source Files | Manifests / Lockfiles | Runtime Crash Findings (`airgap_crash_risks`) | Behavioral Findings | Advisory Robustness Hints (`timeout=` omitted, not scored) | Telemetry (not scored) | TP | FP | FN |
| :--- | :--- | :--- | :-: | :-: | :-: | :--- | :--- | :-: | :--- | :-: | :-: | :-: |
| `smolagents` | `https://github.com/huggingface/smolagents.git` | `96f33faaf028479119ec8d34507b47694cf14e34` | 0.05 s | 18 | 1 / 0 | `huggingface-hub` (`prod`), `litellm` (`optional_extra`), `transformers` (`optional_extra`), `agents.py` `snapshot_download()`, `models.py` `from_pretrained()`, `tools.py` `hf_hub_download()`, `_function_type_hints_utils.py:159` docstring `from_pretrained()` *(FP)* | — | 3 | `gradio`, `opentelemetry-exporter-otlp` | 6 | 1 | 0 |
| `crawl4ai` | `https://github.com/unclecode/crawl4ai.git` | `cae74b203a33994f7e13b9052c3b0d5c93daa0e6` | 0.15 s | 109 | 3 / 1 | `model_loader.py` (`from_pretrained`, `nltk.download`), `table_extraction.py` (`encoding_for_model`), `playwright`, `nltk`, `huggingface-hub`, `litellm`, `tiktoken` (`uv.lock`), `transformers`, `sentence-transformers` (`[extra: transformer]`) | *(missed multi-line `git clone` in `model_loader.py:219` + `spacy.load`: 2 FN)* | 4 | — | 10 | 0 | 2 |
| `aider` | `https://github.com/Aider-AI/aider.git` | `5dc9490bb35f9729ef2c95d00a19ccd30c26339c` | 0.09 s | 104 | 6 / 0 | `huggingface-hub`, `tiktoken`, `litellm`, `nltk`, `sentence-transformers`, `transformers`, `playwright` | *(missed split-string `MODEL_INFO_URL` in `aider/models.py:162`: 1 FN)* | 2 | `posthog` (`prod`) | 7 | 0 | 1 |
| `open-webui` | `https://github.com/open-webui/open-webui.git` | `b0e6098e940942281d9c83f3529ea117287a3a22` | 0.59 s | 475 | 5 / 3 | `RapidOCR()`, `snapshot_download` (`utils.py`), `from_pretrained` (`retrieval.py`), `tiktoken.get_encoding()`, `KokoroTTS.from_pretrained` (`kokoro.worker.ts`), `tiktoken`, `chromadb`, `transformers`, `sentence-transformers`, `unstructured` (`ml-weight-downloader`), `rapidocr`, `faster-whisper`, `playwright`, `huggingface-hub` (`uv.lock`) | *(missed `spacy` transitive under `unstructured` in `uv.lock`, and `kokoro-js` in `package.json`: 2 FN)* | 26 | `opentelemetry-exporter-otlp`, `chromadb`, `langsmith` | 14 | 0 | 2 |
| `browser-use` | `https://github.com/browser-use/browser-use.git` | `070be98109c03f04a95f704533e8f6e9868d0525` | 0.05 s | 45 | 1 / 1 | `tiktoken` (`uv.lock` via `pydantic-ai-slim[openai]`) | — | 0 | *(stdlib `urllib` PostHog in `telemetry/service.py`)* | 1 | 0 | 0 |
| `markitdown` | `https://github.com/microsoft/markitdown.git` | `ed178952a6672abdfd35b5f9e76a80b6cefc086e` | 0.02 s | 55 | 4 / 0 | — (0 runtime downloads; `magika` bundles ONNX weights in wheel) | — | 0 | — | 0 | 0 | 0 |
| `crewAI` | `https://github.com/crewAIInc/crewAI.git` | `135eee13990a6e4ffbd9bf0152d249ebdc35a528` | 0.30 s | 979 | 14 / 1 | `fastembed` (`qdrant/config.py`), `chromadb`, `tiktoken`, `huggingface-hub` (`uv.lock`), `litellm`, `unstructured`, `nltk`, `playwright`; plus `TextEmbeddingModel.from_pretrained()` Vertex AI SDK *(FP)* | `crewai_cli/constants.py:352` + `crewai/constants.py:357` cost-map URL, 3 `uv pip install` calls; plus private `devtools/litellm_catalog_update.py` *(FP)* and `arxiv_paper_tool.py` `urlretrieve()` *(FP)*. *(missed `[extra: docling]` + `spacy`: 2 FN)* | 1 | `opentelemetry-exporter-otlp`, `chromadb`, `crewai` | 13 | 3 | 2 |
| `openai-agents-python` | `https://github.com/openai/openai-agents-python.git` | `d68961657843c7d81dfc25834484f8aac2957eb3` | 0.19 s | 321 | 1 / 1 | `litellm` (`pyproject.toml [extra: litellm]`; dev `playwright` cleanly skipped) | — | 1 | — | 1 | 0 | 0 |
| `servers` | `https://github.com/modelcontextprotocol/servers.git` | `36380287ed3b15d115b55f546617d723072b1296` | 0.03 s | 83 | 8 / 4 | — (0 runtime downloads across all 7 MCP servers) | — | 0 | — | 0 | 0 | 0 |
| `instructor` | `https://github.com/jxnl/instructor.git` | `aeb7e2558166caeec497e541bcfc6b4eaa2cf53b` | 0.06 s | 238 | 4 / 1 | `litellm` (`pyproject.toml [extra: litellm]`) | — | 0 | — | 1 | 0 | 0 |

**Phase 3 Total (out-of-sample, frozen `47b2ddc`):** `53 TP`, `4 FP`, `7 FN` -> **93.0% precision**, **88.3% recall**.  
Moving HTTP `timeout=` omissions into `robustness_hints` kept all `37` hints (`26` in `open-webui`, `4` in `crawl4ai`, `3` in `smolagents`, `2` in `aider`, `1` in `crewAI`, `1` in `openai-agents-python`) from dropping out-of-sample precision from **93.0%** (`53/57`) to **56.4%** (`53/94`).

### Phase 3 Dynamic `--run` Probe Execution (`--dns-action sinkhole`, `--network none`)

| Repository | Probe Command Executed (`airgap-check --run`) | Image / Observer | Exit & Measured Time (`sinkhole`) | Observed Protocol & Host(s) |
| :--- | :--- | :--- | :--- | :--- |
| `aider` | `python3 -c "import tiktoken; tiktoken.get_encoding('cl100k_base')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (358 ms) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `openaipublic.blob.core.windows.net` |
| `browser-use` | `python3 -c "import tiktoken; tiktoken.encoding_for_model('gpt-4o')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (212 ms) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `openaipublic.blob.core.windows.net` |
| `crawl4ai` | `python3 -c "import nltk, tiktoken; nltk.download('punkt'); tiktoken.get_encoding('cl100k_base')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (345 ms) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `raw.githubusercontent.com`, `openaipublic.blob.core.windows.net` |
| `crewAI` | `python3 -c "import chromadb; c = chromadb.Client(); col = c.create_collection('crewai_col'); col.add(documents=['hello'], ids=['1'])"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (592 ms) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `chroma-onnx-models.s3.amazonaws.com` |
| `instructor` | `python3 -c "import openai, pydantic; print('instructor-core-offline-probe')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 0 (417 ms) | None (core prod deps clean offline) |
| `markitdown` | `python3 -c "print('markitdown-core-offline-probe')"` *(plus separate `python:3.12-slim-bookworm` `MarkItDown().convert_stream` verification with `magika==1.0.3`)* | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 0 (163 ms) | None (clean offline) |
| `open-webui` | `python3 -c "import chromadb; c = chromadb.Client(); col = c.create_collection('owui_col'); col.add(documents=['hello'], ids=['1'])"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (557 ms) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `chroma-onnx-models.s3.amazonaws.com` |
| `openai-agents-python` | `python3 -c "import openai, pydantic; print('openai-agents-core-offline-probe')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 0 (419 ms) | None (core prod deps clean offline) |
| `servers` | `node -e "console.log('mcp-servers-offline-probe')"` | `node:20-bookworm-slim` (`node+udp53+sni`) | exit 0 (153 ms) | None (clean offline) |
| `smolagents` | `python3 -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-small-en-v1.5')"` | `airgap-eval-py:latest` (`python3+udp53+sni`) | exit 1 (293 ms; 477 ms under `--dns-action nxdomain`) | `dns_getaddrinfo`, `dns_udp53`, `tls_sni`: `huggingface.co` |

### Dynamic Observer E2E Checks (`docker run --rm --network none`)

In addition to the probe tests above, `go test -v ./...` verifies unknown-host capture directly via container loopback sinkholes (no dependency on package rules):
- `TestStandaloneDynamicUnderNetworkNone`: Python subprocess `/usr/bin/getent` DNS lookup + plain HTTP (`?token=` stripped) + HTTPS TLS ClientHello SNI captured inside `python:3.12-slim-bookworm`.
- `TestNodeOnlyDynamicUnderNetworkNone`: Pure Node.js HTTP + HTTPS `ClientHello` SNI capture inside `node:20-bookworm-slim` (`observer=node+udp53+sni`).
- `TestDynamicNxdomainAndDockerfileBuild`: `--build` temporary Dockerfile image build + `--network none` SNI capture, plus `--dns-action nxdomain` immediate `DNS_RESOLUTION_BLOCKED_IN_AIRGAP` verification.
