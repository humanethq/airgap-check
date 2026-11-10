# Benchmark v2 Pre-Registration & Protocol (`benchmark/REPOS2.md`)

**Date Frozen:** `2026-11-10`  
**Analyzer Rules Frozen At:** [`47b2ddc`](https://github.com/humanethq/airgap-check/commit/47b2ddccb1c243c100f86e6579a07e75fb130721) (released as `v0.2.1` at [`6e2940f`](https://github.com/humanethq/airgap-check/commit/6e2940f))  
**Status:** **PRE-REGISTERED BEFORE CLONING OR SCANNING.** Detection rules (`*.go`) are frozen and MUST NOT be modified during this run. Misses or false positives discovered during evaluation will be logged for post-run triage rather than patched mid-run.

---

## 1. Pre-Registered Target Repositories (10) & Backups (3)

Upstream `HEAD` commit SHAs resolved live via `git ls-remote` on `2026-11-10` prior to cloning:

| # | Repository | Ecosystem | Role | Upstream URL | Pinned `HEAD` Commit SHA |
| :-: | :--- | :--- | :--- | :--- | :--- |
| 1 | `open-webui/open-webui` | Python + Svelte | Core target (heavy local AI app) | `https://github.com/open-webui/open-webui.git` | `b0e6098e940942281d9c83f3529ea117287a3a22` |
| 2 | `Mintplex-Labs/anything-llm` | Node / TS | Node `--run` target | `https://github.com/Mintplex-Labs/anything-llm.git` | `ace9dad3348b4d8a237b09978517ced2bd18e198` |
| 3 | `langgenius/dify` | Python + Next.js | Multi-service target | `https://github.com/langgenius/dify.git` | `a4d64bcdddf1f080ff61e53029c3f64474d48cf6` |
| 4 | `infiniflow/ragflow` | Python | Document processing / weights target | `https://github.com/infiniflow/ragflow.git` | `216e651b1a519b2a3f11d83cc874ef971d226397` |
| 5 | `deepset-ai/haystack` | Python | Framework target | `https://github.com/deepset-ai/haystack.git` | `1c32a82cc56426d3bdbae68c189f60ab77624e79` |
| 6 | `browser-use/browser-use` | Python | Browser automation + telemetry | `https://github.com/browser-use/browser-use.git` | `693ddd2069d50b41baa3dd48335c9a2265379db8` |
| 7 | `Aider-AI/aider` | Python CLI | CLI + `tiktoken`/`litellm` target | `https://github.com/Aider-AI/aider.git` | `5dc9490bb35f9729ef2c95d00a19ccd30c26339c` |
| 8 | `FlowiseAI/Flowise` | Node / TS | 2nd Node-heavy target | `https://github.com/FlowiseAI/Flowise.git` | `9291856d1ea4a4ceea9f8fef8ce14f4f6c81e8eb` |
| 9 | `openai/openai-agents-python` | Python | **Negative control 1** | `https://github.com/openai/openai-agents-python.git` | `d68961657843c7d81dfc25834484f8aac2957eb3` |
| 10 | `danny-avila/LibreChat` | Node / TS | **Negative control 2** (API client) | `https://github.com/danny-avila/LibreChat.git` | `f4154b649efa37e1345ccc517a4d8d1ed2178c82` |

### Backups (used only if a primary repository cannot build/install/run within the 20-minute cap)

| # | Repository | Upstream URL | Pinned `HEAD` Commit SHA |
| :-: | :--- | :--- | :--- |
| B1 | `Significant-Gravitas/AutoGPT` | `https://github.com/Significant-Gravitas/AutoGPT.git` | `9cb76f9026d388c9bf2e098af2beae1cc864f055` |
| B2 | `Unstructured-IO/unstructured` | `https://github.com/Unstructured-IO/unstructured.git` | `293d235cfcd5f5e89c3cc5ff85562005e182ae33` |
| B3 | `Cinnamon/kotaemon` | `https://github.com/Cinnamon/kotaemon.git` | `9ad3e4e49aa35b8acddd235918a5d9753c1cfdf9` |

---

## 2. Execution Protocol

1. **Frozen analyzer:** Run unmodified `airgap-check v0.2.1` (rules `47b2ddc`) across all clean clones pinned to the SHAs above.
2. **Hard time cap:** Maximum **20 minutes per repository** for environment prep + `(a)` + `(b)` + `--run`. If setup/build fails or exceeds 20 minutes, record the exact command, failure output, and elapsed time, and substitute the next backup repository (`AutoGPT`, `unstructured`, `kotaemon`) if applicable, without dropping the failure from reporting.
3. **Dual `--network none` measurements per repository (breaking circularity):**
   - **(a) Static-derived probe:** Probe command derived from `airgap-check` static findings.
   - **(b) Documented quickstart / import / CLI smoke test:** Derived strictly from the repository's `README.md` / quickstart / `package.json` `scripts` / `pyproject.toml` entrypoints, run inside `docker run --rm --network none`.
4. **Independent Ground Truth:** In addition to `airgap-check --run` (including Node `--run` coverage on `anything-llm`, `Flowise`, and `LibreChat`), execute `(b)` (and where relevant `(a)`) inside standalone containers with `strace -s 256 -f -e trace=connect,sendto,socket` under `docker run --rm --network none` (no `airgap-check` hooks loaded) to observe raw syscall-level DNS (`UDP:53`) and TCP connection attempts independently.

---

## 3. Pre-Registered FP / FN Criteria

### Evaluation Scope
- **Scored static categories:** `airgap_crash_risks` and `behavioral_findings`.
- **Unscored (reported separately):** `telemetry_leak_risks` (e.g. `posthog`, `langsmith`, `opentelemetry`), `robustness_hints` (advisory missing `timeout=`), `egress_and_secret_risks`, and `allowed_egress_manifest`.
- **Counting unit:** Every distinct entry emitted in `airgap_crash_risks` and `behavioral_findings` is scored once.

### Component-Level Definitions
- **True Positive (TP):** A scored finding that accurately identifies:
  1. A production, lockfile-transitive, browser-client, or documented-optional dependency in non-dev manifests whose offline first-use behavior fetches external runtime assets (weights, tokenizers, corpora, browser binaries, price maps) or fails offline; **or**
  2. A runtime call/subprocess/URL in non-test, non-comment, non-maintainer-devtool source code that triggers a runtime asset download, subprocess package install, or cache download offline.
  *(Verified via `(a)`/`(b)` `strace` execution or direct inspection of upstream library/source behavior.)*
- **False Positive (FP):** A scored finding that matches:
  1. Comments, docstrings, documentation/examples, test files, or maintainer-only scripts; **or**
  2. A dev-only dependency misclassified as production/runtime; **or**
  3. Code or a package that does **not** fetch external assets over the network at runtime (e.g. weights bundled inside the wheel/repo, purely remote managed-cloud API client handle such as Vertex AI `TextEmbeddingModel.from_pretrained`, or coincidental symbol name).
- **False Negative (FN):** Any offline-blocking runtime dependency download, runtime code download call, or network-requiring subprocess/asset fetch in non-dev manifests/lockfiles/production code — **or any external non-telemetry download observed via independent `strace` during `(b)`** — that is absent from `airgap_crash_risks` and `behavioral_findings`.

### Repo-Level Ground Truth Distinction
Static findings will also be contrasted side-by-side against `(b)` independent quickstart/import `strace` behavior (`crashes_immediately` vs `lazy_on_feature_use` vs `clean_offline`) so lazy vs eager startup failures are reported explicitly without circularity.

---

## 4. Frozen `v0.2.1` (`47b2ddc`) Benchmark v2 Results (Out-of-Sample)

All static scans and container runs below were executed using the unmodified `v0.2.1` analyzer (`47b2ddc`) pre-registered in Sections 1–3. Because `ragflow` (`Dockerfile` builds on `infiniflow/github_action_runner:latest` + multi-GB `infiniflow/ragflow_deps:latest` bind mounts) exceeded/was blocked within the 20-minute per-repo container budget (its codebase also migrated the backend engine from Python to Go with pre-baked weights), backup repository `B1` (`Significant-Gravitas/AutoGPT`) was executed dynamically in its place while `ragflow` remained statically evaluated and scored.

### 4.1 Static Findings & Component-Level Precision / Recall (`47b2ddc`, Out-of-Sample)

| # | Repository | Role | Source Files (`47b2ddc`) | Manifests / Lockfiles | `airgap_crash_risks` (`47b2ddc`) | `behavioral_findings` (`47b2ddc`) | Unscored Telemetry / Advisory Robustness | TP | FP | FN |
| :-: | :--- | :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| 1 | `open-webui` | Core heavy app | 475 | 5 / 3 | 14 | 0 | `3` tel / `26` rob | 14 | 0 | 4 |
| 2 | `anything-llm` | Node `--run` | 1,164 | 4 / 3 | 3 | 1 | `2` tel / `0` rob | 4 | 0 | 3 |
| 3 | `dify` | Python + Next.js | 7,749 | 59 / 3 | 8 | 0 | `6` tel / `0` rob | 7 | 1 | 2 |
| 4 | `ragflow` | Go rewrite (static only; container blocked) | 2,923 | 8 / 5 | 3 | 2 | `0` tel / `2` rob / `16` env | 0 | 5 | 0 |
| 5 | `haystack` | Python framework | 300 | 2 / 0 | 5 | 0 | `1` tel / `0` rob | 5 | 0 | 0 |
| 6 | `browser-use` | Browser + telemetry | 45 | 1 / 1 | 1 | 0 | `0` tel / `0` rob | 1 | 0 | 0 |
| 7 | `aider` | Python CLI | 104 | 6 / 0 | 7 | 0 | `1` tel / `2` rob | 7 | 0 | 2 |
| 8 | `Flowise` | 2nd Node target | 1,681 | 8 / 1 | 3 | 0 | `4` tel / `0` rob | 3 | 0 | 2 |
| 9 | `openai-agents-python` | **Negative control 1** | 321 | 1 / 1 | 1 | 0 | `0` tel / `1` rob | 1 | 0 | 4 |
| 10 | `LibreChat` | **Negative control 2** | 3,817 | 10 / 2 | 0 | 0 | `4` tel / `0` rob | 0 | 0 | 0 |
| B1 | `AutoGPT` | Backup 1 (dynamic replacement for `ragflow`) | 4,818 | 5 / 5 | 8 | 1 | `4` tel / `20` rob | 6 | 3 | 2 |

**Aggregate Out-of-Sample Scores (`v0.2.1` frozen `47b2ddc`):**
- **Pre-Registered Primary 10 (`#1–#10`, including `ragflow` static):** `42 TP`, `6 FP`, `17 FN` -> **87.5% precision**, **71.2% recall**.
- **Executable 10 (`#1–#3, B1, #5–#10`, substituting B1 `AutoGPT` for blocked `ragflow` container):** `48 TP`, `4 FP`, `19 FN` -> **92.3% precision**, **71.6% recall**.
- **All 11 Scanned Repositories (`#1–#10 + B1`):** `48 TP`, `9 FP`, `19 FN` -> **84.2% precision**, **71.6% recall**.

### 4.2 Triage of Every `v0.2.1` (`47b2ddc`) False Positive (`9` total) and False Negative (`19` total)

- **False Positives (`9` across 3 repos):**
  1. `dify` (`1`): `playwright [transitive_lockfile]` in `pnpm-lock.yaml` — `@playwright/test` (`devDependencies`) satisfied an optional `peerDependenciesMeta` edge on `next@16.4.5`.
  2. `ragflow` (`5`): 3 build/test/dev script findings (`deps/download_deps.py`, `scripts/gen_tokenizer_oracle.py`, `tools/scripts/download_dev_deps.py`), 1 asset URL inside build-prep script `deps/download_deps.py:88`, and 1 Go SHA-1 verification table entry (`expectedBpeHashes` in `internal/tokenizer/bpe_loader.go:61`, whose `localBpeLoader` is strictly disk-only and performs zero network I/O). *(Unscored `.env` FP: 3 LLM token-limit config keys in `docker/.env` containing `TOKEN`.)*
  3. `AutoGPT` (`3`): 2 standalone CLI eval scripts (`copilot/capabilities/eval/prefix.py` and `onboarding_dump/eval_corpus.py:41`), plus `spacy` in `classic/pyproject.toml` which directly pins `en-core-web-sm = { url = ... }` (verified `exit 0` offline with zero network calls in `(a)` and `strace`).
- **False Negatives (`19` across 7 repos):**
  1. `open-webui` (`4`): `spacy` transitive under `unstructured` in `uv.lock`, `kokoro-js` in `package.json`, runtime GitHub release check (`api.github.com`) in `backend/open_webui/main.py:2786` (observed live in `(b)` & `strace`), and runtime `subprocess.check_call([..., "-m", "pip", "install", ...])` in `backend/open_webui/utils/plugin.py:451`.
  2. `anything-llm` (`3`): `tesseract.js` in `collector/package.json` (verified failing exit 1 against `cdn.jsdelivr.net`), `langchainhub` transitive in `collector/yarn.lock`, and runtime `https://models.dev/api.json` fetch in `server/utils/helpers/modelPricing/index.js:70` (observed live in `(b)` `server_direct` & `strace`).
  3. `dify` (`2`): `nltk` inside `[tool.uv] default-groups = ["tools"]` in `api/pyproject.toml`, and `https://updates.dify.ai` in `api/configs/feature/__init__.py:948` (observed live in `(b)` & `strace`).
  4. `aider` (`2`): Split-line `MODEL_INFO_URL` (`raw.githubusercontent.com`) in `aider/models.py:163` and `pypi.org` version check in `aider/versioncheck.py:78` — both masked because multiline expression `"""..."""` strings inverted `v0.2.1`'s triple-quote docstring mask! Both confirmed live in `(b)` `aider --exit` & `strace`. *(Also `[tool.setuptools.dynamic.optional-dependencies]` mis-scoped 6 optional deps as `prod` in `v0.2.1`.)*
  5. `Flowise` (`2`): `langchainhub` in `packages/server/package.json` (verified exit 1 against `api.hub.langchain.com` in `(a)` & `strace`) and GitHub release check in `packages/ui/src/ui-component/dialog/AboutDialog.jsx:16`.
  6. `openai-agents-python` (`4`): `huggingface-hub` and `tiktoken` transitively under `[extra: litellm]` in `uv.lock`, `curl` installer hitting `api.github.com` in `src/agents/extensions/sandbox/blaxel/mounts.py:243`, and multi-line `subprocess.run(["git", "clone", ...])` in `src/agents/sandbox/util/github.py:22`.
  7. `AutoGPT` (`2`): `gtts` in `classic/pyproject.toml` and `gtts.gTTS()` in `classic/forge/forge/speech/gtts.py` (verified failing exit 1 against `translate.google.com` in `(b)` & `strace`).
- **Notable Unscored Observations in `v0.2.1`:** Custom stdlib telemetry senders without a third-party SDK (`browser-use` `eu.i.posthog.com` + detached `atexit` process; `haystack` `eu.posthog.com`; `dify` `otel.dify.ai` / `otel.dify.cn`; `openai-agents` `/v1/traces/ingest` hitting `api.openai.com` even when `OPENAI_BASE_URL` points to `127.0.0.1`; `aider` `us.i.posthog.com`) were confirmed via `--run` / `strace`, motivating `AnalyzeSourceTelemetryURLs` in `v0.2.2`. Frontend paths nested below root (e.g. `autogpt_platform/frontend/`) were also misclassified as `server_runtime` rather than `browser_client`.

### 4.3 Independent `(b)` Quickstart / Import vs `(a)` Probe Execution & `--run` Audit (`v0.2.1`)

All container measurements below were run inside `docker run --rm --network none`: independently via raw `strace -f` (`ENETUNREACH` against container resolver `192.168.65.7:53`) and via `airgap-check v0.2.1 --run` (`--dns-action sinkhole`, loopback `UDP:53` + TLS SNI + hooks).

| Repository | `(b)` Documented Quickstart / Import / CLI Behavior (`--network none` + `strace`) | Startup Offline Classification | `(a)` Static-Derived Probe Behavior (`airgap-check --run`, `sinkhole`) | Hosts Observed Dynamically |
| :--- | :--- | :--- | :--- | :--- |
| `open-webui` | `uvicorn` starts & seeds SQLite (`22,481 ms`, exit `137` at timeout) while attempting Hugging Face embedding resolution (`get_model_path`, `13,067 ms`, exit `0` fallback); `ChromaClient()` clean (`exit 0`, `3,836 ms`); `get_app_latest_release_version` fails to reach `api.github.com` (`14,842 ms`, exit `0`). | `crashes_immediately` on RAG/embedding feature boot unless pre-cached (`HF_HUB_OFFLINE=1`); core Chroma client clean | `tiktoken` (542 ms, exit 1), `chromadb` (1,317 ms, exit 1), `faster-whisper` (932 ms, exit 1), `unstructured` (2,500 ms, exit 1), `playwright` (570 ms, exit 1), `spacy` (2,455 ms, exit 1, missing wheel). *(Note: `rapidocr==3.10.0` bundled `PP-OCRv6_det_small.onnx`, passing blank-image probe `exit 0` in 1,253 ms; `rec`/`cls` fetch on text OCR.)* | `huggingface.co`, `openaipublic.blob.core.windows.net`, `chroma-onnx-models.s3.amazonaws.com`, `github.com`, `api.github.com` |
| `anything-llm` | Collector starts cleanly (`exit 0`, `3,229 ms`); Node backend (`server/index.js`) starts (`exit 0` under test stop, `5,371 ms`, **`SILENT_EGRESS_ATTEMPTED_AND_DROPPED`**) while asynchronously fetching **`models.dev`** (`modelPricing`) and **`raw.githubusercontent.com`** (`modelMap`); `prisma migrate` also hits `binaries.prisma.sh` if engines unbuilt (`3,501 ms`, exit `1`). | `lazy_on_feature_use` / background startup warnings (`models.dev`, `raw.githubusercontent.com`) | `tesseract.js` (`exit 1`, `502 ms`, `cdn.jsdelivr.net`), `@xenova/transformers` (`exit 1`, `391 ms`, `huggingface.co`); `js-tiktoken` clean offline (`exit 0`, `685 ms`) | `models.dev`, `raw.githubusercontent.com`, `cdn.jsdelivr.net`, `huggingface.co`, `binaries.prisma.sh` |
| `dify` | `flask db --help` (`10,989 ms`) & `import app` (`10,645 ms`) exit `0` clean (`strace` exit `0`); `check_version_update` attempts **`updates.dify.ai`** (`9,572 ms`, exit `0`); `CommunityTelemetryService` attempts `otel.dify.ai` & `otel.dify.cn` (`2,974 ms`, exit `0`). | `lazy_on_feature_use` (boot imports clean; version check & RAG tools hit network on call) | `tiktoken` (`496 ms`, exit `1`), `transformers` (`3,770 ms`, exit `1`), `chromadb` (`1,592 ms`, exit `1`), `unstructured` (`1,343 ms`, exit `1`), `nltk.download` (`691 ms`, `SILENT_EGRESS`, `raw.githubusercontent.com`), `nltk.data.find` (`1,052 ms`, exit `1`), `spacy` (`1,089 ms`, exit `1`) | `updates.dify.ai`, `otel.dify.ai`, `otel.dify.cn`, `openaipublic.blob.core.windows.net`, `huggingface.co`, `chroma-onnx-models.s3.amazonaws.com`, `packages.unstructured.io`, `github.com`, `raw.githubusercontent.com` |
| `ragflow` | **Skipped / blocked (20-min cap):** Multi-stage `Dockerfile` (`infiniflow/github_action_runner:latest` + `infiniflow/ragflow_deps:latest` multi-GB mounts) exceeded build constraints. Substituted by B1 `AutoGPT`. | `not_run_container_blocked` (Go `localBpeLoader` performs 0 network I/O by source inspection; deps pre-baked in image) | Not run (replaced by B1 `AutoGPT`) | — (blocked in container build; 0 runtime hosts in source) |
| `haystack` | Default `Pipeline + DocumentSplitter()` exits `0` cleanly on split aside from background PostHog telemetry (`1,582 ms`, `eu.i.posthog.com`); `DocumentSplitter(split_by="sentence")` **crashes immediately** (`453 ms`, exit `1`, missing `nltk` punkt resource). | `crashes_immediately` on sentence splitting; default word splitter `clean_offline` aside from telemetry | `nltk.download()` + `tiktoken` (`375 ms`, exit `1`) | `raw.githubusercontent.com`, `openaipublic.blob.core.windows.net`, `eu.i.posthog.com` |
| `browser-use` | `browser-use --help` exits `0` cleanly (`187 ms`, DNS attempt for telemetry only); `ProductTelemetry().flush()` hits **`eu.i.posthog.com`** (`1,831 ms`, exit `0`, **`SILENT_EGRESS`**). | `clean_offline` for CLI startup (telemetry dropped quietly) | `tiktoken.encoding_for_model("gpt-4o")` (`200 ms`, exit `1`) | `openaipublic.blob.core.windows.net`, `eu.i.posthog.com` |
| `aider` | `aider --no-git --yes --exit --model gpt-4o` (against loopback base URL, `1,518 ms`, exit `0`, **`NETWORK_EGRESS_BLOCKED_IN_AIRGAP`**) immediately tries **`pypi.org`** (`versioncheck.py`) and **`raw.githubusercontent.com`** (`models.py` + `litellm`). Confirmed identically in `strace`. | `lazy_on_feature_use` / startup background warnings (`pypi.org`, `raw.githubusercontent.com`) | `tiktoken.get_encoding("cl100k_base")` (`234 ms`, exit `1`) | `pypi.org`, `raw.githubusercontent.com`, `openaipublic.blob.core.windows.net` |
| `Flowise` | `node /app/packages/server/bin/run start` boots cleanly (`exit 137` under 28 s `timeout`, `28,384 ms`, 0 network calls during server boot; `strace` exit clean until kill). | `clean_offline` at boot (`lazy_on_feature_use` on Playwright/Puppeteer/LangChainHub nodes & UI About check) | **`langchainhub`** (`exit 1`, `563 ms`, `api.hub.langchain.com`), `playwright` (`exit 1`, `316 ms`), `puppeteer` (`exit 1`, `406 ms`), telemetry (`8,395 ms`, `exit 137`, `app.posthog.com`). `@dqbd/tiktoken` clean (`exit 0`, `429 ms`). `@xenova/transformers` hit `sharp` arch error (`282 ms`). | `api.hub.langchain.com`, `app.posthog.com` |
| `openai-agents-python` | `Agent(...)` construction clean (`752 ms`, exit `0`, 0 syscalls); `Runner.run_sync(...)` (`OPENAI_BASE_URL=http://127.0.0.1:11434/v1`) fails hitting localhost LLM (`5,395 ms`, exit `1`) AND dispatches background tracing DNS/TCP to **`api.openai.com`** (verified stopped when `OPENAI_AGENTS_DISABLE_TRACING=1` in `strace`). | `clean_offline` for core agent loop (aside from background `api.openai.com` tracing unless `OPENAI_AGENTS_DISABLE_TRACING=1`) | `[extra: litellm]` `litellm.model_cost` (`1,574 ms`, exit `0` fallback, `raw.githubusercontent.com`) | `api.openai.com`, `raw.githubusercontent.com` |
| `LibreChat` | `@librechat/api` `countTokens()` exits `0` offline (`1,518 ms`, 0 syscalls in `strace`); server entrypoint (`index.js`) connects only to loopback MongoDB (`127.0.0.1:27017`) until test `timeout` (`31,802 ms`, exit `124`). | `clean_offline` (pure API/DB client; core tokenizers offline) | — (negative control clean) | None offline (`127.0.0.1:27017` MongoDB only) |
| `AutoGPT` *(Backup B1)* | `poetry run autogpt --help` (`2,052 ms`) and `import autogpt.app.main` (`3,493 ms`) clean (`exit 0`, 0 syscalls); `autogpt run` (`TELEMETRY_OPT_IN=true`, `2,093 ms`, exit `1`) **crashes via `sentry_sdk` importing `tiktoken` (`openaipublic.blob.core.windows.net`)**; `GTTSVoice._speech()` fails hitting **`translate.google.com`** (`1,033 ms`, exit `1`); `split_text` hits `openaipublic.blob.core.windows.net` (`2,650 ms`, exit `1`). | `crashes_immediately` when `TELEMETRY_OPT_IN=true` (`sentry_sdk` -> `tiktoken`) or on `split_text` / `gtts`; CLI `--help` & `import` clean | `tiktoken` (`981 ms`, exit `1`), `playwright` (`963 ms`, exit `1`); **`spacy` (`en_core_web_sm` pinned wheel) succeeded offline (`1,765 ms`, exit `0`, 0 syscalls in `strace`)** | `openaipublic.blob.core.windows.net`, `translate.google.com` |

### 4.4 Bugs Exposed in `v0.2.1` `--run` Observer During Benchmark v2

1. **Image `ENTRYPOINT` hijack (`AutoGPT` `dyn_b_upstream_ep`):** Running `--help` against `bench2-autogpt-classic:local` invoked the image's baked `ENTRYPOINT ["poetry", "run", ...]` instead of `sh -c`, causing `observer=unknown`, `exit=1` (`Poetry could not find a pyproject.toml file in /workspace or its parents`) before hooks could load.
2. **Literal Python `bytes` host formatting (`AutoGPT` `dyn_b_run_notel`):** `socket.getaddrinfo(b"api.openai.com", ...)` logged `"host": "b'api.openai.com'"` instead of `"api.openai.com"`.
3. **Noisy `runtime_error_url` matches (`open-webui`, `AutoGPT`, `Flowise`):** Traceback URLs in help/error links (`https://errors.pydantic.dev/...`, `https://cloud.google.com/...`, `https://sharp.pixelplumbing.com/...`, `https://pptr.dev/...`) were misreported as failed egress attempts.
4. **Detached child exit races & timeout log loss (`LibreChat` `dyn_b_server`, `browser-use`):** `atexit` detached child processes (`browser-use`'s `EXIT_SENDER`) could lose telemetry attempts after parent exit, and host-side command timeouts did not force-remove (`docker rm -f`) the named container or preserve pre-timeout attempts.

---

## 5. `v0.2.2` Fixes & Post-Diagnosis Verification (NOT Out-of-Sample)

> **Statistical Honesty Notice:** The results below were measured **after** diagnosing the Benchmark v2 findings above and modifying `airgap-check` (`v0.2.2`). Therefore these numbers are **in-sample verification** on the Benchmark v2 repositories, **NOT** out-of-sample generalization metrics. Only `v0.2.1` (`47b2ddc`) in Section 4 represents the frozen out-of-sample Benchmark v2 result.

### 5.1 Fixes Implemented in `v0.2.2`

- **Parser & Scope Accuracy (`manifests.go`, `main.go`):**
  - Added `[tool.uv] default-groups` promotion (`dify` `nltk`), `[dependency-groups]` group traversal while skipping `dev`/`test`/`lint`/`docs`, and `[tool.setuptools.dynamic.optional-dependencies]` file mapping (`aider` `requirements-help.txt` / `requirements-playwright.txt`).
  - Fixed `uv.lock` / `poetry.lock` optional-extra BFS traversal (`openai-agents-python` `[extra: litellm]`, `open-webui` `[extra: unstructured]` -> `spacy`).
  - Added pnpm v9 lockfile multi-document parsing (`importers:` + `snapshots:` + `packages:`) AND `peerDependenciesMeta.<pkg>.optional: true` + test-runner package exclusion (`@playwright/test`, `vitest`, `jest`, `cypress`, etc.), eliminating the `dify` `next@16.4.5` -> `playwright` FP without hiding transitive `@xenova/transformers`.
  - Added `IsNonRuntimeSourcePath`, `conftest.py` exclusion, nested `/frontend/`/`packages/ui/` browser-context matching (`AutoGPT`), spaCy wheel pin suppression (`en-core-web-sm` in `AutoGPT`), and LLM token-limit `.env` exclusions (`*TOKEN_LIMIT*`, `*BATCH_TOKENS*` in `ragflow`).
- **Source Masking, Patterns & Direct Telemetry (`rules.go`, `remediate.go`):**
  - Replaced Python triple-quote parity tracking in `BuildNonCodeLineMask` with expression-assignment/paren-depth awareness (`tripleMode`) so multiline expressions like `MODEL_INFO_URL = """..."""` or `f"""..."""` (`aider/models.py`, `aider/versioncheck.py`) do not invert docstring masking on subsequent lines.
  - Added adjacent string concatenation joining, multi-line `subprocess.run([...])` inspection (`openai-agents-python` `sandbox/util/github.py`), Go/Python hash-verification map exclusion (`ragflow` `expectedBpeHashes`), Vertex AI `TextEmbeddingModel.from_pretrained` exclusion, UI credential form / placeholder / `<a href>` / `window.open` telemetry exclusions (`Flowise` `*.credential.ts`, `dify` `providers.ts`, `ragflow`), and `AnalyzeSourceTelemetryURLs` (catching `eu.i.posthog.com`, `otel.dify.ai`/`cn`, `api.openai.com/v1/traces/ingest`).
  - Added package/runtime rules for `gtts`, `tesseract.js`, `kokoro-js`, `langchainhub`, `spacy.load()`, and runtime metadata/update URLs (`models.dev/api.json`, `pypi.org/pypi/*/json`, `api.github.com/repos/*/releases/latest`, `updates.*`).
- **`--run` Docker Runtime Hardening (`dynamic.go`):**
  - Passes `--entrypoint ""` and `--name <unique>` to `docker run`, binds a host temp `attempts.jsonl` file (`fsync` per event) so pre-timeout attempts survive crashes/timeouts, executes `docker rm -f` on timeout (`TIMEOUT_EXCEEDED_IN_AIRGAP`), decodes Python `bytes` hosts, polls `/proc` up to 1 s for detached child exit, and constrains `runtime_error_url` extraction with error-context + doc-host filtering (`errors.pydantic.dev`, `cloud.google.com`, `sharp.pixelplumbing.com`).

### 5.2 Static Re-Scan Comparison (`v0.2.1` vs `v0.2.2` Across All 11 Benchmark v2 Repos)

| Repository | `v0.2.1` (`47b2ddc`, Out-of-Sample) TP / FP / FN | `v0.2.2` Crash + Behavioral (In-Sample) | `v0.2.2` TP / FP / FN | Key `v0.2.2` Deltas Verified on Disk |
| :--- | :---: | :-: | :---: | :--- |
| `open-webui` | `14 / 0 / 4` | `16 + 2 = 18` (`871 ms`) | `18 / 0 / 0` | `+spacy [optional_extra]`, `+kokoro-js [prod]`, `+main.py:2786` (`api.github.com`), `+plugin.py:451` (`pip install`) |
| `anything-llm` | `4 / 0 / 3` | `5 + 2 = 7` (`813 ms`) | `7 / 0 / 0` | `+tesseract.js`, `+langchainhub`, `+modelPricing` (`models.dev`) |
| `dify` | `7 / 1 / 2` | `8 + 1 = 9` (`3,166 ms`) | `9 / 0 / 0` | `-playwright` FP (optional peer `@playwright/test`), `+nltk` (`default-groups`), `+updates.dify.ai`; tel `6 -> 10` |
| `ragflow` | `0 / 5 / 0` | `0 + 0 = 0` (`2,715 ms`) | `0 / 0 / 0` | `-5` FPs (`download_deps.py`, oracle/dev scripts, `bpe_loader.go` hash map), env FPs `16 -> 13` |
| `haystack` | `5 / 0 / 0` | `5 + 0 = 5` (`308 ms`) | `5 / 0 / 0` | Unchanged scored (`5`); tel `1 -> 2` (`eu.posthog.com` source URL) |
| `browser-use` | `1 / 0 / 0` | `1 + 0 = 1` (`96 ms`) | `1 / 0 / 0` | `tiktoken` kept; tel `0 -> 1` (`browser_use/telemetry/service.py:32` stdlib PostHog) |
| `aider` | `7 / 0 / 2` | `7 + 2 = 9` (`97 ms`) | `9 / 0 / 0` | `3 [prod]` + `4 [optional_extra]` scopes fixed; `+models.py:163`, `+versioncheck.py:78` |
| `Flowise` | `3 / 0 / 2` | `4 + 1 = 5` (`697 ms`) | `5 / 0 / 0` | `+langchainhub`, `+AboutDialog.jsx:16` (`api.github.com`); `.credential.ts` UI forms filtered |
| `openai-agents-python` | `1 / 0 / 4` | `3 + 2 = 5` (`333 ms`) | `5 / 0 / 0` | `+huggingface-hub` & `+tiktoken` via `[extra: litellm]`, `+blaxel/mounts.py:243`, `+sandbox/util/github.py:22`; tel `0 -> 2` (`/v1/traces/ingest`) |
| `LibreChat` | `0 / 0 / 0` | `0 + 0 = 0` (`1,298 ms`) | `0 / 0 / 0` | Negative control still `0`; tel `4 -> 7` (`langfuse` destinations) |
| `AutoGPT` *(B1)* | `6 / 3 / 2` | `8 + 0 = 8` (`2,132 ms`) | `8 / 0 / 0` | `-spacy` FP (wheel pin), `-2` eval script FPs, `+gtts` + `gtts.gTTS()`; nested `frontend/` tagged `browser_client` |

### 5.3 Verification Scope & Limitations for `v0.2.2`

- **Static suite:** Re-scanned all 11 pinned Benchmark v2 repositories above (`67 TP, 0 FP, 0 FN` against the Benchmark v2 findings documented in Section 4 — in-sample verification only).
- **Dynamic `--run` verification:** All `v0.2.2` `--run` runtime fixes (`--entrypoint ""` override on baked images, Python `bytes` host decoding, detached `atexit` child telemetry capture, `docker rm -f` timeout cleanup with zero lingering containers + pre-timeout attempt preservation via bind-mounted `attempts.jsonl`, and Node 20 global `fetch()` interception) were verified against real `docker run --rm --network none` containers (`python:3.12-slim-bookworm`, `node:20-bookworm-slim`, and built Dockerfiles) inside `go test -v ./...` (`18/18` tests passing). We did **not** re-run the 46 full upstream Benchmark v2 application containers on `v0.2.2`.
