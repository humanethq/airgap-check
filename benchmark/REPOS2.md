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
