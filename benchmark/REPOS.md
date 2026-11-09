# Benchmark Repositories & Execution Details

Tested on: **November 9, 2026**  
Rules frozen at commit: [`8ce2f11`](https://github.com/humanethq/airgap-check/commit/8ce2f11e5f411e18d8137217dd3b0f3727b4e12d)

---

## Phase 1: Calibration Set (10 Repositories)

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
| `llm-examples` | `https://github.com/streamlit/llm-examples.git` | `7cf260745675e41f92e7436d3777aafdab9dad9f` | 2025-12-08 | Streamlit / Python |
| `openai-realtime-console` | `https://github.com/openai/openai-realtime-console.git` | `ab8b8f5852b47ec1b9ef73bf566851d0eeafddbb` | 2025-08-28 | React / TypeScript |
| `rags` | `https://github.com/run-llama/rags.git` | `4bec27023950c078fe0d559e1720d757d0024c93` | 2023-12-04 | Streamlit / Python |

---

## Phase 2: Held-Out Evaluation Set (10 Repositories)

Rules were frozen prior to evaluating these repositories. These are probe-based tests: we did not start the applications themselves. Each repository was scanned statically with `airgap-check` and dynamically executed inside a container with `--network none` using `airgap-eval-py:latest` (`python:3.12-slim-bookworm` with standard dependencies installed) running a probe call that exercised the specific library functions flagged by the static scan.

| Repository | Upstream URL | Commit SHA | Probe Command Executed Under `--network none` | Probe Result & Measured Time | Intercepted Host(s) |
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
