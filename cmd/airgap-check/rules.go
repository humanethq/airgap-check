package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type knownPackageRule struct {
	packages   []string // normalized exact package names (PEP 503 for Python/Rust, exact for npm/Go)
	ecosystems []string // empty = all ecosystems; else e.g. []string{"python", "rust"}
	component  string
	category   string // "runtime_model_asset" or "telemetry_analytics"
	severity   string
	hosts      []string
	impact     string
	mitigation string
	autoSealed bool
}

var knownAirgapAndTelemetryRules = []knownPackageRule{
	// --- Runtime Model / Binary / Corpus Downloaders ---
	{
		packages:   []string{"tiktoken", "tiktoken-rs"},
		ecosystems: []string{"python", "rust"},
		component:  "tiktoken",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.blob.core.windows.net"},
		impact:     "Downloads cl100k_base/o200k_base BPE rank files over HTTPS on first call; crashes with ConnectionError in --network none.",
		mitigation: "Pre-warm cl100k_base & o200k_base into TIKTOKEN_CACHE_DIR during image build (see `--fix`).",
	},
	{
		packages:   []string{"chromadb"},
		ecosystems: []string{"python"},
		component:  "chromadb (default ONNX embedding)",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"chroma-onnx-models.s3.amazonaws.com"},
		impact:     "Calling collection.add() with the default embedding function downloads all-MiniLM-L6-v2 ONNX weights from chroma-onnx-models.s3.amazonaws.com; crashes in --network none.",
		mitigation: "Pass an explicit local embedding_function or pre-warm ONNXMiniLM_L6_V2 into XDG_CACHE_HOME during image build (see `--fix`).",
	},
	{
		packages:   []string{"fastembed", "fastembed-gpu"},
		ecosystems: []string{"python"},
		component:  "fastembed",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "TextEmbedding() hangs for ~39s (3s+9s+27s backoff) attempting to download ONNX weights before raising ValueError in --network none.",
		mitigation: "Pre-populate fastembed cache_dir during image build and pass local_files_only=True (see `--fix`).",
	},
	{
		packages:   []string{"sentence-transformers"},
		ecosystems: []string{"python"},
		component:  "sentence-transformers",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Fetches embedding weights and tokenizer configs from HuggingFace Hub at runtime; fails in offline networks.",
		mitigation: "Pre-download model weights into HF_HOME during build and set HF_HUB_OFFLINE=1 (see `--fix`).",
	},
	{
		packages:   []string{"transformers", "@huggingface/transformers", "@xenova/transformers"},
		component:  "transformers",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Calls huggingface.co API (retry backoff ~23s) for model/tokenizer weights on first use unless local_files_only=True and weights are cached.",
		mitigation: "Pre-populate HF_HOME / model cache during build and set TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 (see `--fix`).",
	},
	{
		packages:   []string{"huggingface-hub"},
		ecosystems: []string{"python"},
		component:  "huggingface-hub",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "hf_hub_download()/snapshot_download() checks huggingface.co with retry backoff unless HF_HUB_OFFLINE=1 and weights are pre-baked.",
		mitigation: "Pre-bake needed repos into HF_HOME during build, then set HF_HUB_OFFLINE=1 in runtime ENV (see `--fix`).",
	},
	{
		packages:   []string{"easyocr"},
		ecosystems: []string{"python"},
		component:  "easyocr",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"github.com", "releases.jaided.ai"},
		impact:     "easyocr.Reader() downloads CRAFT detection and recognition .pth/.zip weights into ~/.EasyOCR/model on first run; crashes offline or on read-only rootfs.",
		mitigation: "Pre-download EasyOCR weights into EASYOCR_MODULE_PATH=/app/.cache/easyocr at build time and pass download_enabled=False.",
	},
	{
		packages:   []string{"rapidocr", "rapidocr-onnxruntime", "rapidocr-openvino", "rapidocr-paddle"},
		ecosystems: []string{"python"},
		component:  "rapidocr",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "www.modelscope.cn"},
		impact:     "RapidOCR downloads default PP-OCR detection/classification/recognition models on first call unless det_model_dir/rec_model_dir are pre-baked.",
		mitigation: "Warm RapidOCR() or bake .onnx OCR models during image build (see `--fix`).",
	},
	{
		packages:   []string{"paddleocr"},
		ecosystems: []string{"python"},
		component:  "paddleocr",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"paddleocr.bj.bcebos.com"},
		impact:     "PaddleOCR() downloads model tarballs to ~/.paddleocr on first instantiation; crashes offline or in non-writable /root.",
		mitigation: "Pre-download PaddleOCR models into writable image directory and pass det_model_dir/rec_model_dir explicitly.",
	},
	{
		packages:   []string{"flagembedding"},
		ecosystems: []string{"python"},
		component:  "FlagEmbedding",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "FlagModel/FlagReranker/BGEM3FlagModel download BGE checkpoints via HuggingFace Hub on initialization.",
		mitigation: "Pre-download BGE model IDs into HF_HOME during image build and set HF_HUB_OFFLINE=1.",
	},
	{
		packages:   []string{"litellm"},
		ecosystems: []string{"python"},
		component:  "litellm (startup cost map fetch)",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "LiteLLM fetches model_prices_and_context_window.json from GitHub at import/startup unless LITELLM_LOCAL_MODEL_COST_MAP=True is set.",
		mitigation: "Set ENV LITELLM_LOCAL_MODEL_COST_MAP=True so LiteLLM uses its bundled offline price map immediately.",
		autoSealed: true,
	},
	{
		packages:   []string{"openai-whisper", "whisper", "faster-whisper", "mlx-whisper"},
		ecosystems: []string{"python"},
		component:  "whisper",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.azureedge.net", "huggingface.co"},
		impact:     "Downloads Whisper .pt / CTranslate2 weights at runtime into ~/.cache/whisper or HF_HOME.",
		mitigation: "Pre-download Whisper checkpoints into XDG_CACHE_HOME/whisper or HF_HOME during build (see `--fix`).",
	},
	{
		packages:   []string{"spacy"},
		ecosystems: []string{"python"},
		component:  "spacy",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "spacy.cli.download fetches language pipelines at runtime if not installed as a wheel.",
		mitigation: "Pin the spacy model wheel URL in dependencies or run `python3 -m spacy download` during build (see `--fix`).",
	},
	{
		packages:   []string{"nltk"},
		ecosystems: []string{"python"},
		component:  "nltk",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "nltk.download() / LookupError on missing punkt/stopwords fetches corpora from raw.githubusercontent.com at runtime.",
		mitigation: "Pre-download NLTK_DATA into the image during build via `python3 -m nltk.downloader` (see `--fix`).",
	},
	{
		packages:   []string{"playwright", "playwright-core", "patchright"},
		component:  "playwright",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"playwright.azureedge.net"},
		impact:     "Requires headless browser binaries downloaded from playwright.azureedge.net; fails at launch if missing.",
		mitigation: "Run `playwright install --with-deps chromium` with PLAYWRIGHT_BROWSERS_PATH during image build (see `--fix`).",
	},
	{
		packages:   []string{"puppeteer"},
		ecosystems: []string{"node"},
		component:  "puppeteer",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"storage.googleapis.com"},
		impact:     "Requires Chromium binary cached in PUPPETEER_CACHE_DIR (~/.cache/puppeteer); fails if omitted from final Docker stage.",
		mitigation: "Set PUPPETEER_CACHE_DIR=/app/.cache/puppeteer and run `npx puppeteer browsers install chrome` at build time.",
	},
	{
		packages:   []string{"tesseract.js"},
		ecosystems: []string{"node"},
		component:  "tesseract.js",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"cdn.jsdelivr.net", "tessdata.projectnaptha.com"},
		impact:     "Fetches *.traineddata language files and worker WASM/JS bundles over HTTPS on first OCR call unless pre-baked locally.",
		mitigation: "Pre-download required *.traineddata files during image build and pass local langPath/cachePath options (see `--fix`).",
	},
	{
		packages:   []string{"kokoro-js"},
		ecosystems: []string{"node"},
		component:  "kokoro-js",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Downloads Kokoro ONNX TTS model checkpoints via Transformers.js / HuggingFace Hub on first synthesis call unless pre-baked locally.",
		mitigation: "Pre-download Kokoro ONNX model assets during image build and configure Transformers.js with local model paths and allowRemoteModels=false.",
	},
	{
		packages:   []string{"langchainhub", "@langchain/hub"},
		component:  "langchainhub",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"api.smith.langchain.com"},
		impact:     "Fetches versioned prompt templates over HTTPS from LangSmith Hub on hub.pull() at runtime; fails offline unless bundled locally.",
		mitigation: "Vendor prompt templates in source or local config instead of calling hub.pull() at runtime.",
	},
	{
		packages:   []string{"gtts"},
		ecosystems: []string{"python"},
		component:  "gtts",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"translate.google.com"},
		impact:     "gTTS makes live HTTPS requests to Google Translate TTS at runtime and has no offline synthesis fallback.",
		mitigation: "Replace gTTS with an offline local TTS engine whose voice weights are baked into the container image.",
	},
	{
		packages:   []string{"timm", "ultralytics", "unstructured", "surya-ocr", "docling-ibm-models", "kokoro", "kokoro-onnx", "stanza", "flair"},
		ecosystems: []string{"python"},
		component:  "ml-weight-downloader",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"huggingface.co", "github.com", "raw.githubusercontent.com"},
		impact:     "Downloads neural network checkpoints, OCR/layout models, or NLP resources on first inference unless cached in build.",
		mitigation: "Pre-warm required model weights into HF_HOME / TORCH_HOME / XDG_CACHE_HOME during image build.",
	},

	// --- Server & Browser Telemetry / Observability Leaks ---
	{
		packages:   []string{"chromadb"},
		ecosystems: []string{"python"},
		component:  "chromadb",
		category:   "telemetry_analytics",
		severity:   "HIGH",
		hosts:      []string{"us.i.posthog.com", "eu.i.posthog.com"},
		impact:     "ChromaDB emits PostHog telemetry events by default unless ANONYMIZED_TELEMETRY=False is set.",
		mitigation: "Set ANONYMIZED_TELEMETRY=False and CHROMA_TELEMETRY_IMPL=none in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"crewai"},
		ecosystems: []string{"python"},
		component:  "crewai",
		category:   "telemetry_analytics",
		severity:   "HIGH",
		hosts:      []string{"telemetry.crewai.com"},
		impact:     "CrewAI spawns background OTLP threads connecting to telemetry.crewai.com:4319 unless disabled.",
		mitigation: "Set CREWAI_DISABLE_TELEMETRY=true and OTEL_SDK_DISABLED=true in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"posthog", "posthog-js", "posthog-node"},
		component:  "posthog",
		category:   "telemetry_analytics",
		severity:   "MEDIUM",
		hosts:      []string{"us.i.posthog.com", "app.posthog.com"},
		impact:     "Sends usage analytics to PostHog endpoints.",
		mitigation: "Disable PostHog client init in code (especially browser posthog-js, which cannot be silenced by server ENV vars).",
	},
	{
		packages:   []string{"sentry-sdk", "@sentry/node", "@sentry/nextjs", "@sentry/react", "@sentry/browser"},
		component:  "sentry-sdk",
		category:   "telemetry_analytics",
		severity:   "MEDIUM",
		hosts:      []string{"ingest.sentry.io", "sentry.io"},
		impact:     "Ships stack traces and local context to Sentry ingest servers when a DSN is configured.",
		mitigation: "Leave SENTRY_DSN unset in offline/regulated deployments or block *.sentry.io at the egress proxy.",
	},
	{
		packages:   []string{"langsmith"},
		component:  "langsmith",
		category:   "telemetry_analytics",
		severity:   "HIGH",
		hosts:      []string{"api.smith.langchain.com"},
		impact:     "Uploads LLM prompts and completions to LangSmith cloud when LANGCHAIN_TRACING_V2 is enabled.",
		mitigation: "Set LANGCHAIN_TRACING_V2=false in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"langfuse"},
		component:  "langfuse",
		category:   "telemetry_analytics",
		severity:   "MEDIUM",
		hosts:      []string{"cloud.langfuse.com"},
		impact:     "Uploads LLM traces and prompts to cloud.langfuse.com unless LANGFUSE_ENABLED=false or self-hosted host is configured.",
		mitigation: "Unset LANGFUSE_PUBLIC_KEY/SECRET_KEY or set LANGFUSE_ENABLED=false in air-gapped environments.",
		autoSealed: true,
	},
	{
		packages:   []string{"wandb"},
		ecosystems: []string{"python"},
		component:  "wandb",
		category:   "telemetry_analytics",
		severity:   "HIGH",
		hosts:      []string{"api.wandb.ai"},
		impact:     "Weights & Biases syncs runs and logs to api.wandb.ai unless WANDB_MODE=offline or WANDB_DISABLED=true.",
		mitigation: "Set WANDB_MODE=offline and WANDB_DISABLED=true in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"opentelemetry-exporter-otlp", "opentelemetry-exporter-otlp-proto-http", "opentelemetry-exporter-otlp-proto-grpc", "@opentelemetry/exporter-trace-otlp-http", "@opentelemetry/exporter-trace-otlp-grpc"},
		component:  "opentelemetry-exporter-otlp",
		category:   "telemetry_analytics",
		severity:   "MEDIUM",
		hosts:      []string{},
		impact:     "Exports OTLP traces/metrics in background threads unless OTEL_SDK_DISABLED=true or an internal collector endpoint is configured.",
		mitigation: "Set OTEL_SDK_DISABLED=true for air-gapped runs without an internal OTLP collector.",
		autoSealed: true,
	},
	{
		packages:   []string{"ddtrace"},
		ecosystems: []string{"python"},
		component:  "ddtrace",
		category:   "telemetry_analytics",
		severity:   "MEDIUM",
		hosts:      []string{"intake.logs.datadoghq.com"},
		impact:     "Attempts Datadog trace/agent submission unless DD_TRACE_ENABLED=false or a local Datadog Agent sidecar runs.",
		mitigation: "Set DD_TRACE_ENABLED=false when running outside Datadog-instrumented clusters.",
		autoSealed: true,
	},
	{
		packages:   []string{"gradio"},
		ecosystems: []string{"python"},
		component:  "gradio",
		category:   "telemetry_analytics",
		severity:   "LOW",
		hosts:      []string{"api.gradio.app"},
		impact:     "Gradio emits startup analytics pings and checks api.gradio.app for version notices unless disabled.",
		mitigation: "Set GRADIO_ANALYTICS_ENABLED=False in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"scarf", "@scarf/scarf"},
		component:  "scarf",
		category:   "telemetry_analytics",
		severity:   "LOW",
		hosts:      []string{"scarf.sh"},
		impact:     "Reports package import/install telemetry to scarf.sh.",
		mitigation: "Set SCARF_NO_ANALYTICS=true and DO_NOT_TRACK=1 in container ENV.",
		autoSealed: true,
	},
	{
		packages:   []string{"openai-agents"},
		ecosystems: []string{"python"},
		component:  "openai-agents",
		category:   "telemetry_analytics",
		severity:   "HIGH",
		hosts:      []string{"api.openai.com"},
		impact:     "Exports tracing spans to api.openai.com/v1/traces/ingest by default (even when using a local LLM endpoint) unless tracing is disabled.",
		mitigation: "Set OPENAI_AGENTS_DISABLE_TRACING=1 in container ENV or call set_tracing_disabled(True).",
		autoSealed: true,
	},
}

var knownExternalHostSDKs = map[string]string{
	"openai":              "api.openai.com",
	"anthropic":           "api.anthropic.com",
	"@anthropic-ai/sdk":   "api.anthropic.com",
	"google-generativeai": "generativelanguage.googleapis.com",
	"google-genai":        "generativelanguage.googleapis.com",
	"@google/genai":       "generativelanguage.googleapis.com",
	"groq":                "api.groq.com",
	"mistralai":           "api.mistral.ai",
	"cohere":              "api.cohere.com",
	"stripe":              "api.stripe.com",
}

type sourceCodePatternRule struct {
	hints      []string
	re         *regexp.Regexp
	component  string
	category   string
	severity   string
	hosts      []string
	impact     string
	mitigation string
	autoSealed bool
}

func hasAnySubstring(s string, subs []string) bool {
	if len(subs) == 0 {
		return true
	}
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var sourceCodeDownloadRules = []sourceCodePatternRule{
	{
		hints:      []string{"nltk.download"},
		re:         regexp.MustCompile(`\bnltk\.download\s*\(`),
		component:  "nltk.download()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "Explicit nltk.download() call in source code attempts an outbound HTTPS fetch to GitHub raw URLs at runtime.",
		mitigation: "Move nltk.download() to the Dockerfile build stage and set NLTK_DATA.",
	},
	{
		hints:      []string{"spacy.cli.download"},
		re:         regexp.MustCompile(`\bspacy\.cli\.download\s*\(`),
		component:  "spacy.cli.download()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "Explicit spacy.cli.download() call in source code invokes pip/HTTP download at runtime.",
		mitigation: "Install the spacy model wheel during image build instead of calling spacy.cli.download() at runtime.",
	},
	{
		hints:      []string{"spacy.load"},
		re:         regexp.MustCompile(`\bspacy\.load\s*\(`),
		component:  "spacy.load()",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "Loads a spaCy language pipeline by name at runtime; fails if the model wheel is not pre-installed in the image.",
		mitigation: "Pin the spaCy model wheel URL in dependencies or install it during Docker image build (see `--fix`).",
	},
	{
		hints:      []string{"gtts.gTTS", "gTTS("},
		re:         regexp.MustCompile(`\b(?:gtts\.)?gTTS\s*\(`),
		component:  "gtts.gTTS()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"translate.google.com"},
		impact:     "Invokes gTTS() online speech synthesis over HTTPS to translate.google.com; fails offline.",
		mitigation: "Use an offline local TTS engine instead of gTTS in air-gapped deployments.",
	},
	{
		hints:      []string{"from_pretrained", "hf_hub_download", "snapshot_download"},
		re:         regexp.MustCompile(`\b(?:from_pretrained|hf_hub_download|snapshot_download)\s*\(`),
		component:  "huggingface_hub.from_pretrained/download",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Calls HuggingFace Hub over HTTPS to check/download model weights unless local_files_only=True and weights exist locally.",
		mitigation: "Pre-bake model weights into HF_HOME during build and set HF_HUB_OFFLINE=1.",
	},
	{
		hints:      []string{"torch.hub."},
		re:         regexp.MustCompile(`\btorch\.hub\.(?:load|load_state_dict_from_url)\s*\(`),
		component:  "torch.hub.load()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"github.com", "download.pytorch.org"},
		impact:     "Downloads PyTorch repository code and checkpoints over HTTPS at runtime.",
		mitigation: "Pre-populate TORCH_HOME in the container image during build.",
	},
	{
		hints:      []string{"whisper.load_model"},
		re:         regexp.MustCompile(`\bwhisper\.load_model\s*\(`),
		component:  "whisper.load_model()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.azureedge.net"},
		impact:     "Downloads Whisper model checkpoint from openaipublic.azureedge.net if not present in cache.",
		mitigation: "Pre-download the .pt model during build and pass download_root to whisper.load_model().",
	},
	{
		hints:      []string{"tiktoken."},
		re:         regexp.MustCompile(`\btiktoken\.(?:get_encoding|encoding_for_model)\s*\(`),
		component:  "tiktoken.get_encoding()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.blob.core.windows.net"},
		impact:     "Downloads BPE encoding file from openaipublic.blob.core.windows.net on first call if TIKTOKEN_CACHE_DIR is unpopulated.",
		mitigation: "Pre-warm cl100k_base & o200k_base into TIKTOKEN_CACHE_DIR at build time (see `--fix`).",
	},
	{
		hints:      []string{"easyocr.Reader"},
		re:         regexp.MustCompile(`\beasyocr\.Reader\s*\(`),
		component:  "easyocr.Reader()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"github.com", "releases.jaided.ai"},
		impact:     "EasyOCR Reader downloads detection/recognition model weights on first initialization unless pre-baked into model_storage_directory.",
		mitigation: "Pre-warm EasyOCR into /app/.cache/easyocr during build and pass download_enabled=False.",
	},
	{
		hints:      []string{"RapidOCR("},
		re:         regexp.MustCompile(`\bRapidOCR\(`),
		component:  "RapidOCR()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "www.modelscope.cn"},
		impact:     "RapidOCR downloads default ONNX/Paddle detection & recognition models on first call unless local model dirs are passed.",
		mitigation: "Pre-warm RapidOCR models into the container image during build.",
	},
	{
		hints:      []string{"PaddleOCR("},
		re:         regexp.MustCompile(`\bPaddleOCR\(`),
		component:  "PaddleOCR()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"paddleocr.bj.bcebos.com"},
		impact:     "PaddleOCR downloads model tarballs to ~/.paddleocr at runtime unless model directories are baked.",
		mitigation: "Bake det_model_dir / rec_model_dir / cls_model_dir into the image.",
	},
	{
		hints:      []string{"FlagReranker", "FlagModel", "BGEM3FlagModel", "FlagLLMReranker"},
		re:         regexp.MustCompile(`\b(?:FlagReranker|FlagModel|BGEM3FlagModel|FlagLLMReranker)\s*\(`),
		component:  "FlagEmbedding",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "FlagEmbedding pulls BGE embedding/reranker weights from HuggingFace Hub at runtime unless pre-cached in HF_HOME.",
		mitigation: "Pre-download BGE model snapshots into HF_HOME during build and set HF_HUB_OFFLINE=1.",
	},
	{
		hints:      []string{"TextEmbedding"},
		re:         regexp.MustCompile(`\bTextEmbedding\s*\(`),
		component:  "fastembed TextEmbedding()",
		category:   "runtime_model_asset",
		severity:   "HIGH",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Instantiating fastembed TextEmbedding() downloads ONNX model weights with ~39s retry backoff if not pre-warmed.",
		mitigation: "Pre-warm TextEmbedding(cache_dir='/app/.cache/fastembed') at build time and pass local_files_only=True.",
	},
}

// --- Custom Rules Loader (.airgap-check.json / --rules) ---

type LoadedCustomRules struct {
	PkgRules         []knownPackageRule
	IgnoreComponents map[string]bool
	IgnoreHosts      map[string]bool
}

func LoadCustomRules(targetDir, customPath string) (*LoadedCustomRules, error) {
	res := &LoadedCustomRules{
		IgnoreComponents: make(map[string]bool),
		IgnoreHosts:      make(map[string]bool),
	}

	var paths []string
	defaultCfg := filepath.Join(targetDir, ".airgap-check.json")
	if _, err := os.Stat(defaultCfg); err == nil {
		paths = append(paths, defaultCfg)
	}
	if strings.TrimSpace(customPath) != "" && customPath != defaultCfg {
		paths = append(paths, customPath)
	}

	type rawRulesFile struct {
		Rules            []CustomRuleEntry `json:"rules"`
		IgnoreComponents []string          `json:"ignore_components"`
		IgnoreHosts      []string          `json:"ignore_hosts"`
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading custom rules file %s: %w", p, err)
		}
		var parsed rawRulesFile
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("parsing custom rules JSON %s: %w", p, err)
		}
		for _, ic := range parsed.IgnoreComponents {
			res.IgnoreComponents[strings.ToLower(strings.TrimSpace(ic))] = true
		}
		for _, ih := range parsed.IgnoreHosts {
			res.IgnoreHosts[strings.ToLower(strings.TrimSpace(ih))] = true
		}
		for _, r := range parsed.Rules {
			pkg := NormalizePackageName(r.PackageOrPattern, "python")
			if pkg == "" {
				continue
			}
			cat := r.Category
			if cat == "" {
				cat = "runtime_model_asset"
			}
			sev := r.Severity
			if sev == "" {
				sev = "HIGH"
			}
			comp := r.Component
			if comp == "" {
				comp = r.PackageOrPattern
			}
			var ecos []string
			if r.PythonOnly {
				ecos = []string{"python"}
			}
			res.PkgRules = append(res.PkgRules, knownPackageRule{
				packages:   []string{pkg},
				ecosystems: ecos,
				component:  comp,
				category:   cat,
				severity:   sev,
				hosts:      r.Hosts,
				impact:     r.Impact,
				mitigation: r.Mitigation,
			})
		}
	}
	return res, nil
}

// --- Universal Behavioral Source-Code Analyzer (beyond hardcoded packages) ---

var (
	assetExtOrHintRe         = regexp.MustCompile(`(?i)\.(?:onnx|safetensors|gguf|ggml|ckpt|tflite|tiktoken|tar\.gz|tgz|whl|pth|pt|bin|zip)(?:$|[?"'\s#])|model_prices_and_context_window\.json|download[_-]?model|weights[_-]?url|cost_map_url`)
	runtimeMetaOrUpdateURLRe = regexp.MustCompile(`(?i)https?://(?:models\.dev/api\.json|pypi\.org/pypi/[^/\s"'` + "`" + `)]+/json|api\.github\.com/repos/[^/\s"'` + "`" + `)]+/[^/\s"'` + "`" + `)]+/releases(?:/latest)?|updates?\.[a-zA-Z0-9.-]+\.[a-z]{2,}(?:/[^\s"'` + "`" + `)]*)?)`)
	sourceTelemetryURLRe     = regexp.MustCompile(`(?i)https?://(?:(?:us|eu|app)\.i\.posthog\.com|(?:us|eu|app)\.posthog\.com|posthog\.com(?:/batch|/capture|/decide|/e)?(?:$|[?"'\s/#])|[^/\s"'` + "`" + `)]*ingest[^/\s"'` + "`" + `)]*\.sentry\.io|telemetry\.[a-zA-Z0-9.-]+\.[a-z]{2,}|otel\.[a-zA-Z0-9.-]+\.[a-z]{2,}|cloud\.langfuse\.com|api\.smith\.langchain\.com|api\.wandb\.ai|scarf\.sh|api\.openai\.com/v1/traces/ingest)(?:/[^\s"'` + "`" + `)]*)?`)
	urlRetrieveRe            = regexp.MustCompile(`\b(?:urllib\.request\.urlretrieve|urlretrieve|wget\.download)\s*\(`)
	archiveUnpackRe          = regexp.MustCompile(`\b(?:shutil\.unpack_archive|tarfile\.open|zipfile\.ZipFile)\s*\(`)
	httpFetchHintRe          = regexp.MustCompile(`\b(?:urllib\.request|requests\.(?:get|post|Session)|httpx\.(?:get|Client|AsyncClient)|aiohttp\.ClientSession|fetch\(|axios\.(?:get|post|request)|http\.(?:Get|Post|NewRequest|Client))`)
	subprocessStartRe        = regexp.MustCompile(`\b(?:subprocess\.(?:run|Popen|check_call|check_output|call)|os\.system|execSync|child_process\.exec(?:File|Sync)?|exec\.Command)\s*\(`)
	subprocessNetRe          = regexp.MustCompile(`(?i)\b(?:subprocess\.(?:run|Popen|check_call|check_output|call)|os\.system|execSync|child_process\.exec|exec\.Command)\b[^\n]*(?:pip(?:\s+|["'],\s*["'])install|uv(?:\s+|["'],\s*["'])pip|playwright(?:\s+|["'],\s*["'])install|spacy(?:\s+|["'],\s*["'])download|\bcurl(?:\s+|["'],\s*["'])|\bwget(?:\s+|["'],\s*["'])|git(?:\s+|["'],\s*["'])clone(?:\s+|["'],\s*["'])https?://|ollama(?:\s+|["'],\s*["'])pull)`)
	subprocessNetActionRe    = regexp.MustCompile(`(?i)(?:pip\b[\s"',\[]+install|uv\b[\s"',\[]+pip|playwright\b[\s"',\[]+install|spacy\b[\s"',\[]+download|\bcurl\b|\bwget\b|git\b[\s"',\[]+clone|\bollama\b[\s"',\[]+pull)`)
	adjacentStringConcatRe   = regexp.MustCompile(`(?:"\s*(?:\+\s*)?\r?\n\s*"|'\s*(?:\+\s*)?\r?\n\s*')`)
	hashDigestPairRe         = regexp.MustCompile(`(?i)(?:"https?://[^"]+"|'https?://[^']+')\s*[:=,]\s*(?:"[0-9a-f]{32,128}"|'[0-9a-f]{32,128}')|(?:"[0-9a-f]{32,128}"|'[0-9a-f]{32,128}')\s*[:=,]\s*(?:"https?://[^"]+"|'https?://[^']+')`)
	pyReqNoTimeoutRe         = regexp.MustCompile(`\b(?:requests\.(?:get|post|put|patch|delete|head|request)|urllib\.request\.urlopen)\s*\(`)
	homeCacheLiteralRe       = regexp.MustCompile(`(?:"~/\.cache|'~/\.cache|"/root/\.cache|'/root/\.cache|Path\.home\(\)\s*/\s*["']\.cache|os\.path\.expanduser\(\s*["']~/\.cache|user_cache_dir\s*\()`)
	cacheEnvOverrideRe       = regexp.MustCompile(`\b(?:HF_HOME|XDG_CACHE_HOME|TORCH_HOME|TIKTOKEN_CACHE_DIR|NLTK_DATA|EASYOCR_MODULE_PATH|CACHE_DIR)\b`)
)

// IsNonRuntimeSourcePath returns true for build-prep scripts, CI helpers, eval harnesses,
// benchmarks, devtools, and documentation files that are not part of app runtime.
func IsNonRuntimeSourcePath(relSlash, lowerName string) bool {
	lower := strings.ToLower(relSlash)
	for _, seg := range []string{
		"ci_cd/", "scripts/", "benchmark/", "benchmarks/", "direct_benchmark/",
		"eval/", "evals/", "evaluation/", "docs/", "examples/", "cookbook/",
		"packaging/", "devtools/", "dev_tools/", ".storybook/", "stories/",
	} {
		if strings.HasPrefix(lower, seg) || strings.Contains(lower, "/"+seg) {
			return true
		}
	}
	if lowerName == "" {
		lowerName = strings.ToLower(filepath.Base(relSlash))
	}
	switch lowerName {
	case "download_deps.py", "download_dev_deps.py", "eval_corpus.py":
		return true
	}
	return strings.HasSuffix(lowerName, "_oracle.py") ||
		strings.HasSuffix(lowerName, "_eval.py") ||
		strings.HasPrefix(lowerName, "eval_")
}

func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "* ") ||
		trimmed == "*"
}

func FileHasHTTPClient(content string) bool {
	return (strings.Contains(content, "urllib") ||
		strings.Contains(content, "requests.") ||
		strings.Contains(content, "httpx.") ||
		strings.Contains(content, "aiohttp.") ||
		strings.Contains(content, "fetch(") ||
		strings.Contains(content, "axios.") ||
		strings.Contains(content, "http.Get(") ||
		strings.Contains(content, "http.Post(") ||
		strings.Contains(content, "http.NewRequest") ||
		strings.Contains(content, "http.Client")) && httpFetchHintRe.MatchString(content)
}

func HasActiveHTTPClient(lines []string, nonCodeMask []bool) bool {
	for idx, line := range lines {
		if idx < len(nonCodeMask) && nonCodeMask[idx] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || isCommentLine(trimmed) {
			continue
		}
		if FileHasHTTPClient(line) {
			return true
		}
	}
	return false
}

// IsHashVerificationLine returns true when a line defines a URL -> SHA/MD5 digest mapping
// in a file that does not make outbound HTTP requests (e.g. local BPE hash tables).
func IsHashVerificationLine(rawLine, content string, hasHTTPFetchInFile bool) bool {
	if hasHTTPFetchInFile {
		return false
	}
	return hashDigestPairRe.MatchString(rawLine)
}

func isManagedRemoteSDKFromPretrained(line string) bool {
	for _, cls := range []string{
		"TextEmbeddingModel.from_pretrained",
		"MultimodalEmbeddingModel.from_pretrained",
		"GenerativeModel.from_pretrained",
		"ChatModel.from_pretrained",
		"CodeGenerationModel.from_pretrained",
		"CodeChatModel.from_pretrained",
		"TextGenerationModel.from_pretrained",
		"ImageGenerationModel.from_pretrained",
		"ImageTextModel.from_pretrained",
	} {
		if strings.Contains(line, cls) {
			return true
		}
	}
	return false
}

func endsWithPythonExprContinuation(prev string) bool {
	if prev == "" {
		return false
	}
	for _, suf := range []string{"=", "(", "[", "{", ",", "+", "-", "*", "/", "%", "\\", "->"} {
		if strings.HasSuffix(prev, suf) {
			return true
		}
	}
	return prev == "return" || prev == "yield" || prev == "await" ||
		strings.HasSuffix(prev, " return") || strings.HasSuffix(prev, " yield") || strings.HasSuffix(prev, " await")
}

func pythonTripleStartOffset(trimmed string) int {
	n := len(trimmed)
	for prefixLen := 0; prefixLen <= 2 && prefixLen+3 <= n; prefixLen++ {
		if prefixLen > 0 {
			ok := true
			for k := 0; k < prefixLen; k++ {
				switch trimmed[k] {
				case 'r', 'R', 'u', 'U', 'f', 'F', 'b', 'B':
				default:
					ok = false
				}
			}
			if !ok {
				continue
			}
		}
		if trimmed[prefixLen:prefixLen+3] == `"""` || trimmed[prefixLen:prefixLen+3] == `'''` {
			return prefixLen
		}
	}
	return -1
}

// BuildNonCodeLineMask marks lines that are non-executable comments, docstrings, or doctests.
func BuildNonCodeLineMask(content, lowerFileName string) []bool {
	lines := strings.Split(content, "\n")
	mask := make([]bool, len(lines))
	isPy := strings.HasSuffix(lowerFileName, ".py")
	isRuby := strings.HasSuffix(lowerFileName, ".rb")
	isGo := strings.HasSuffix(lowerFileName, ".go")

	if isPy {
		// tripleMode: 0 = outside triple quote, 1 = docstring (masked), 2 = expression triple string (not masked)
		tripleMode := 0
		tripleDelim := ""
		parenDepth := 0
		prevSignificantEnd := ""

		isEscapedAt := func(s string, pos int) bool {
			bs := 0
			for p := pos - 1; p >= 0 && s[p] == '\\'; p-- {
				bs++
			}
			return bs%2 == 1
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if tripleMode == 0 {
				if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ">>>") {
					mask[i] = true
					continue
				}
			}

			docOffset := -1
			if tripleMode == 0 && parenDepth == 0 && !endsWithPythonExprContinuation(prevSignificantEnd) {
				docOffset = pythonTripleStartOffset(trimmed)
			}

			enteredDocstringThisLine := false
			closedDocstringThisLine := false
			hasNonDocCodeThisLine := false
			var singleQuote byte
			codeEnd := len(trimmed)

			for j := 0; j < len(trimmed); {
				if tripleMode != 0 {
					if j+3 <= len(trimmed) && trimmed[j:j+3] == tripleDelim && !isEscapedAt(trimmed, j) {
						wasDoc := tripleMode == 1
						tripleMode = 0
						tripleDelim = ""
						j += 3
						if wasDoc {
							closedDocstringThisLine = true
						} else {
							hasNonDocCodeThisLine = true
						}
						continue
					}
					j++
					continue
				}

				if singleQuote != 0 {
					hasNonDocCodeThisLine = true
					if trimmed[j] == '\\' && j+1 < len(trimmed) {
						j += 2
						continue
					}
					if trimmed[j] == singleQuote {
						singleQuote = 0
					}
					j++
					continue
				}

				c := trimmed[j]
				if c == '#' {
					codeEnd = j
					break
				}
				if (c == '"' || c == '\'') && j+3 <= len(trimmed) && (trimmed[j:j+3] == `"""` || trimmed[j:j+3] == `'''`) {
					tripleDelim = trimmed[j : j+3]
					if j == docOffset {
						tripleMode = 1
						enteredDocstringThisLine = true
					} else {
						tripleMode = 2
						hasNonDocCodeThisLine = true
					}
					j += 3
					continue
				}
				if c == '"' || c == '\'' {
					hasNonDocCodeThisLine = true
					singleQuote = c
					j++
					continue
				}
				switch c {
				case '(', '[', '{':
					parenDepth++
					hasNonDocCodeThisLine = true
				case ')', ']', '}':
					if parenDepth > 0 {
						parenDepth--
					}
					hasNonDocCodeThisLine = true
				case ' ', '\t', '\r':
				default:
					if docOffset < 0 || j >= docOffset {
						hasNonDocCodeThisLine = true
					}
				}
				j++
			}

			if (tripleMode == 1 || enteredDocstringThisLine || closedDocstringThisLine) && !hasNonDocCodeThisLine {
				mask[i] = true
				if tripleMode == 0 {
					prevSignificantEnd = ""
				}
				continue
			}

			if tripleMode == 0 && codeEnd > 0 {
				codeSlice := strings.TrimSpace(trimmed[:codeEnd])
				if codeSlice != "" {
					prevSignificantEnd = codeSlice
				}
			}
		}
		return mask
	}

	if isRuby {
		inPod := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				mask[i] = true
				continue
			}
			if strings.HasPrefix(line, "=begin") {
				inPod = true
				mask[i] = true
				continue
			}
			if inPod {
				mask[i] = true
				if strings.HasPrefix(line, "=end") {
					inPod = false
				}
			}
		}
		return mask
	}

	// C / JS / TS / Go / Rust comment & block comment masking (quote-aware).
	inBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			mask[i] = true
			continue
		}
		hasCode := false
		var inQuote byte
		for j := 0; j < len(line); j++ {
			c := line[j]
			if inBlock {
				if c == '*' && j+1 < len(line) && line[j+1] == '/' {
					inBlock = false
					j++
				}
				continue
			}
			if inQuote != 0 {
				hasCode = true
				if c == '\\' && (!isGo || inQuote != '`') && j+1 < len(line) {
					j++
					continue
				}
				if c == inQuote {
					inQuote = 0
				}
				continue
			}
			if c == ' ' || c == '\t' || c == '\r' {
				continue
			}
			if c == '/' && j+1 < len(line) {
				if line[j+1] == '/' {
					break
				}
				if line[j+1] == '*' {
					inBlock = true
					j++
					continue
				}
			}
			hasCode = true
			if c == '"' || c == '\'' || c == '`' {
				inQuote = c
			}
		}
		if !hasCode {
			mask[i] = true
		}
	}
	return mask
}

func isPlaceholderExampleHostOrLine(host, lineLower string) bool {
	if host == "bucket.s3.amazonaws.com" || host == "my-bucket.s3.amazonaws.com" || host == "your-bucket.s3.amazonaws.com" {
		return true
	}
	if strings.Contains(lineLower, "e.g.,") || strings.Contains(lineLower, "e.g. ") || strings.Contains(lineLower, "for example") {
		return true
	}
	return false
}

// buildJoinedCodeSnippet reconstructs split adjacent string literals across up to maxLookahead unmasked lines.
func buildJoinedCodeSnippet(lines []string, nonCodeMask []bool, idx, maxLookahead int) string {
	var b strings.Builder
	b.WriteString(lines[idx])
	limit := idx + maxLookahead
	if limit > len(lines) {
		limit = len(lines)
	}
	for j := idx + 1; j < limit; j++ {
		if j < len(nonCodeMask) && nonCodeMask[j] {
			break
		}
		tr := strings.TrimSpace(lines[j])
		if tr == "" {
			break
		}
		b.WriteByte('\n')
		b.WriteString(lines[j])
		if tr == ")" || strings.HasSuffix(tr, ";") {
			break
		}
	}
	return adjacentStringConcatRe.ReplaceAllString(b.String(), "")
}

// AnalyzeBehavioralPatterns scans non-test runtime source files for generalizable air-gap
// download anti-patterns (returned in findings) and non-download resilience warnings such
// as HTTP client calls omitting timeout= (returned separately in hints).
func AnalyzeBehavioralPatterns(relSlash, content string, seen map[string]bool) ([]CheckRiskFinding, []CheckRiskFinding, map[string]string) {
	var findings []CheckRiskFinding
	var hints []CheckRiskFinding
	hosts := make(map[string]string)
	lowerPath := strings.ToLower(relSlash)
	lowerBase := strings.ToLower(filepath.Base(relSlash))
	if IsNonRuntimeSourcePath(relSlash, lowerBase) {
		return findings, hints, hosts
	}

	lines := strings.Split(content, "\n")
	isPythonFile := strings.HasSuffix(lowerPath, ".py")
	nonCodeMask := BuildNonCodeLineMask(content, lowerBase)
	hasHTTPFetchInFile := FileHasHTTPClient(content) && HasActiveHTTPClient(lines, nonCodeMask)

	// Fast file-level pre-filters avoid per-line regex sweeps across thousands of files.
	hasHTTPProtocol := strings.Contains(content, "http://") || strings.Contains(content, "https://")
	checkAssetURL := hasHTTPProtocol && (assetExtOrHintRe.MatchString(content) || strings.Contains(content, "\"\n") || strings.Contains(content, "'\n"))
	checkRuntimeMetaURL := hasHTTPProtocol && runtimeMetaOrUpdateURLRe.MatchString(content)
	checkUrlRetrieve := (strings.Contains(content, "urlretrieve") || strings.Contains(content, "wget.download")) && urlRetrieveRe.MatchString(content)
	checkUnpack := hasHTTPFetchInFile && (strings.Contains(content, "unpack_archive") || strings.Contains(content, "tarfile.open") || strings.Contains(content, "ZipFile")) && archiveUnpackRe.MatchString(content)
	checkSubproc := (strings.Contains(content, "subprocess") || strings.Contains(content, "os.system") || strings.Contains(content, "execSync") || strings.Contains(content, "child_process") || strings.Contains(content, "exec.Command")) && (subprocessStartRe.MatchString(content) || subprocessNetRe.MatchString(content))
	checkPyTimeout := isPythonFile && (strings.Contains(content, "requests.") || strings.Contains(content, "urllib.request.urlopen")) && pyReqNoTimeoutRe.MatchString(content)

	if checkAssetURL || checkRuntimeMetaURL || checkUrlRetrieve || checkUnpack || checkSubproc || checkPyTimeout {
		noTimeoutCount := 0
		noTimeoutFirstLine := 0
		foundSubproc := false
		foundArchiveFetch := false

		for idx, rawLine := range lines {
			lineNo := idx + 1
			if nonCodeMask[idx] {
				continue
			}
			trimmed := strings.TrimSpace(rawLine)
			if trimmed == "" || isCommentLine(trimmed) {
				continue
			}

			// 1. Unknown external URLs serving model weights, price maps, or binary archives (including adjacent split literals)
			if checkAssetURL && (strings.Contains(trimmed, "http://") || strings.Contains(trimmed, "https://")) {
				effectiveLine := trimmed
				if !assetExtOrHintRe.MatchString(effectiveLine) {
					effectiveLine = buildJoinedCodeSnippet(lines, nonCodeMask, idx, 6)
				}
				if assetExtOrHintRe.MatchString(effectiveLine) && !IsHashVerificationLine(effectiveLine, content, hasHTTPFetchInFile) {
					lowerLine := strings.ToLower(effectiveLine)
					matches := httpsURLRegex.FindAllStringSubmatch(effectiveLine, -1)
					for _, m := range matches {
						if len(m) < 2 {
							continue
						}
						parsed, err := url.Parse(m[0])
						if err != nil || parsed.Hostname() == "" {
							continue
						}
						h := strings.ToLower(parsed.Hostname())
						if (isIgnoredLocalOrDocHost(h) && h != "raw.githubusercontent.com") || isPlaceholderExampleHostOrLine(h, lowerLine) {
							continue
						}
						key := "behavioral_asset_url|" + h + "|" + relSlash
						if !seen[key] {
							seen[key] = true
							hosts[h] = "behavioral_code"
							cleanDisplayURL := strings.SplitN(m[0], "?", 2)[0]
							findings = append(findings, CheckRiskFinding{
								Category:         "behavioral_asset_download",
								Severity:         "HIGH",
								Component:        fmt.Sprintf("runtime asset/model URL (%s)", h),
								SourceFile:       fmt.Sprintf("%s:%d", relSlash, lineNo),
								DependencyScope:  "behavioral_heuristic",
								ExecutionContext: "server_runtime",
								EgressHosts:      []string{h},
								FailureImpact:    fmt.Sprintf("References remote model/archive/config URL (%s) in runtime code; fails or stalls if not pre-baked or disabled via env.", cleanDisplayURL),
								Mitigation:       "Pre-download the remote asset at Docker build time or configure an offline local path/env toggle.",
							})
							break
						}
					}
				}
			}

			// 1b. Runtime update, release, PyPI version check, or pricing metadata endpoints
			if checkRuntimeMetaURL && (strings.Contains(trimmed, "http://") || strings.Contains(trimmed, "https://")) {
				for _, m := range runtimeMetaOrUpdateURLRe.FindAllString(trimmed, -1) {
					parsed, err := url.Parse(m)
					if err != nil || parsed.Hostname() == "" {
						continue
					}
					h := strings.ToLower(parsed.Hostname())
					lowerLine := strings.ToLower(trimmed)
					if isPlaceholderExampleHostOrLine(h, lowerLine) {
						continue
					}
					if h == "localhost" || h == "127.0.0.1" || h == "0.0.0.0" || strings.HasSuffix(h, ".test") || strings.HasSuffix(h, ".example") || strings.HasSuffix(h, ".invalid") || strings.HasSuffix(h, ".localhost") {
						continue
					}
					key := "behavioral_runtime_api|" + h + "|" + relSlash
					if !seen[key] {
						seen[key] = true
						hosts[h] = "behavioral_code"
						cleanDisplayURL := strings.SplitN(m, "?", 2)[0]
						findings = append(findings, CheckRiskFinding{
							Category:         "behavioral_runtime_api_check",
							Severity:         "MEDIUM",
							Component:        fmt.Sprintf("runtime update/pricing API check (%s)", h),
							SourceFile:       fmt.Sprintf("%s:%d", relSlash, lineNo),
							DependencyScope:  "behavioral_heuristic",
							ExecutionContext: "server_runtime",
							EgressHosts:      []string{h},
							FailureImpact:    fmt.Sprintf("Queries external metadata/update/pricing API (%s) at runtime; fails or hangs when internet egress is blocked.", cleanDisplayURL),
							Mitigation:       "Disable online version/pricing lookups via config/ENV or cache the JSON metadata locally in the image.",
						})
					}
				}
			}

			// 2. Explicit urlretrieve() / download-and-unpack primitive
			if checkUrlRetrieve && !foundArchiveFetch && urlRetrieveRe.MatchString(trimmed) {
				key := "behavioral_urlretrieve|" + relSlash
				if !seen[key] {
					seen[key] = true
					foundArchiveFetch = true
					findings = append(findings, CheckRiskFinding{
						Category:         "behavioral_asset_download",
						Severity:         "HIGH",
						Component:        "urlretrieve() runtime file download",
						SourceFile:       fmt.Sprintf("%s:%d", relSlash, lineNo),
						DependencyScope:  "behavioral_heuristic",
						ExecutionContext: "server_runtime",
						FailureImpact:    "Downloads remote file via urlretrieve() directly inside runtime code; breaks in air-gapped networks.",
						Mitigation:       "Move asset download into Dockerfile build steps.",
					})
				}
			}
			if checkUnpack && !foundArchiveFetch && archiveUnpackRe.MatchString(trimmed) && assetExtOrHintRe.MatchString(trimmed) {
				key := "behavioral_unpack|" + relSlash
				if !seen[key] {
					seen[key] = true
					foundArchiveFetch = true
					findings = append(findings, CheckRiskFinding{
						Category:         "behavioral_asset_download",
						Severity:         "MEDIUM",
						Component:        "runtime archive download + extract",
						SourceFile:       fmt.Sprintf("%s:%d", relSlash, lineNo),
						DependencyScope:  "behavioral_heuristic",
						ExecutionContext: "server_runtime",
						FailureImpact:    "Combines HTTP download with archive extraction in runtime code; may download weights/binaries lazily on first request.",
						Mitigation:       "Extract required archives during image build and load from a read-only local directory.",
					})
				}
			}

			// 3. Subprocess runtime installers (single-line and multi-line lists up to 800 chars)
			if checkSubproc && !foundSubproc {
				matchedSubproc := subprocessNetRe.MatchString(trimmed)
				if !matchedSubproc {
					if loc := subprocessStartRe.FindStringIndex(trimmed); loc != nil {
						var wb strings.Builder
						wb.WriteString(trimmed[loc[0]:])
						endIdx := idx + 16
						if endIdx > len(lines) {
							endIdx = len(lines)
						}
						for j := idx + 1; j < endIdx && wb.Len() < 800; j++ {
							if nonCodeMask[j] {
								continue
							}
							wb.WriteByte('\n')
							wb.WriteString(lines[j])
						}
						wStr := wb.String()
						if len(wStr) > 800 {
							wStr = wStr[:800]
						}
						callSnippet := sliceUntilBalancedParen(wStr)
						if subprocessNetActionRe.MatchString(callSnippet) {
							matchedSubproc = true
						}
					}
				}
				if matchedSubproc {
					key := "behavioral_subprocess|" + relSlash
					if !seen[key] {
						seen[key] = true
						foundSubproc = true
						findings = append(findings, CheckRiskFinding{
							Category:         "behavioral_subprocess_download",
							Severity:         "CRITICAL",
							Component:        "runtime subprocess downloader/installer",
							SourceFile:       fmt.Sprintf("%s:%d", relSlash, lineNo),
							DependencyScope:  "behavioral_heuristic",
							ExecutionContext: "server_runtime",
							FailureImpact:    "Executes external package manager / curl / wget / git clone at runtime; guaranteed failure without egress network.",
							Mitigation:       "Perform all dependency, binary, and repository installation during Docker image build.",
						})
					}
				}
			}

			// 4. Python HTTP requests without timeout= (infinite hang under packet-drop air-gap firewall)
			if checkPyTimeout {
				if loc := pyReqNoTimeoutRe.FindStringIndex(trimmed); loc != nil {
					endIdx := idx + 24
					if endIdx > len(lines) {
						endIdx = len(lines)
					}
					window := trimmed[loc[0]:]
					for j := idx + 1; j < endIdx; j++ {
						if nonCodeMask[j] {
							continue
						}
						window += "\n" + lines[j]
					}
					callSnippet, closed := sliceUntilBalancedParenStatus(window)
					if closed && !strings.Contains(callSnippet, "timeout") && !strings.Contains(callSnippet, "**") {
						if noTimeoutFirstLine == 0 {
							noTimeoutFirstLine = lineNo
						}
						noTimeoutCount++
					}
				}
			}
		}

		if noTimeoutCount > 0 {
			key := "robustness_timeout|" + relSlash
			if !seen[key] {
				seen[key] = true
				hints = append(hints, CheckRiskFinding{
					Category:         "robustness_hint",
					Severity:         "LOW",
					Component:        fmt.Sprintf("HTTP client without timeout (%d call(s))", noTimeoutCount),
					SourceFile:       fmt.Sprintf("%s:%d", relSlash, noTimeoutFirstLine),
					DependencyScope:  "robustness_hint",
					ExecutionContext: "server_runtime",
					FailureImpact:    "Python requests/urllib call omits timeout= (defaults to infinite wait / ~127s OS TCP retry under DROP firewalls).",
					Mitigation:       "Always set explicit short connect/read timeouts (e.g. timeout=(2, 10)) so isolated workers fail fast instead of deadlocking.",
				})
			}
		}
	}

	// 5. Hardcoded ~/.cache or /root/.cache write alongside download logic without cache-env override
	if hasHTTPFetchInFile && homeCacheLiteralRe.MatchString(content) && !cacheEnvOverrideRe.MatchString(content) {
		key := "behavioral_cache|" + relSlash
		if !seen[key] {
			seen[key] = true
			findings = append(findings, CheckRiskFinding{
				Category:         "behavioral_cache_dir_write",
				Severity:         "MEDIUM",
				Component:        "hardcoded ~/.cache or /root/.cache download path",
				SourceFile:       relSlash,
				DependencyScope:  "behavioral_heuristic",
				ExecutionContext: "server_runtime",
				FailureImpact:    "Writes downloaded artifacts into ~/.cache without an explicit cache env override; fails on --read-only or unprivileged rootfs containers.",
				Mitigation:       "Honor XDG_CACHE_HOME / configurable cache_dir pointed at a pre-warmed image directory or writable volume.",
			})
		}
	}

	return findings, hints, hosts
}

var (
	uiTelemetryPlaceholderLineRe = regexp.MustCompile(`(?i)(?:\bplaceholder\s*[:={]|\b(?:doc_?url|docs_?url|help_?url)\s*[:=]|\bhref\s*[:=]|<a\s[^>]*href|\bwindow\.open\s*\()`)
	uiTelemetryPrevLineLinkRe    = regexp.MustCompile(`(?i)(?:\bwindow\.open\s*\([^;\)]*$|href\s*[:=]\s*\{?\s*$)`)
)

func isUITelemetryPlaceholderOrLink(relSlash, lowerContent, lineLower string, lines []string, idx int) bool {
	lowerRel := strings.ToLower(relSlash)
	if strings.HasSuffix(lowerRel, ".credential.ts") || strings.HasSuffix(lowerRel, ".credential.js") || strings.Contains(lowerContent, "implements inodecredential") {
		return true
	}
	if uiTelemetryPlaceholderLineRe.MatchString(lineLower) {
		return true
	}
	for back := 1; back <= 2 && idx-back >= 0; back++ {
		prev := strings.TrimSpace(strings.ToLower(lines[idx-back]))
		if prev == "" || isCommentLine(prev) {
			continue
		}
		if uiTelemetryPrevLineLinkRe.MatchString(prev) {
			return true
		}
		break
	}
	return false
}

// AnalyzeSourceTelemetryURLs detects direct outbound telemetry/OTLP/tracing URL literals in non-comment
// runtime source files (catching custom stdlib/urllib telemetry senders such as browser-use PostHog,
// dify OTLP endpoints, and openai-agents tracing ingest even when no third-party telemetry SDK is listed).
func AnalyzeSourceTelemetryURLs(relSlash, content string, nonCodeMask []bool, isBrowser bool, seen map[string]bool) ([]CheckRiskFinding, map[string]string) {
	var findings []CheckRiskFinding
	hosts := make(map[string]string)
	if (!strings.Contains(content, "http://") && !strings.Contains(content, "https://")) || !sourceTelemetryURLRe.MatchString(content) {
		return findings, hosts
	}
	lowerContent := strings.ToLower(content)
	if strings.HasSuffix(strings.ToLower(relSlash), ".credential.ts") || strings.HasSuffix(strings.ToLower(relSlash), ".credential.js") || strings.Contains(lowerContent, "implements inodecredential") {
		return findings, hosts
	}
	lines := strings.Split(content, "\n")
	hasHTTPFetchInFile := FileHasHTTPClient(content) && HasActiveHTTPClient(lines, nonCodeMask)
	for idx, rawLine := range lines {
		if idx < len(nonCodeMask) && nonCodeMask[idx] {
			continue
		}
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || isCommentLine(trimmed) || (!strings.Contains(trimmed, "http://") && !strings.Contains(trimmed, "https://")) {
			continue
		}
		if IsHashVerificationLine(trimmed, content, hasHTTPFetchInFile) {
			continue
		}
		lineLower := strings.ToLower(trimmed)
		if isUITelemetryPlaceholderOrLink(relSlash, lowerContent, lineLower, lines, idx) {
			continue
		}
		for _, m := range sourceTelemetryURLRe.FindAllString(trimmed, -1) {
			parsed, err := url.Parse(m)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			h := strings.ToLower(parsed.Hostname())
			if isPlaceholderExampleHostOrLine(h, lineLower) {
				continue
			}
			key := "source_tel|" + h + "|" + relSlash
			if seen[key] {
				continue
			}
			seen[key] = true
			hosts[h] = "static_code"
			execCtx := "server_runtime"
			autoSealed := false
			comp := fmt.Sprintf("telemetry endpoint (%s)", h)
			impact := fmt.Sprintf("Runtime source references outbound telemetry endpoint %s.", strings.SplitN(m, "?", 2)[0])
			mitigation := "Disable telemetry via runtime config/ENV or block the host at the egress proxy."

			switch {
			case strings.Contains(m, "/v1/traces/ingest"):
				comp = "openai-agents tracing ingest (/v1/traces/ingest)"
				autoSealed = true
				mitigation = "Set OPENAI_AGENTS_DISABLE_TRACING=1 in container ENV or disable tracing in code."
			case strings.Contains(h, "posthog.com"):
				if strings.Contains(lowerContent, "anonymized_telemetry") {
					autoSealed = true
				}
			case strings.HasPrefix(h, "otel.") || strings.Contains(h, ".otel."):
				if strings.Contains(lowerContent, "otel_") || strings.Contains(lowerContent, "telemetry") {
					autoSealed = true
				}
			}
			if isBrowser {
				execCtx = "browser_client"
				autoSealed = false
				impact = fmt.Sprintf("Client-side source in %s sends telemetry from the end-user's browser to %s.", relSlash, h)
				mitigation = "Server environment variables do NOT disable browser SDKs; gate SDK initialization in frontend source code."
			}

			findings = append(findings, CheckRiskFinding{
				Category:         "telemetry_analytics",
				Severity:         "MEDIUM",
				Component:        comp,
				SourceFile:       fmt.Sprintf("%s:%d", relSlash, idx+1),
				DependencyScope:  "source_call",
				ExecutionContext: execCtx,
				EgressHosts:      []string{h},
				FailureImpact:    impact,
				Mitigation:       mitigation,
				AutoSealedByEnv:  autoSealed,
			})
		}
	}
	return findings, hosts
}

func sliceUntilBalancedParenStatus(s string) (string, bool) {
	openIdx := strings.IndexByte(s, '(')
	if openIdx < 0 {
		return s, false
	}
	depth := 0
	inQuote := byte(0)
	for i := openIdx; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth <= 0 {
				return s[:i+1], true
			}
		}
	}
	return s, false
}

func sliceUntilBalancedParen(s string) string {
	res, _ := sliceUntilBalancedParenStatus(s)
	return res
}

func hasLocalFilesOnlyTrueNearby(content string, callEndIdx int) bool {
	end := callEndIdx + 240
	if end > len(content) {
		end = len(content)
	}
	snippet := sliceUntilBalancedParen(content[callEndIdx:end])
	lower := strings.ToLower(strings.ReplaceAll(snippet, " ", ""))
	return strings.Contains(lower, "local_files_only=true")
}

func matchesEcosystem(ruleEcos []string, manifestFormat string) bool {
	if len(ruleEcos) == 0 || manifestFormat == "" {
		return true
	}
	for _, e := range ruleEcos {
		if e == manifestFormat {
			return true
		}
	}
	return false
}
