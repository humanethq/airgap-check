package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

const defaultHermeticRuntimeEnv = "DO_NOT_TRACK=1 NEXT_TELEMETRY_DISABLED=1 ANONYMIZED_TELEMETRY=False SCARF_NO_ANALYTICS=true HF_HUB_DISABLE_TELEMETRY=1 LANGCHAIN_TRACING_V2=false LANGFUSE_ENABLED=false CREWAI_DISABLE_TELEMETRY=true OTEL_SDK_DISABLED=true DD_TRACE_ENABLED=false WANDB_MODE=offline WANDB_DISABLED=true GRADIO_ANALYTICS_ENABLED=False LITELLM_LOCAL_MODEL_COST_MAP=True STREAMLIT_BROWSER_GATHER_USAGE_STATS=false XDG_CACHE_HOME=/app/.cache TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken HF_HOME=/app/.cache/huggingface NLTK_DATA=/app/.cache/nltk_data EASYOCR_MODULE_PATH=/app/.cache/easyocr TORCH_HOME=/app/.cache/torch"

func formatDependencyScopeBadge(scope string) string {
	switch scope {
	case "prod":
		return "PROD DEP"
	case "optional_extra":
		return "OPTIONAL EXTRA"
	case "transitive_lockfile":
		return "TRANSITIVE LOCKFILE"
	case "source_call":
		return "SOURCE CALL"
	case "behavioral_heuristic":
		return "BEHAVIORAL HEURISTIC"
	case "robustness_hint":
		return "ROBUSTNESS HINT"
	default:
		return "DETECTED"
	}
}

func printCheckReportHuman(out io.Writer, r *CheckReport, showFix bool) {
	_, _ = fmt.Fprintln(out, "┌─────────────────────────────────────────────────────────────────────────────┐")
	_, _ = fmt.Fprintln(out, "│                   AIRGAP-CHECK: OFFLINE & TELEMETRY AUDIT                   │")
	_, _ = fmt.Fprintln(out, "└─────────────────────────────────────────────────────────────────────────────┘")
	_, _ = fmt.Fprintf(out, "  Target Repository : %s\n", r.TargetPath)
	_, _ = fmt.Fprintf(out, "  Test Scope        : %s (%d manifests, %d lockfiles, %d source files, %d .env files)\n",
		r.Scope.Mode, len(r.Scope.InspectedManifests), len(r.Scope.InspectedLockfiles), r.Scope.ScannedSourceFiles, len(r.Scope.InspectedEnvFiles))
	_, _ = fmt.Fprintf(out, "  Scope Note        : %s\n", r.Scope.LimitationsNote)
	_, _ = fmt.Fprintf(out, "  Verdict           : %s\n\n", r.AirgapReadinessVerdict)

	if r.DynamicRun != nil {
		_, _ = fmt.Fprintln(out, "0. DYNAMIC AIR-GAP EXECUTION (`docker run --rm --network none`)")
		buildNote := ""
		if r.DynamicRun.AutoBuiltImage {
			buildNote = " (auto-built from Dockerfile)"
		}
		_, _ = fmt.Fprintf(out, "   Image / Command  : %s%s -> `%s`\n", r.DynamicRun.DockerImage, buildNote, r.DynamicRun.Command)
		if r.DynamicRun.ObserverRuntime != "" {
			_, _ = fmt.Fprintf(out, "   Observer Runtime : %s\n", r.DynamicRun.ObserverRuntime)
		}
		_, _ = fmt.Fprintf(out, "   Exit / Duration  : exit=%d (%dms) | crashed_in_airgap=%v\n",
			r.DynamicRun.ExitCode, r.DynamicRun.DurationMs, r.DynamicRun.CrashedInAirgap)
		if r.DynamicRun.FailureCategory != "" {
			_, _ = fmt.Fprintf(out, "   Failure Category : %s\n", r.DynamicRun.FailureCategory)
		}
		if len(r.DynamicRun.ObservedAttempts) == 0 {
			_, _ = fmt.Fprintln(out, "   Observed Egress  : 0 outbound DNS/TCP/TLS/HTTP attempts observed.")
		} else {
			_, _ = fmt.Fprintf(out, "   Observed Egress  : %d outbound attempt(s) intercepted by --network none sinkhole:\n", len(r.DynamicRun.ObservedAttempts))
			for _, att := range r.DynamicRun.ObservedAttempts {
				_, _ = fmt.Fprintf(out, "     • [%s] %s:%d (%s)\n", att.Protocol, att.Host, att.Port, att.Detail)
			}
		}
		if r.DynamicRun.StderrSnippet != "" {
			_, _ = fmt.Fprintf(out, "   Stderr Excerpt   :\n     %s\n", strings.ReplaceAll(r.DynamicRun.StderrSnippet, "\n", "\n     "))
		}
		_, _ = fmt.Fprintln(out)
	}

	_, _ = fmt.Fprintf(out, "1. AIR-GAP RUNTIME CRASH RISKS (%d found)\n", len(r.AirgapCrashRisks))
	if len(r.AirgapCrashRisks) == 0 {
		_, _ = fmt.Fprintln(out, "   • No known runtime downloader packages or calls found in static scan.")
	} else {
		for _, f := range r.AirgapCrashRisks {
			actionBadge := "BUILD-TIME BAKE REQUIRED"
			if f.AutoSealedByEnv {
				actionBadge = "SILENCE VIA ENV (--fix)"
			}
			_, _ = fmt.Fprintf(out, "   • [%s | %s | %s] %s (%s)\n", f.Severity, formatDependencyScopeBadge(f.DependencyScope), actionBadge, f.Component, f.SourceFile)
			if len(f.EgressHosts) > 0 {
				_, _ = fmt.Fprintf(out, "     Egress   : %s\n", strings.Join(f.EgressHosts, ", "))
			}
			_, _ = fmt.Fprintf(out, "     Impact   : %s\n", f.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", f.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "2. BEHAVIORAL & UNKNOWN-LIBRARY DOWNLOAD PATTERNS (%d found)\n", len(r.BehavioralFindings))
	if len(r.BehavioralFindings) == 0 {
		_, _ = fmt.Fprintln(out, "   • No generic remote asset URLs, subprocess installers, or hardcoded ~/.cache downloads detected.")
	} else {
		for _, f := range r.BehavioralFindings {
			_, _ = fmt.Fprintf(out, "   • [%s | %s] %s (%s)\n", f.Severity, f.Category, f.Component, f.SourceFile)
			if len(f.EgressHosts) > 0 {
				_, _ = fmt.Fprintf(out, "     Egress   : %s\n", strings.Join(f.EgressHosts, ", "))
			}
			_, _ = fmt.Fprintf(out, "     Impact   : %s\n", f.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", f.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "3. TELEMETRY & EXTERNAL ANALYTICS (%d found)\n", len(r.TelemetryLeakRisks))
	if len(r.TelemetryLeakRisks) == 0 {
		_, _ = fmt.Fprintln(out, "   • None detected in static scan.")
	} else {
		for _, f := range r.TelemetryLeakRisks {
			badge := "SERVER RUNTIME — REVIEW REQUIRED"
			if f.ExecutionContext == "browser_client" {
				badge = "BROWSER CLIENT — SERVER ENV DOES NOT SILENCE"
			} else if f.AutoSealedByEnv {
				badge = "SERVER RUNTIME — SILENCE VIA ENV (--fix)"
			}
			scopeTag := formatDependencyScopeBadge(f.DependencyScope)
			_, _ = fmt.Fprintf(out, "   • [%s | %s | %s] %s (%s)\n", f.Severity, scopeTag, badge, f.Component, f.SourceFile)
			if len(f.EgressHosts) > 0 {
				_, _ = fmt.Fprintf(out, "     Egress   : %s\n", strings.Join(f.EgressHosts, ", "))
			}
			_, _ = fmt.Fprintf(out, "     Behavior : %s\n", f.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", f.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "4. .ENV CREDENTIALS & USAGE CLASSIFICATION (%d found — values never read/logged)\n", len(r.SecretRecommendations))
	if len(r.SecretRecommendations) == 0 {
		_, _ = fmt.Fprintln(out, "   • No credentials detected in .env files.")
	} else {
		for _, rec := range r.SecretRecommendations {
			gitStatus := "untracked (.gitignore)"
			if rec.GitTracked {
				gitStatus = "WARNING: TRACKED IN GIT"
			}
			_, _ = fmt.Fprintf(out, "   • %s [%s | %s]\n", rec.SecretKey, rec.UsageKind, gitStatus)
			_, _ = fmt.Fprintf(out, "     Analysis : %s\n", rec.Explanation)
			_, _ = fmt.Fprintf(out, "     Guidance : %s\n", rec.Guidance)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "5. OBSERVED & REFERENCED EXTERNAL HOSTS (%d hosts)\n", len(r.AllowedEgressManifest))
	if len(r.AllowedEgressManifest) == 0 {
		_, _ = fmt.Fprintln(out, "   • None detected.")
	} else {
		_, _ = fmt.Fprintf(out, "   %-36s %-22s %-24s %-30s\n", "HOST", "SOURCE", "CLASSIFICATION", "HANDLING")
		for _, m := range r.AllowedEgressManifest {
			_, _ = fmt.Fprintf(out, "   %-36s %-22s %-24s %-30s\n", m.Host, m.Source, m.Classification, m.PolicyAction)
		}
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "6. ROBUSTNESS HINTS — ADVISORY, NOT ASSET DOWNLOADS (%d found)\n", len(r.RobustnessHints))
	if len(r.RobustnessHints) == 0 {
		_, _ = fmt.Fprintln(out, "   • No unbounded requests/urllib calls without timeout= detected.")
	} else {
		for _, h := range r.RobustnessHints {
			_, _ = fmt.Fprintf(out, "   • [%s] %s (%s)\n", h.Severity, h.Component, h.SourceFile)
			_, _ = fmt.Fprintf(out, "     Impact   : %s\n", h.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", h.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "7. RECOMMENDED OFFLINE ENV FLAGS (pass `--fix` for a ready-to-paste Dockerfile block)\n   %s\n", strings.Join(r.HermeticBuildEnv, " "))
	if showFix && r.RemediationDockerfileSnippet != "" {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "8. STANDALONE DOCKERFILE REMEDIATION (`--fix` — paste into your Dockerfile)")
		for _, line := range strings.Split(r.RemediationDockerfileSnippet, "\n") {
			_, _ = fmt.Fprintf(out, "   %s\n", line)
		}
	}
}

func generateRemediationDockerfileSnippet(r *CheckReport) string {
	var b strings.Builder
	b.WriteString("# --- BEGIN AIR-GAP & TELEMETRY REMEDIATION (paste into your Dockerfile) ---\n")
	b.WriteString("# 1. Silence background SDK telemetry, online cost-map lookups & enforce writable cache paths\n")
	b.WriteString("ENV DO_NOT_TRACK=1 \\\n")
	b.WriteString("    NEXT_TELEMETRY_DISABLED=1 \\\n")
	b.WriteString("    ANONYMIZED_TELEMETRY=False \\\n")
	b.WriteString("    CHROMA_TELEMETRY_IMPL=none \\\n")
	b.WriteString("    SCARF_NO_ANALYTICS=true \\\n")
	b.WriteString("    HF_HUB_DISABLE_TELEMETRY=1 \\\n")
	b.WriteString("    HF_HUB_OFFLINE=1 \\\n")
	b.WriteString("    TRANSFORMERS_OFFLINE=1 \\\n")
	b.WriteString("    LANGCHAIN_TRACING_V2=false \\\n")
	b.WriteString("    LANGFUSE_ENABLED=false \\\n")
	b.WriteString("    CREWAI_DISABLE_TELEMETRY=true \\\n")
	b.WriteString("    OTEL_SDK_DISABLED=true \\\n")
	b.WriteString("    DD_TRACE_ENABLED=false \\\n")
	b.WriteString("    WANDB_MODE=offline \\\n")
	b.WriteString("    WANDB_DISABLED=true \\\n")
	b.WriteString("    GRADIO_ANALYTICS_ENABLED=False \\\n")
	b.WriteString("    LITELLM_LOCAL_MODEL_COST_MAP=True \\\n")
	b.WriteString("    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \\\n")
	b.WriteString("    XDG_CACHE_HOME=/app/.cache \\\n")
	b.WriteString("    TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken \\\n")
	b.WriteString("    HF_HOME=/app/.cache/huggingface \\\n")
	b.WriteString("    NLTK_DATA=/app/.cache/nltk_data \\\n")
	b.WriteString("    EASYOCR_MODULE_PATH=/app/.cache/easyocr \\\n")
	b.WriteString("    TORCH_HOME=/app/.cache/torch \\\n")
	b.WriteString("    PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright \\\n")
	b.WriteString("    PUPPETEER_CACHE_DIR=/app/.cache/puppeteer\n")
	b.WriteString("RUN mkdir -p /app/.cache/tiktoken /app/.cache/huggingface /app/.cache/nltk_data /app/.cache/easyocr /app/.cache/torch /app/.cache/ms-playwright /app/.cache/puppeteer\n")

	seenComp := make(map[string]bool)
	for _, f := range r.AirgapCrashRisks {
		comp := strings.ToLower(f.Component)
		switch {
		case strings.Contains(comp, "tiktoken") && !seenComp["tiktoken"]:
			seenComp["tiktoken"] = true
			b.WriteString("\n# Pre-warm Python tiktoken BPE encodings (cl100k_base & o200k_base) at build time\n")
			b.WriteString("RUN TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken python3 -c \"import tiktoken; [tiktoken.get_encoding(e) for e in ('cl100k_base', 'o200k_base')]\"\n")
		case strings.Contains(comp, "chromadb") && !seenComp["chromadb"]:
			seenComp["chromadb"] = true
			b.WriteString("\n# Pre-warm ChromaDB default ONNX embedding model (all-MiniLM-L6-v2) at build time\n")
			b.WriteString("RUN HOME=/app XDG_CACHE_HOME=/app/.cache python3 -c \"from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2; ef = ONNXMiniLM_L6_V2(); ef(['airgap-warmup'])\"\n")
		case strings.Contains(comp, "fastembed") && !seenComp["fastembed"]:
			seenComp["fastembed"] = true
			b.WriteString("\n# Pre-warm FastEmbed default ONNX model into /app/.cache/fastembed at build time\n")
			b.WriteString("RUN python3 -c \"from fastembed import TextEmbedding; list(TextEmbedding(cache_dir='/app/.cache/fastembed').embed(['airgap-warmup']))\"\n")
		case (strings.Contains(comp, "transformers") || strings.Contains(comp, "huggingface") || strings.Contains(comp, "flagembedding")) && !seenComp["hf"]:
			seenComp["hf"] = true
			b.WriteString("\n# Pre-download HuggingFace model weights during build BEFORE setting HF_HUB_OFFLINE=1 (replace <MODEL_ID>)\n")
			b.WriteString("# RUN HF_HOME=/app/.cache/huggingface HF_HUB_OFFLINE=0 python3 -c \"from huggingface_hub import snapshot_download; snapshot_download('<MODEL_ID>')\"\n")
		case strings.Contains(comp, "easyocr") && !seenComp["easyocr"]:
			seenComp["easyocr"] = true
			b.WriteString("\n# Pre-download EasyOCR detection/recognition weights during build\n")
			b.WriteString("RUN EASYOCR_MODULE_PATH=/app/.cache/easyocr python3 -c \"import easyocr; easyocr.Reader(['en'], gpu=False, model_storage_directory='/app/.cache/easyocr')\"\n")
		case strings.Contains(comp, "rapidocr") && !seenComp["rapidocr"]:
			seenComp["rapidocr"] = true
			b.WriteString("\n# Pre-warm RapidOCR ONNX models during build (adapt import if using rapidocr package directly)\n")
			b.WriteString("# RUN python3 -c \"from rapidocr_onnxruntime import RapidOCR; RapidOCR()\"\n")
		case strings.Contains(comp, "paddleocr") && !seenComp["paddleocr"]:
			seenComp["paddleocr"] = true
			b.WriteString("\n# Pre-warm PaddleOCR model weights into /app/.paddleocr during build\n")
			b.WriteString("# RUN HOME=/app python3 -c \"from paddleocr import PaddleOCR; PaddleOCR(lang='en')\"\n")
		case strings.Contains(comp, "nltk") && !seenComp["nltk"]:
			seenComp["nltk"] = true
			b.WriteString("\n# Pre-download NLTK corpora into /app/.cache/nltk_data during build\n")
			b.WriteString("RUN python3 -m nltk.downloader -d /app/.cache/nltk_data punkt punkt_tab stopwords averaged_perceptron_tagger\n")
		case strings.Contains(comp, "spacy") && !seenComp["spacy"]:
			seenComp["spacy"] = true
			b.WriteString("\n# Pre-install spaCy pipeline wheel during build\n")
			b.WriteString("RUN python3 -m spacy download en_core_web_sm\n")
		case strings.Contains(comp, "whisper") && !seenComp["whisper"]:
			seenComp["whisper"] = true
			b.WriteString("\n# Pre-warm OpenAI Whisper checkpoint into /app/.cache/whisper during build\n")
			b.WriteString("RUN XDG_CACHE_HOME=/app/.cache python3 -c \"import whisper; whisper.load_model('base')\"\n")
		case strings.Contains(comp, "playwright") && !seenComp["playwright"]:
			seenComp["playwright"] = true
			b.WriteString("\n# Pre-install Playwright Chromium headless browser binary during build\n")
			if strings.Contains(f.SourceFile, "package.json") || strings.Contains(f.SourceFile, "lock.yaml") || strings.Contains(f.SourceFile, "package-lock.json") || strings.Contains(f.SourceFile, "yarn.lock") {
				b.WriteString("RUN PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright npx playwright install --with-deps chromium\n")
			} else {
				b.WriteString("RUN PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright python3 -m playwright install --with-deps chromium\n")
			}
		case strings.Contains(comp, "puppeteer") && !seenComp["puppeteer"]:
			seenComp["puppeteer"] = true
			b.WriteString("\n# Pre-install Puppeteer Chrome binary into PUPPETEER_CACHE_DIR during build\n")
			b.WriteString("RUN PUPPETEER_CACHE_DIR=/app/.cache/puppeteer npx puppeteer browsers install chrome\n")
		}
	}

	hasTimeoutWarning := len(r.RobustnessHints) > 0
	var behavioralHosts []string
	seenBHost := make(map[string]bool)
	for _, bf := range r.BehavioralFindings {
		for _, h := range bf.EgressHosts {
			if !seenBHost[h] {
				seenBHost[h] = true
				behavioralHosts = append(behavioralHosts, h)
			}
		}
	}
	if r.DynamicRun != nil {
		for _, att := range r.DynamicRun.ObservedAttempts {
			if att.Host != "" && !seenBHost[att.Host] {
				seenBHost[att.Host] = true
				behavioralHosts = append(behavioralHosts, att.Host)
			}
		}
	}
	if len(behavioralHosts) > 0 {
		sort.Strings(behavioralHosts)
		b.WriteString(fmt.Sprintf("\n# ACTION: Pre-fetch or mock assets served from dynamically/behaviorally detected hosts: %s\n", strings.Join(behavioralHosts, ", ")))
	}
	if hasTimeoutWarning {
		b.WriteString("# ACTION: Add explicit timeout=(2, 10) to requests/urllib HTTP calls flagged in Section 6 (Robustness Hints) to avoid infinite hangs.\n")
	}

	b.WriteString("# --- END AIR-GAP & TELEMETRY REMEDIATION ---")
	return b.String()
}
