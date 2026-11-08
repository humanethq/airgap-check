package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const defaultHermeticRuntimeEnv = "DO_NOT_TRACK=1 NEXT_TELEMETRY_DISABLED=1 ANONYMIZED_TELEMETRY=False SCARF_NO_ANALYTICS=true HF_HUB_DISABLE_TELEMETRY=1 LANGCHAIN_TRACING_V2=false CREWAI_DISABLE_TELEMETRY=true OTEL_SDK_DISABLED=true STREAMLIT_BROWSER_GATHER_USAGE_STATS=false XDG_CACHE_HOME=/app/.cache TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken HF_HOME=/app/.cache/huggingface"

// EnvFileScopeInfo records an inspected .env file and whether it is tracked in git.
type EnvFileScopeInfo struct {
	RelPath    string `json:"rel_path"`
	GitTracked bool   `json:"git_tracked"`
}

// CheckScope explicitly states what was and was not tested during `airgap-check`.
type CheckScope struct {
	Mode               string             `json:"mode"`
	InspectedManifests []string           `json:"inspected_manifests"`
	InspectedEnvFiles  []EnvFileScopeInfo `json:"inspected_env_files"`
	ScannedSourceFiles int                `json:"scanned_source_files"`
	LimitationsNote    string             `json:"limitations_note"`
}

// CheckRiskFinding describes a static or runtime air-gap / telemetry / egress risk.
type CheckRiskFinding struct {
	Category         string   `json:"category"`
	Severity         string   `json:"severity"`
	Component        string   `json:"component"`
	SourceFile       string   `json:"source_file"`
	ExecutionContext string   `json:"execution_context"`
	EgressHosts      []string `json:"egress_hosts,omitempty"`
	FailureImpact    string   `json:"failure_impact"`
	Mitigation       string   `json:"mitigation"`
	AutoSealedByEnv  bool     `json:"auto_sealed_by_env"`
}

// SecretRecommendation classifies an environment key by how it is used on the wire vs locally.
type SecretRecommendation struct {
	SecretKey        string   `json:"secret_key"`
	SourceFile       string   `json:"source_file"`
	GitTracked       bool     `json:"git_tracked"`
	UsageKind        string   `json:"usage_kind"` // "wire_api_key", "local_signing_or_internal", "signed_request_flow", "needs_review"
	ProxyEligible    bool     `json:"proxy_eligible"`
	Explanation      string   `json:"explanation"`
	RecommendedHosts []string `json:"recommended_hosts,omitempty"`
	Guidance         string   `json:"guidance,omitempty"`
}

// EgressManifestEntry summarizes a referenced or dynamically observed external host.
type EgressManifestEntry struct {
	Host           string `json:"host"`
	Source         string `json:"source"`
	Classification string `json:"classification"`
	PolicyAction   string `json:"policy_action"`
}

// CheckReport is the calibrated output of `airgap-check [path]`.
type CheckReport struct {
	TargetPath                   string                 `json:"target_path"`
	Scope                        CheckScope             `json:"scope"`
	AirgapCrashRisks             []CheckRiskFinding     `json:"airgap_crash_risks"`
	TelemetryLeakRisks           []CheckRiskFinding     `json:"telemetry_leak_risks"`
	EgressAndSecretRisks         []CheckRiskFinding     `json:"egress_and_secret_risks"`
	AllowedEgressManifest        []EgressManifestEntry  `json:"allowed_egress_manifest"`
	SecretRecommendations        []SecretRecommendation `json:"secret_recommendations"`
	HermeticBuildEnv             []string               `json:"hermetic_build_env"`
	RemediationDockerfileSnippet string                 `json:"remediation_dockerfile_snippet,omitempty"`
	DynamicRun                   *DynamicCheckResult    `json:"dynamic_run,omitempty"`
	AirgapReadinessVerdict       string                 `json:"airgap_readiness_verdict"`
}

type knownPackageRule struct {
	matchSubstr string
	component   string
	category    string
	severity    string
	pythonOnly  bool
	hosts       []string
	impact      string
	mitigation  string
	autoSealed  bool
}

var knownAirgapAndTelemetryRules = []knownPackageRule{
	{
		matchSubstr: "tiktoken",
		component:   "tiktoken",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		pythonOnly:  true,
		hosts:       []string{"openaipublic.blob.core.windows.net"},
		impact:      "Python tiktoken downloads cl100k_base/o200k_base BPE encodings over HTTPS on first call; crashes with ConnectionError in --network none.",
		mitigation:  "Pre-warm cl100k_base & o200k_base into TIKTOKEN_CACHE_DIR during image build (see `--fix` Dockerfile snippet).",
		autoSealed:  false,
	},
	{
		matchSubstr: "chromadb",
		component:   "chromadb (default ONNX embedding)",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		pythonOnly:  true,
		hosts:       []string{"chroma-onnx-models.s3.amazonaws.com"},
		impact:      "Calling collection.add() with the default embedding function downloads all-MiniLM-L6-v2 ONNX weights from chroma-onnx-models.s3.amazonaws.com; crashes with ConnectError in --network none.",
		mitigation:  "Pass an explicit offline/local embedding_function or pre-populate ~/.cache/chroma/onnx_models/all-MiniLM-L6-v2 during build (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "fastembed",
		component:   "fastembed",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		pythonOnly:  true,
		hosts:       []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:      "TextEmbedding() hangs for ~39s (3s+9s+27s retry backoff) attempting to download ONNX models from HuggingFace/GCS before crashing with ValueError in --network none.",
		mitigation:  "Pre-populate fastembed cache_dir during image build and pass local_files_only=True (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "sentence-transformers",
		component:   "sentence-transformers",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		hosts:       []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:      "Fetches embedding weights and tokenizer configs from HuggingFace Hub at runtime; fails with ConnectionError in offline networks.",
		mitigation:  "Pre-download model weights into HF_HOME during build and set HF_HUB_OFFLINE=1 (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "transformers",
		component:   "transformers",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		hosts:       []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:      "Calls huggingface.co API (5 retries with exponential backoff) for model/tokenizer metadata on startup unless local_files_only=True and weights are cached.",
		mitigation:  "Pre-populate HF_HOME during build and set TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "whisper",
		component:   "whisper",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		hosts:       []string{"openaipublic.azureedge.net"},
		impact:      "Downloads Whisper .pt checkpoints at runtime into ~/.cache/whisper.",
		mitigation:  "Pre-download Whisper model checkpoints into XDG_CACHE_HOME/whisper during build (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "spacy",
		component:   "spacy",
		category:    "runtime_model_asset",
		severity:    "HIGH",
		hosts:       []string{"raw.githubusercontent.com"},
		impact:      "spacy.cli.download fetches language pipelines at runtime if not installed as a wheel in requirements.txt.",
		mitigation:  "Pin the spacy model wheel URL in requirements.txt or run `python3 -m spacy download` during build (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "nltk",
		component:   "nltk",
		category:    "runtime_model_asset",
		severity:    "HIGH",
		hosts:       []string{"raw.githubusercontent.com"},
		impact:      "nltk.download() fetches corpora over GitHub raw URLs at runtime; fails with ValueError/URLError in --network none.",
		mitigation:  "Pre-download NLTK_DATA into the image during build via `python3 -m nltk.downloader` (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "playwright",
		component:   "playwright",
		category:    "runtime_model_asset",
		severity:    "CRITICAL",
		hosts:       []string{"playwright.azureedge.net"},
		impact:      "Requires headless browser binaries (chromium/firefox/webkit) downloaded from playwright.azureedge.net; fails at launch if missing.",
		mitigation:  "Run `playwright install --with-deps chromium` with PLAYWRIGHT_BROWSERS_PATH during image build (see `--fix`).",
		autoSealed:  false,
	},
	{
		matchSubstr: "chromadb",
		component:   "chromadb",
		category:    "telemetry_analytics",
		severity:    "HIGH",
		hosts:       []string{"us.i.posthog.com", "eu.i.posthog.com"},
		impact:      "ChromaDB client/server emits PostHog telemetry events by default unless ANONYMIZED_TELEMETRY=False is set.",
		mitigation:  "Set ANONYMIZED_TELEMETRY=False and CHROMA_TELEMETRY_IMPL=none in container ENV.",
		autoSealed:  true,
	},
	{
		matchSubstr: "crewai",
		component:   "crewai",
		category:    "telemetry_analytics",
		severity:    "HIGH",
		hosts:       []string{"telemetry.crewai.com"},
		impact:      "CrewAI spawns background OTLP threads connecting to telemetry.crewai.com:4319 unless disabled.",
		mitigation:  "Set CREWAI_DISABLE_TELEMETRY=true and OTEL_SDK_DISABLED=true in container ENV.",
		autoSealed:  true,
	},
	{
		matchSubstr: "posthog",
		component:   "posthog",
		category:    "telemetry_analytics",
		severity:    "MEDIUM",
		hosts:       []string{"us.i.posthog.com", "app.posthog.com"},
		impact:      "Sends usage analytics to PostHog endpoints.",
		mitigation:  "If used in browser (posthog-js), requests leave from the end-user's browser and server env vars do NOT disable it; disable posthog.init() in client code for offline deployments.",
		autoSealed:  false,
	},
	{
		matchSubstr: "sentry",
		component:   "sentry-sdk",
		category:    "telemetry_analytics",
		severity:    "MEDIUM",
		hosts:       []string{"ingest.sentry.io", "sentry.io"},
		impact:      "Ships stack traces and local context to Sentry ingest servers when a DSN is configured.",
		mitigation:  "Leave SENTRY_DSN unset in offline/regulated deployments or block *.sentry.io at the egress proxy.",
		autoSealed:  false,
	},
	{
		matchSubstr: "langsmith",
		component:   "langsmith",
		category:    "telemetry_analytics",
		severity:    "HIGH",
		hosts:       []string{"api.smith.langchain.com"},
		impact:      "Uploads LLM prompts and completions to LangSmith cloud when LANGCHAIN_TRACING_V2 is enabled.",
		mitigation:  "Set LANGCHAIN_TRACING_V2=false in container ENV.",
		autoSealed:  true,
	},
	{
		matchSubstr: "scarf",
		component:   "scarf",
		category:    "telemetry_analytics",
		severity:    "LOW",
		hosts:       []string{"scarf.sh"},
		impact:      "Reports package import/install telemetry to scarf.sh.",
		mitigation:  "Set SCARF_NO_ANALYTICS=true and DO_NOT_TRACK=1 in container ENV.",
		autoSealed:  true,
	},
}

type sourceCodePatternRule struct {
	re         *regexp.Regexp
	component  string
	category   string
	severity   string
	hosts      []string
	impact     string
	mitigation string
	autoSealed bool
}

var sourceCodeDownloadRules = []sourceCodePatternRule{
	{
		re:         regexp.MustCompile(`\bnltk\.download\s*\(`),
		component:  "nltk.download()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "Explicit nltk.download() call in source code attempts an outbound HTTPS fetch to GitHub raw URLs at runtime.",
		mitigation: "Move nltk.download() to the Dockerfile build stage and set NLTK_DATA.",
		autoSealed: false,
	},
	{
		re:         regexp.MustCompile(`\bspacy\.cli\.download\s*\(`),
		component:  "spacy.cli.download()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"raw.githubusercontent.com"},
		impact:     "Explicit spacy.cli.download() call in source code invokes pip/HTTP download at runtime.",
		mitigation: "Install the spacy model wheel during image build instead of calling spacy.cli.download() at runtime.",
		autoSealed: false,
	},
	{
		re:         regexp.MustCompile(`\b(?:from_pretrained|hf_hub_download|snapshot_download)\s*\(`),
		component:  "huggingface_hub.from_pretrained/download",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"huggingface.co", "cdn-lfs.hf.co"},
		impact:     "Calls HuggingFace Hub over HTTPS to check/download model weights unless local_files_only=True and weights exist locally.",
		mitigation: "Pre-bake model weights into HF_HOME during build and set HF_HUB_OFFLINE=1.",
		autoSealed: false,
	},
	{
		re:         regexp.MustCompile(`\btorch\.hub\.load\s*\(`),
		component:  "torch.hub.load()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"github.com", "download.pytorch.org"},
		impact:     "Downloads PyTorch repository code and checkpoints over HTTPS at runtime.",
		mitigation: "Pre-populate TORCH_HOME in the container image during build.",
		autoSealed: false,
	},
	{
		re:         regexp.MustCompile(`\bwhisper\.load_model\s*\(`),
		component:  "whisper.load_model()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.azureedge.net"},
		impact:     "Downloads Whisper model checkpoint from openaipublic.azureedge.net if not present in cache.",
		mitigation: "Pre-download the .pt model during build and pass download_root to whisper.load_model().",
		autoSealed: false,
	},
	{
		re:         regexp.MustCompile(`\btiktoken\.(?:get_encoding|encoding_for_model)\s*\(`),
		component:  "tiktoken.get_encoding()",
		category:   "runtime_model_asset",
		severity:   "CRITICAL",
		hosts:      []string{"openaipublic.blob.core.windows.net"},
		impact:     "Downloads BPE encoding file from openaipublic.blob.core.windows.net on first call if TIKTOKEN_CACHE_DIR is unpopulated.",
		mitigation: "Pre-warm cl100k_base & o200k_base into TIKTOKEN_CACHE_DIR at build time (see `--fix`).",
		autoSealed: false,
	},
}

var (
	httpsURLRegex = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::[0-9]+)?(/[^\s"'` + "`" + `)]*)?`)
	envKeyRegex   = regexp.MustCompile(`^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$`)
)

func main() {
	var (
		jsonOutput  bool
		dynamicRun  bool
		showFix     bool
		dockerImage string
		runCmd      string
		timeoutSec  int
	)
	flag.BoolVar(&jsonOutput, "json", false, "Output audit report in JSON format")
	flag.BoolVar(&dynamicRun, "run", false, "Run dynamic air-gap verification inside `docker run --rm --network none` and capture UDP:53 DNS/TCP attempts")
	flag.BoolVar(&showFix, "fix", false, "Print a ready-to-paste Dockerfile snippet (ENV + build-time pre-warming RUN lines) to seal the repository")
	flag.StringVar(&dockerImage, "image", "", "Docker image to use with --run (defaults to detected ecosystem base image)")
	flag.StringVar(&runCmd, "run-cmd", "", "Custom command to execute inside the --network none container with --run")
	flag.IntVar(&timeoutSec, "timeout", 45, "Timeout in seconds for --run dynamic execution")
	flag.Parse()

	target := "."
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	report, err := AnalyzeProjectAirgapAndEgress(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airgap-check error: %v\n", err)
		os.Exit(1)
	}
	if dynamicRun {
		dynRes, dynErr := RunDynamicAirgapCheck(
			context.Background(),
			report.TargetPath,
			report,
			dockerImage,
			runCmd,
			time.Duration(timeoutSec)*time.Second,
		)
		if dynErr != nil {
			fmt.Fprintf(os.Stderr, "airgap-check --run error: %v\n", dynErr)
			os.Exit(1)
		}
		mergeDynamicResultIntoReport(report, dynRes)
	}
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}
	printCheckReportHuman(os.Stdout, report, showFix)
}

func AnalyzeProjectAirgapAndEgress(targetDir string) (*CheckReport, error) {
	absPath, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("path %s must be a directory", absPath)
	}

	report := &CheckReport{
		TargetPath: absPath,
		Scope: CheckScope{
			Mode:               "static",
			InspectedManifests: []string{},
			InspectedEnvFiles:  []EnvFileScopeInfo{},
			LimitationsNote:    "Static scan inspects direct manifests, source code patterns, and .env key names only. Transitive dependencies and runtime network calls are invisible without `airgap-check --run`.",
		},
		AirgapCrashRisks:      []CheckRiskFinding{},
		TelemetryLeakRisks:    []CheckRiskFinding{},
		EgressAndSecretRisks:  []CheckRiskFinding{},
		AllowedEgressManifest: []EgressManifestEntry{},
		SecretRecommendations: []SecretRecommendation{},
		HermeticBuildEnv:      strings.Fields(defaultHermeticRuntimeEnv),
	}

	seenRules := make(map[string]bool)
	discoveredHosts := make(map[string]string)
	seenSecrets := make(map[string]bool)

	walkErr := filepath.Walk(absPath, func(p string, fi os.FileInfo, walkInErr error) error {
		if walkInErr != nil {
			return walkInErr
		}
		relPath, err := filepath.Rel(absPath, p)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		name := fi.Name()
		isEnvFile := !fi.IsDir() && strings.HasPrefix(strings.ToLower(name), ".env")
		if !isEnvFile && shouldSkipPath(relPath, name, fi.IsDir()) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() || !fi.Mode().IsRegular() || fi.Size() > 2*1024*1024 {
			return nil
		}

		relSlash := filepath.ToSlash(relPath)
		lowerName := strings.ToLower(name)
		isBrowserContext := isFrontendOrBrowserPath(relSlash, lowerName)
		isNodePkgJSON := lowerName == "package.json"

		if isDependencyManifest(lowerName) {
			report.Scope.InspectedManifests = append(report.Scope.InspectedManifests, relSlash)
			rawBytes, err := os.ReadFile(p)
			if err == nil {
				manifestSearchText := strings.ToLower(string(rawBytes))
				if isNodePkgJSON {
					manifestSearchText = extractPackageJSONProdDependenciesText(rawBytes)
				}
				for _, rule := range knownAirgapAndTelemetryRules {
					if rule.pythonOnly && isNodePkgJSON {
						continue
					}
					if strings.Contains(manifestSearchText, rule.matchSubstr) {
						execCtx := "server_runtime"
						autoSealed := rule.autoSealed
						mitigation := rule.mitigation
						impact := rule.impact

						if isBrowserContext && rule.category == "telemetry_analytics" {
							execCtx = "browser_client"
							autoSealed = false
							impact = fmt.Sprintf("Client-side package in %s sends telemetry from the end-user's browser to %s. In air-gapped networks the server does not crash, but browser requests fail/timeout.", relSlash, strings.Join(rule.hosts, ", "))
							mitigation = "Server environment variables do NOT disable browser SDKs; gate SDK initialization in frontend source code."
						}

						dedupKey := rule.component + "|" + execCtx
						if seenRules[dedupKey] {
							continue
						}
						seenRules[dedupKey] = true
						seenRules[rule.component] = true

						finding := CheckRiskFinding{
							Category:         rule.category,
							Severity:         rule.severity,
							Component:        rule.component,
							SourceFile:       relSlash,
							ExecutionContext: execCtx,
							EgressHosts:      rule.hosts,
							FailureImpact:    impact,
							Mitigation:       mitigation,
							AutoSealedByEnv:  autoSealed,
						}
						if rule.category == "runtime_model_asset" {
							report.AirgapCrashRisks = append(report.AirgapCrashRisks, finding)
						} else {
							report.TelemetryLeakRisks = append(report.TelemetryLeakRisks, finding)
						}
						for _, h := range rule.hosts {
							if _, exists := discoveredHosts[h]; !exists {
								discoveredHosts[h] = "static_manifest"
							}
						}
					}
				}
				for sdk, host := range map[string]string{
					"openai":              "api.openai.com",
					"anthropic":           "api.anthropic.com",
					"google-generativeai": "generativelanguage.googleapis.com",
					"@google/genai":       "generativelanguage.googleapis.com",
					"groq":                "api.groq.com",
					"mistralai":           "api.mistral.ai",
					"cohere":              "api.cohere.com",
					"stripe":              "api.stripe.com",
				} {
					if strings.Contains(manifestSearchText, sdk) {
						if _, exists := discoveredHosts[host]; !exists {
							discoveredHosts[host] = "static_manifest"
						}
					}
				}
			}
		}

		if strings.HasPrefix(lowerName, ".env") && !isTemplateEnvFileName(lowerName) {
			gitTracked := isFileTrackedByGit(absPath, relSlash)
			report.Scope.InspectedEnvFiles = append(report.Scope.InspectedEnvFiles, EnvFileScopeInfo{
				RelPath:    relSlash,
				GitTracked: gitTracked,
			})
			rawBytes, err := os.ReadFile(p)
			if err == nil {
				lines := strings.Split(string(rawBytes), "\n")
				for _, line := range lines {
					m := envKeyRegex.FindStringSubmatch(line)
					if len(m) == 3 {
						keyName := m[1]
						valClean := cleanEnvValueForPresenceCheck(m[2])
						if isNonEmptySecretCandidate(keyName, valClean) && !seenSecrets[keyName] {
							seenSecrets[keyName] = true
							rec := classifySecretKey(keyName, relSlash, gitTracked)
							report.SecretRecommendations = append(report.SecretRecommendations, rec)
							for _, h := range rec.RecommendedHosts {
								if _, exists := discoveredHosts[h]; !exists {
									discoveredHosts[h] = "static_manifest"
								}
							}
							gitNote := "untracked local file"
							sev := "MEDIUM"
							if gitTracked {
								gitNote = "TRACKED IN GIT INDEX"
								sev = "CRITICAL"
							} else if rec.ProxyEligible {
								sev = "HIGH"
							}
							report.EgressAndSecretRisks = append(report.EgressAndSecretRisks, CheckRiskFinding{
								Category:         "env_secret_" + rec.UsageKind,
								Severity:         sev,
								Component:        keyName,
								SourceFile:       fmt.Sprintf("%s (%s)", relSlash, gitNote),
								ExecutionContext: "server_runtime",
								EgressHosts:      rec.RecommendedHosts,
								FailureImpact:    rec.Explanation,
								Mitigation:       rec.Guidance,
								AutoSealedByEnv:  false,
							})
						}
					}
				}
			}
		}

		if isSourceCodeFile(lowerName) && !isTestSourceFile(relSlash, lowerName) {
			report.Scope.ScannedSourceFiles++
			rawBytes, err := os.ReadFile(p)
			if err == nil {
				content := string(rawBytes)
				if strings.Contains(content, "next/font/google") && !seenRules["next/font/google"] {
					seenRules["next/font/google"] = true
					report.AirgapCrashRisks = append(report.AirgapCrashRisks, CheckRiskFinding{
						Category:         "runtime_model_asset",
						Severity:         "HIGH",
						Component:        "next/font/google",
						SourceFile:       relSlash,
						ExecutionContext: "server_runtime",
						EgressHosts:      []string{"fonts.googleapis.com", "fonts.gstatic.com"},
						FailureImpact:    "Fetches Google Fonts over HTTPS during build; fails in offline build environments.",
						Mitigation:       "Self-host font files with next/font/local for offline builds.",
						AutoSealedByEnv:  false,
					})
				}

				for _, codeRule := range sourceCodeDownloadRules {
					if codeRule.re.MatchString(content) && !seenRules[codeRule.component+"|"+relSlash] {
						seenRules[codeRule.component+"|"+relSlash] = true
						report.AirgapCrashRisks = append(report.AirgapCrashRisks, CheckRiskFinding{
							Category:         codeRule.category,
							Severity:         codeRule.severity,
							Component:        codeRule.component,
							SourceFile:       relSlash,
							ExecutionContext: "server_runtime",
							EgressHosts:      codeRule.hosts,
							FailureImpact:    codeRule.impact,
							Mitigation:       codeRule.mitigation,
							AutoSealedByEnv:  codeRule.autoSealed,
						})
						for _, h := range codeRule.hosts {
							if _, exists := discoveredHosts[h]; !exists {
								discoveredHosts[h] = "static_code"
							}
						}
					}
				}

				if !isBrowserContext {
					matches := httpsURLRegex.FindAllStringSubmatch(content, -1)
					for _, m := range matches {
						if len(m) >= 2 {
							parsed, uErr := url.Parse(m[0])
							if uErr != nil || parsed.Hostname() == "" {
								continue
							}
							h := strings.ToLower(parsed.Hostname())
							if isIgnoredLocalOrDocHost(h) {
								continue
							}
							if _, exists := discoveredHosts[h]; !exists {
								discoveredHosts[h] = "static_code"
							}
						}
					}
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	rebuildAllowedEgressManifest(report, discoveredHosts)
	report.RemediationDockerfileSnippet = generateRemediationDockerfileSnippet(report)
	computeStaticVerdict(report)
	return report, nil
}

func shouldSkipPath(relPath, name string, isDir bool) bool {
	lower := strings.ToLower(name)
	if isDir {
		switch lower {
		case ".git", "node_modules", ".next", "dist", "build", "out", "venv", ".venv", "__pycache__", "vendor", ".cache":
			return true
		}
	}
	return false
}

func extractPackageJSONProdDependenciesText(rawBytes []byte) string {
	var parsed struct {
		Dependencies         map[string]any `json:"dependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(rawBytes, &parsed); err != nil {
		return strings.ToLower(string(rawBytes))
	}
	var keys []string
	for k := range parsed.Dependencies {
		keys = append(keys, strings.ToLower(k))
	}
	for k := range parsed.OptionalDependencies {
		keys = append(keys, strings.ToLower(k))
	}
	return strings.Join(keys, " ")
}

func isTemplateEnvFileName(lowerName string) bool {
	for _, marker := range []string{"example", "sample", "template", "dist", "defaults", "test"} {
		if strings.Contains(lowerName, marker) {
			return true
		}
	}
	return false
}

func cleanEnvValueForPresenceCheck(rawVal string) string {
	v := strings.TrimSpace(rawVal)
	if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
		return strings.TrimSpace(v[1 : len(v)-1])
	}
	if idx := strings.Index(v, "#"); idx >= 0 {
		v = strings.TrimSpace(v[:idx])
	}
	return v
}

func isNonEmptySecretCandidate(keyName, cleanedVal string) bool {
	if cleanedVal == "" {
		return false
	}
	lowerVal := strings.ToLower(cleanedVal)
	switch lowerVal {
	case "true", "false", "0", "1", "yes", "no", "none", "null", "undefined", "changeme", "xxx", "your-api-key", "your_api_key":
		return false
	}
	if strings.HasPrefix(lowerVal, "<") && strings.HasSuffix(lowerVal, ">") {
		return false
	}
	upperKey := strings.ToUpper(keyName)
	for _, boolPrefix := range []string{"USE_", "ENABLE_", "DISABLE_", "ALLOW_", "IS_", "HAS_"} {
		if strings.HasPrefix(upperKey, boolPrefix) {
			return false
		}
	}
	if strings.Contains(upperKey, "URL") && !strings.Contains(cleanedVal, "@") {
		return false
	}
	return isSensitiveEnvKey(upperKey)
}

func isTestSourceFile(relSlash, lowerName string) bool {
	if strings.Contains(relSlash, "/__tests__/") || strings.Contains(relSlash, "/test/") || strings.Contains(relSlash, "/tests/") {
		return true
	}
	for _, suffix := range []string{"_test.go", "_test.py", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.tsx", ".spec.js"} {
		if strings.HasSuffix(lowerName, suffix) {
			return true
		}
	}
	return strings.HasPrefix(lowerName, "test_") && strings.HasSuffix(lowerName, ".py")
}

func classifyHostDestination(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	switch {
	case strings.Contains(h, "openai.com") || strings.Contains(h, "anthropic.com") ||
		strings.Contains(h, "googleapis.com") && strings.Contains(h, "generativelanguage") ||
		strings.Contains(h, "groq.com") || strings.Contains(h, "mistral.ai") ||
		strings.Contains(h, "cohere.com") || strings.Contains(h, "deepseek.com") ||
		strings.Contains(h, "together.xyz"):
		return "llm_inference_api"
	case strings.Contains(h, "posthog.com") || strings.Contains(h, "sentry.io") ||
		strings.Contains(h, "scarf.sh") || strings.Contains(h, "telemetry.crewai.com") ||
		strings.Contains(h, "smith.langchain.com") || strings.Contains(h, "segment.io") ||
		strings.Contains(h, "mixpanel.com") || strings.Contains(h, "amplitude.com"):
		return "telemetry_analytics"
	case strings.Contains(h, "huggingface.co") || strings.Contains(h, "hf.co") ||
		strings.Contains(h, "openaipublic.blob.core.windows.net") ||
		strings.Contains(h, "openaipublic.azureedge.net") ||
		strings.Contains(h, "chroma-onnx-models.s3.amazonaws.com") ||
		strings.Contains(h, "playwright.azureedge.net") ||
		strings.Contains(h, "raw.githubusercontent.com") ||
		strings.Contains(h, "download.pytorch.org"):
		return "runtime_model_asset"
	default:
		return "external_api"
	}
}

func rebuildAllowedEgressManifest(report *CheckReport, discoveredHosts map[string]string) {
	hostList := make([]string, 0, len(discoveredHosts))
	for h := range discoveredHosts {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)

	browserHosts := make(map[string]bool)
	envSilencedHosts := make(map[string]bool)
	for _, t := range report.TelemetryLeakRisks {
		for _, h := range t.EgressHosts {
			if t.ExecutionContext == "browser_client" {
				browserHosts[h] = true
			} else if t.AutoSealedByEnv {
				envSilencedHosts[h] = true
			}
		}
	}

	report.AllowedEgressManifest = make([]EgressManifestEntry, 0, len(hostList))
	for _, h := range hostList {
		cls := classifyHostDestination(h)
		if cls == "external_api" && isSelfOrCanonicalDomain(report.TargetPath, h) {
			cls = "self_or_canonical_domain"
		}
		action := "EXTERNAL_API_ALLOWLIST_IF_NEEDED"
		switch cls {
		case "self_or_canonical_domain":
			action = "CANONICAL_APP_DOMAIN (self-reference, not an external dependency)"
		case "llm_inference_api":
			action = "ELIGIBLE_FOR_EGRESS_PROXY_OR_LOCAL_VLLM"
		case "telemetry_analytics":
			if browserHosts[h] {
				action = "BROWSER_CLIENT_EGRESS (disable SDK in frontend code)"
			} else if envSilencedHosts[h] {
				action = "SILENCED_BY_ENV_VARS (see --fix)"
			} else {
				action = "UNSEALED_TELEMETRY (block at egress firewall)"
			}
		case "runtime_model_asset":
			action = "RUNTIME_DOWNLOAD_CRASH_IN_AIRGAP (pre-bake in Dockerfile, see --fix)"
		}
		report.AllowedEgressManifest = append(report.AllowedEgressManifest, EgressManifestEntry{
			Host:           h,
			Source:         discoveredHosts[h],
			Classification: cls,
			PolicyAction:   action,
		})
	}
}

func isSelfOrCanonicalDomain(targetPath, host string) bool {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(targetPath)))
	if len(base) < 4 {
		return false
	}
	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts[:len(parts)-1] {
		if p == base {
			return true
		}
	}
	return false
}

func computeStaticVerdict(report *CheckReport) {
	if len(report.AirgapCrashRisks) > 0 || len(report.TelemetryLeakRisks) > 0 || len(report.EgressAndSecretRisks) > 0 {
		report.AirgapReadinessVerdict = "ACTION_REQUIRED_STATIC_FINDINGS (run `airgap-check --run` to verify runtime behavior, or `--fix` for Dockerfile remediation)"
		return
	}
	report.AirgapReadinessVerdict = "STATIC_SCAN_ONLY_RUN_DYNAMIC_CHECK (`airgap-check --run` required to verify offline execution)"
}

func mergeDynamicResultIntoReport(report *CheckReport, dyn *DynamicCheckResult) {
	if dyn == nil {
		return
	}
	report.DynamicRun = dyn
	report.Scope.Mode = "static+dynamic (--network none)"
	report.Scope.LimitationsNote = fmt.Sprintf(
		"Executed `%s` inside `docker run --rm --network none` (%s, %dms). Captures language-agnostic UDP:53 DNS queries (/etc/resolv.conf -> 127.0.0.1:53 when python3 is present), Python socket hooks, and Node.js dns/net hooks. Only code paths exercised by this command were tested; raw hardcoded-IP connections from non-Python/Node static binaries are not intercepted.",
		dyn.Command, dyn.DockerImage, dyn.DurationMs,
	)

	existingHosts := make(map[string]string)
	for _, e := range report.AllowedEgressManifest {
		existingHosts[e.Host] = e.Source
	}
	for _, att := range dyn.ObservedAttempts {
		if att.Host != "" {
			existingHosts[att.Host] = "dynamic_run (" + att.Protocol + ")"
		}
	}
	rebuildAllowedEgressManifest(report, existingHosts)

	if dyn.CrashedInAirgap {
		report.AirgapReadinessVerdict = fmt.Sprintf("DYNAMIC_AIRGAP_FAILURE (%s, exit=%d)", dyn.FailureCategory, dyn.ExitCode)
	} else if len(report.AirgapCrashRisks) > 0 {
		report.AirgapReadinessVerdict = "ACTION_REQUIRED_STATIC_FINDINGS (startup probe passed, but static runtime downloaders exist)"
	} else {
		report.AirgapReadinessVerdict = "DYNAMIC_PROBE_PASSED_UNDER_NETWORK_NONE"
	}
}

func isFileTrackedByGit(repoRoot, relSlash string) bool {
	cmd := exec.Command("git", "-C", repoRoot, "ls-files", "--error-unmatch", relSlash)
	if err := cmd.Run(); err == nil {
		return true
	}
	return false
}

func isFrontendOrBrowserPath(relSlash, lowerName string) bool {
	for _, prefix := range []string{"frontend/", "client/", "web/", "apps/web/", "apps/frontend/", "src/components/"} {
		if strings.HasPrefix(relSlash, prefix) {
			return true
		}
	}
	return strings.HasSuffix(lowerName, ".tsx") || strings.HasSuffix(lowerName, ".jsx")
}

func classifySecretKey(key, sourceFile string, gitTracked bool) SecretRecommendation {
	upper := strings.ToUpper(key)

	for _, localToken := range []string{
		"JWT_", "_JWT", "SESSION_SECRET", "NEXTAUTH_SECRET", "AUTH_SECRET",
		"COOKIE_SECRET", "ENCRYPTION_KEY", "MASTER_KEY", "PRIVATE_KEY",
		"APP_SECRET", "FLASK_SECRET", "DJANGO_SECRET", "SECRET_KEY_BASE",
		"DATABASE_URL", "POSTGRES_", "MYSQL_", "REDIS_", "MONGO",
	} {
		if strings.Contains(upper, localToken) || upper == "SECRET_KEY" {
			return SecretRecommendation{
				SecretKey:     key,
				SourceFile:    sourceFile,
				GitTracked:    gitTracked,
				UsageKind:     "local_signing_or_internal",
				ProxyEligible: false,
				Explanation:   "Local signing/encryption or internal state key used inside the application process; never sent in outbound HTTP headers, so outbound proxy token-swapping is not applicable.",
				Guidance:      "Inject as an encrypted runtime environment variable; never commit to git.",
			}
		}
	}

	for _, signedToken := range []string{
		"CLOUDINARY_", "AWS_SECRET", "AWS_ACCESS_KEY", "S3_SECRET",
		"WEBHOOK_SECRET", "SIGNING_SECRET", "TWILIO_AUTH_TOKEN", "HMAC_",
	} {
		if strings.Contains(upper, signedToken) {
			return SecretRecommendation{
				SecretKey:     key,
				SourceFile:    sourceFile,
				GitTracked:    gitTracked,
				UsageKind:     "signed_request_flow",
				ProxyEligible: false,
				Explanation:   "Used locally to compute cryptographic request signatures (HMAC/SigV4/signed uploads); wire-level token replacement would invalidate the signature.",
				Guidance:      "Requires in-process HMAC signing; keep in encrypted runtime environment.",
			}
		}
	}

	hosts := inferHostsForWireAPIKey(upper)
	if len(hosts) > 0 {
		return SecretRecommendation{
			SecretKey:        key,
			SourceFile:       sourceFile,
			GitTracked:       gitTracked,
			UsageKind:        "wire_api_key",
			ProxyEligible:    true,
			Explanation:      fmt.Sprintf("Outbound HTTP API credential sent in request headers to %s; eligible for egress-proxy token injection or local LLM routing.", strings.Join(hosts, ", ")),
			RecommendedHosts: hosts,
			Guidance:         fmt.Sprintf("Scope outbound egress to %s or route to an internal/air-gapped LLM endpoint.", strings.Join(hosts, ", ")),
		}
	}

	return SecretRecommendation{
		SecretKey:     key,
		SourceFile:    sourceFile,
		GitTracked:    gitTracked,
		UsageKind:     "needs_review",
		ProxyEligible: false,
		Explanation:   "Verify whether this credential is sent as a raw HTTP header to an external API or used locally for signing.",
		Guidance:      "Review usage and ensure `.env` is excluded from git and container layers.",
	}
}

func inferHostsForWireAPIKey(upper string) []string {
	switch {
	case strings.Contains(upper, "OPENAI"):
		return []string{"api.openai.com"}
	case strings.Contains(upper, "ANTHROPIC") || strings.Contains(upper, "CLAUDE"):
		return []string{"api.anthropic.com"}
	case strings.Contains(upper, "GEMINI") || strings.Contains(upper, "GOOGLE_API_KEY"):
		return []string{"generativelanguage.googleapis.com"}
	case strings.Contains(upper, "GROQ"):
		return []string{"api.groq.com"}
	case strings.Contains(upper, "MISTRAL"):
		return []string{"api.mistral.ai"}
	case strings.Contains(upper, "COHERE"):
		return []string{"api.cohere.com"}
	case strings.Contains(upper, "DEEPSEEK"):
		return []string{"api.deepseek.com"}
	case strings.Contains(upper, "TOGETHER"):
		return []string{"api.together.xyz"}
	case strings.Contains(upper, "STRIPE_SECRET") || strings.Contains(upper, "STRIPE_API"):
		return []string{"api.stripe.com"}
	case strings.Contains(upper, "GITHUB_TOKEN") || strings.Contains(upper, "GH_TOKEN"):
		return []string{"api.github.com"}
	default:
		return nil
	}
}

func isDependencyManifest(lowerName string) bool {
	switch lowerName {
	case "requirements.txt", "pyproject.toml", "pipfile", "package.json", "go.mod", "cargo.toml", "gemfile":
		return true
	}
	return strings.HasPrefix(lowerName, "requirements") && strings.HasSuffix(lowerName, ".txt")
}

func isSourceCodeFile(lowerName string) bool {
	for _, ext := range []string{".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".rb"} {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, token := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "DSN", "WEBHOOK"} {
		if strings.Contains(upper, token) {
			return true
		}
	}
	return false
}

func isIgnoredLocalOrDocHost(host string) bool {
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || strings.HasPrefix(host, "-") {
		return true
	}
	for _, reservedTLD := range []string{".test", ".example", ".invalid", ".internal", ".localhost"} {
		if strings.HasSuffix(host, reservedTLD) {
			return true
		}
	}
	for _, ignore := range []string{
		"example.com", "example.dev", "w3.org", "schemas.openxmlformats.org",
		"localhost", "reactjs.org", "vitejs.dev", "nextjs.org", "vercel.com",
		"mozilla.org", "npmjs.com", "pypi.org", "schema.org", "www.sitemaps.org",
		"github.com", "github.io", "docs.crewai.com", "docs.firecrawl.dev",
		"learn.microsoft.com", "arxiv.org", "wikipedia.org", "news.ycombinator.com",
		"twitter.com", "x.com", "linkedin.com", "facebook.com", "instagram.com",
		"youtube.com", "wa.me", "images.unsplash.com", "via.placeholder.com",
		"www.carlogos.org", "playwright.dev", "zod.dev", "d3js.org", "webpack.js.org",
		"opensource.org", "apache.org", "json-schema.org", "datatracker.ietf.org",
		"kit.svelte.dev", "tailwindui.com", "sslip.io", "nip.io",
	} {
		if host == ignore || strings.HasSuffix(host, "."+ignore) {
			return true
		}
	}
	return false
}

func printCheckReportHuman(out io.Writer, r *CheckReport, showFix bool) {
	_, _ = fmt.Fprintln(out, "┌─────────────────────────────────────────────────────────────────────────────┐")
	_, _ = fmt.Fprintln(out, "│                   AIRGAP-CHECK: OFFLINE & TELEMETRY AUDIT                   │")
	_, _ = fmt.Fprintln(out, "└─────────────────────────────────────────────────────────────────────────────┘")
	_, _ = fmt.Fprintf(out, "  Target Repository : %s\n", r.TargetPath)
	_, _ = fmt.Fprintf(out, "  Test Scope        : %s (%d manifests, %d source files, %d .env files)\n",
		r.Scope.Mode, len(r.Scope.InspectedManifests), r.Scope.ScannedSourceFiles, len(r.Scope.InspectedEnvFiles))
	_, _ = fmt.Fprintf(out, "  Scope Note        : %s\n", r.Scope.LimitationsNote)
	_, _ = fmt.Fprintf(out, "  Verdict           : %s\n\n", r.AirgapReadinessVerdict)

	if r.DynamicRun != nil {
		_, _ = fmt.Fprintln(out, "0. DYNAMIC AIR-GAP EXECUTION (`docker run --rm --network none`)")
		_, _ = fmt.Fprintf(out, "   Image / Command  : %s -> `%s`\n", r.DynamicRun.DockerImage, r.DynamicRun.Command)
		_, _ = fmt.Fprintf(out, "   Exit / Duration  : exit=%d (%dms) | crashed_in_airgap=%v\n",
			r.DynamicRun.ExitCode, r.DynamicRun.DurationMs, r.DynamicRun.CrashedInAirgap)
		if r.DynamicRun.FailureCategory != "" {
			_, _ = fmt.Fprintf(out, "   Failure Category : %s\n", r.DynamicRun.FailureCategory)
		}
		if len(r.DynamicRun.ObservedAttempts) == 0 {
			_, _ = fmt.Fprintln(out, "   Observed Egress  : 0 outbound DNS/TCP/TLS attempts observed.")
		} else {
			_, _ = fmt.Fprintf(out, "   Observed Egress  : %d outbound attempt(s) blocked by --network none:\n", len(r.DynamicRun.ObservedAttempts))
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
			_, _ = fmt.Fprintf(out, "   • [%s | BUILD-TIME BAKE REQUIRED] %s (%s)\n", f.Severity, f.Component, f.SourceFile)
			_, _ = fmt.Fprintf(out, "     Egress   : %s\n", strings.Join(f.EgressHosts, ", "))
			_, _ = fmt.Fprintf(out, "     Impact   : %s\n", f.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", f.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "2. TELEMETRY & EXTERNAL ANALYTICS (%d found)\n", len(r.TelemetryLeakRisks))
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
			_, _ = fmt.Fprintf(out, "   • [%s | %s] %s (%s)\n", f.Severity, badge, f.Component, f.SourceFile)
			_, _ = fmt.Fprintf(out, "     Egress   : %s\n", strings.Join(f.EgressHosts, ", "))
			_, _ = fmt.Fprintf(out, "     Behavior : %s\n", f.FailureImpact)
			_, _ = fmt.Fprintf(out, "     Action   : %s\n", f.Mitigation)
		}
	}
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "3. .ENV CREDENTIALS & USAGE CLASSIFICATION (%d found — values never read/logged)\n", len(r.SecretRecommendations))
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

	_, _ = fmt.Fprintf(out, "4. OBSERVED & REFERENCED EXTERNAL HOSTS (%d hosts)\n", len(r.AllowedEgressManifest))
	if len(r.AllowedEgressManifest) == 0 {
		_, _ = fmt.Fprintln(out, "   • None detected.")
	} else {
		_, _ = fmt.Fprintf(out, "   %-36s %-22s %-24s %-30s\n", "HOST", "SOURCE", "CLASSIFICATION", "HANDLING")
		for _, m := range r.AllowedEgressManifest {
			_, _ = fmt.Fprintf(out, "   %-36s %-22s %-24s %-30s\n", m.Host, m.Source, m.Classification, m.PolicyAction)
		}
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "5. RECOMMENDED OFFLINE ENV FLAGS (pass `--fix` for a ready-to-paste Dockerfile block)\n   %s\n", strings.Join(r.HermeticBuildEnv, " "))
	if showFix && r.RemediationDockerfileSnippet != "" {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "6. STANDALONE DOCKERFILE REMEDIATION (`--fix` — paste into your Dockerfile)")
		for _, line := range strings.Split(r.RemediationDockerfileSnippet, "\n") {
			_, _ = fmt.Fprintf(out, "   %s\n", line)
		}
	}
}

func generateRemediationDockerfileSnippet(r *CheckReport) string {
	var b strings.Builder
	b.WriteString("# --- BEGIN AIR-GAP & TELEMETRY REMEDIATION (paste into your Dockerfile) ---\n")
	b.WriteString("# 1. Silence background SDK telemetry & enforce writable offline cache paths\n")
	b.WriteString("ENV DO_NOT_TRACK=1 \\\n")
	b.WriteString("    NEXT_TELEMETRY_DISABLED=1 \\\n")
	b.WriteString("    ANONYMIZED_TELEMETRY=False \\\n")
	b.WriteString("    CHROMA_TELEMETRY_IMPL=none \\\n")
	b.WriteString("    SCARF_NO_ANALYTICS=true \\\n")
	b.WriteString("    HF_HUB_DISABLE_TELEMETRY=1 \\\n")
	b.WriteString("    HF_HUB_OFFLINE=1 \\\n")
	b.WriteString("    TRANSFORMERS_OFFLINE=1 \\\n")
	b.WriteString("    LANGCHAIN_TRACING_V2=false \\\n")
	b.WriteString("    CREWAI_DISABLE_TELEMETRY=true \\\n")
	b.WriteString("    OTEL_SDK_DISABLED=true \\\n")
	b.WriteString("    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \\\n")
	b.WriteString("    XDG_CACHE_HOME=/app/.cache \\\n")
	b.WriteString("    TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken \\\n")
	b.WriteString("    HF_HOME=/app/.cache/huggingface \\\n")
	b.WriteString("    NLTK_DATA=/app/.cache/nltk_data \\\n")
	b.WriteString("    PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright\n")
	b.WriteString("RUN mkdir -p /app/.cache/tiktoken /app/.cache/huggingface /app/.cache/nltk_data /app/.cache/ms-playwright\n")

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
		case (strings.Contains(comp, "transformers") || strings.Contains(comp, "huggingface")) && !seenComp["hf"]:
			seenComp["hf"] = true
			b.WriteString("\n# Pre-download HuggingFace model weights during build (replace <MODEL_ID> with your model)\n")
			b.WriteString("# RUN HF_HOME=/app/.cache/huggingface HF_HUB_OFFLINE=0 python3 -c \"from huggingface_hub import snapshot_download; snapshot_download('<MODEL_ID>')\"\n")
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
			b.WriteString("RUN PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright npx playwright install --with-deps chromium\n")
		}
	}
	b.WriteString("# --- END AIR-GAP & TELEMETRY REMEDIATION ---")
	return b.String()
}
