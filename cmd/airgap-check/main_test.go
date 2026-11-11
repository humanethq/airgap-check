package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func createTestFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	frontDir := filepath.Join(root, "frontend", "src")
	backDir := filepath.Join(root, "backend")
	if err := os.MkdirAll(frontDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(backDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgJSON := `{
  "name": "sample-frontend",
  "dependencies": {
    "react": "^18.2.0",
    "posthog-js": "^1.96.0"
  },
  "devDependencies": {
    "@playwright/test": "^1.42.0"
  }
}`
	if err := os.WriteFile(filepath.Join(root, "frontend", "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	reqs := "fastapi==0.110.1\ntiktoken>=0.7.0\nchromadb>=0.5.0\nplaywright>=1.42.0\n"
	if err := os.WriteFile(filepath.Join(backDir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	serverPy := "import nltk\nnltk.download('punkt')\n"
	if err := os.WriteFile(filepath.Join(backDir, "server.py"), []byte(serverPy), 0o644); err != nil {
		t.Fatal(err)
	}

	envContent := "JWT_SECRET_KEY=jwt-secret-999111\nOPENAI_API_KEY=sk-proj-SECRET888222\nCLOUDINARY_API_SECRET=cloud-sec-777333\n"
	if err := os.WriteFile(filepath.Join(backDir, ".env"), []byte(envContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStandaloneAnalyzeAndFixAndNoSecretLeak(t *testing.T) {
	dir := createTestFixture(t)
	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatalf("AnalyzeProjectAirgapAndEgress: %v", err)
	}

	var buf bytes.Buffer
	printCheckReportHuman(&buf, report, true)
	out := buf.String()

	for _, secret := range []string{"jwt-secret-999111", "sk-proj-SECRET888222", "cloud-sec-777333"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked in human output: %s", secret)
		}
	}

	for _, want := range []string{
		"STANDALONE DOCKERFILE REMEDIATION",
		"TIKTOKEN_CACHE_DIR=/app/.cache/tiktoken",
		"ONNXMiniLM_L6_V2",
		"nltk.downloader",
		"playwright install --with-deps chromium",
		"LITELLM_LOCAL_MODEL_COST_MAP=True",
		"EASYOCR_MODULE_PATH=/app/.cache/easyocr",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected --fix output to contain %q, got:\n%s", want, out)
		}
	}

	if !isSelfOrCanonicalDomain("/workspace/projectx", "projectx.dev") {
		t.Fatalf("expected projectx.dev to be classified as self_or_canonical_domain")
	}
}

func TestStructuralPyprojectIgnoresDevGroupsAndKeyNames(t *testing.T) {
	dir := t.TempDir()
	pyproject := `[project]
name = "demo-agent"
dependencies = [
  "tiktoken>=0.8.0",
  "fastembed>=0.3.0",
]

[project.optional-dependencies]
ocr = ["easyocr>=1.7"]
posthog = ["openai>=1.0.0"]
dev = ["playwright>=1.50"]
test = ["transformers>=4.40"]
e2e-dev = ["chromadb>=0.5.0"]

[dependency-groups]
e2e-dev = ["playwright==1.61.0"]
clai2-browser = ["playwright>=1.45"]

[tool.uv]
constraint-dependencies = [
  "sentence-transformers>=2.2.0",
  "transformers>=4.40.0",
]

[tool.ty.analysis]
allowed-unresolved-imports = ["whisper.**"]
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}
	// Dev requirements file should also be skipped.
	if err := os.WriteFile(filepath.Join(dir, "requirements-dev.txt"), []byte("playwright==1.50\nsentry-sdk\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	crashByComp := make(map[string]CheckRiskFinding)
	for _, f := range report.AirgapCrashRisks {
		crashByComp[f.Component] = f
	}
	if f, ok := crashByComp["tiktoken"]; !ok || f.DependencyScope != "prod" {
		t.Fatalf("expected tiktoken with DependencyScope=prod, got %+v", crashByComp)
	}
	if f, ok := crashByComp["fastembed"]; !ok || f.DependencyScope != "prod" {
		t.Fatalf("expected fastembed with DependencyScope=prod, got %+v", crashByComp)
	}
	if f, ok := crashByComp["easyocr"]; !ok || f.DependencyScope != "optional_extra" {
		t.Fatalf("expected easyocr with DependencyScope=optional_extra, got %+v", crashByComp)
	}
	for _, unexpected := range []string{"playwright", "transformers", "chromadb (default ONNX embedding)", "sentence-transformers", "whisper"} {
		if _, exists := crashByComp[unexpected]; exists {
			t.Fatalf("unexpected crash risk %q from ignored group/tool section: %+v", unexpected, crashByComp[unexpected])
		}
	}
	if len(report.TelemetryLeakRisks) != 0 {
		t.Fatalf("expected 0 telemetry risks (key name 'posthog = ...' and requirements-dev.txt must be ignored), got %+v", report.TelemetryLeakRisks)
	}
}

func TestLockfileBFSResolutionPyAndNode(t *testing.T) {
	dir := t.TempDir()
	pyproject := `[project]
name = "my-app"
dependencies = ["wrapper-pkg>=1.0"]
`
	uvLock := `version = 1

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "wrapper-pkg" },
]

[[package]]
name = "wrapper-pkg"
version = "1.0.0"
dependencies = [
    { name = "tiktoken" },
]

[[package]]
name = "tiktoken"
version = "0.8.0"

[[package]]
name = "playwright"
version = "1.50.0"

[[package]]
name = "my-dev-tool"
version = "1.0.0"
source = { editable = "tests/devtool" }
dependencies = [
    { name = "playwright" },
]
`
	pkgJSON := `{"name": "ui", "dependencies": {"next": "14.0.0"}}`
	pkgLock := `{
  "name": "ui",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "ui"},
    "node_modules/next/node_modules/@huggingface/transformers": {"version": "3.0.0"},
    "node_modules/playwright": {"version": "1.50.0", "dev": true}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(uvLock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(pkgLock), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := make(map[string]CheckRiskFinding)
	for _, f := range report.AirgapCrashRisks {
		found[f.Component] = f
	}
	if f, ok := found["tiktoken"]; !ok || f.DependencyScope != "transitive_lockfile" {
		t.Fatalf("expected transitive tiktoken from uv.lock BFS, got %+v", found)
	}
	if f, ok := found["transformers"]; !ok || f.DependencyScope != "transitive_lockfile" {
		t.Fatalf("expected transitive @huggingface/transformers from package-lock.json, got %+v", found)
	}
	if _, bad := found["playwright"]; bad {
		t.Fatalf("expected dev-only playwright in tests/devtool & dev:true to be excluded, got %+v", found["playwright"])
	}
}

func TestUniversalBehavioralAnalyzerAndLocalFilesOnly(t *testing.T) {
	dir := t.TempDir()
	code := `# requests.get("https://ignored-comment.example.com/weights.onnx")
import os, subprocess, requests
from transformers import AutoModel

model = AutoModel.from_pretrained(
    "/opt/models/local-embed",
    local_files_only=True,
)

def fetch_custom():
    cache_dir = os.path.expanduser("~/.cache/mycustomai")
    r = requests.get("https://cdn.unknown-ai.dev/weights/custom_v2.onnx")
    subprocess.run(["pip", "install", "proprietary-ext"])
    return cache_dir, r
`
	if err := os.WriteFile(filepath.Join(dir, "worker.py"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range report.AirgapCrashRisks {
		if strings.Contains(f.Component, "huggingface") {
			t.Fatalf("expected local_files_only=True call not to raise huggingface crash risk, got %+v", f)
		}
	}

	cats := make(map[string]bool)
	for _, b := range report.BehavioralFindings {
		cats[b.Category] = true
	}
	for _, want := range []string{
		"behavioral_asset_download",
		"behavioral_subprocess_download",
		"behavioral_cache_dir_write",
	} {
		if !cats[want] {
			t.Fatalf("expected behavioral category %s, got %+v", want, report.BehavioralFindings)
		}
	}
	if cats["behavioral_unbounded_http_timeout"] || cats["robustness_hint"] {
		t.Fatalf("unbounded HTTP timeout must not pollute BehavioralFindings: %+v", report.BehavioralFindings)
	}
	if len(report.RobustnessHints) != 1 || report.RobustnessHints[0].Category != "robustness_hint" {
		t.Fatalf("expected missing timeout= warning in RobustnessHints, got %+v", report.RobustnessHints)
	}

	// Timeout-only repos must remain clean of air-gap download findings in Verdict.
	timeoutOnlyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(timeoutOnlyDir, "client.py"), []byte("import requests\nresp = requests.get('https://api.internal.local/health')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	toReport, err := AnalyzeProjectAirgapAndEgress(timeoutOnlyDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(toReport.RobustnessHints) != 1 || len(toReport.BehavioralFindings) != 0 || strings.Contains(toReport.AirgapReadinessVerdict, "ACTION_REQUIRED") {
		t.Fatalf("expected robustness_hint alone not to trigger ACTION_REQUIRED verdict, got %+v", toReport)
	}

	var hasCustomHost, hasIgnoredHost bool
	for _, h := range report.AllowedEgressManifest {
		if h.Host == "cdn.unknown-ai.dev" {
			hasCustomHost = true
		}
		if h.Host == "ignored-comment.example.com" {
			hasIgnoredHost = true
		}
	}
	if !hasCustomHost || hasIgnoredHost {
		t.Fatalf("unexpected manifest hosts: custom=%v ignored=%v manifest=%+v", hasCustomHost, hasIgnoredHost, report.AllowedEgressManifest)
	}
}

func TestCustomRulesAndIgnoreFilters(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("internal-embedder==1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import nltk\nnltk.download('punkt')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `{
  "rules": [
    {
      "package_or_pattern": "internal_embedder",
      "component": "internal-embedder-sdk",
      "category": "runtime_model_asset",
      "severity": "CRITICAL",
      "hosts": ["models.corp.local"],
      "impact": "Downloads corp embeddings at boot.",
      "mitigation": "Bake corp embeddings during build.",
      "python_only": true
    }
  ],
  "ignore_components": ["nltk.download()"],
  "ignore_hosts": ["raw.githubusercontent.com"]
}`
	if err := os.WriteFile(filepath.Join(dir, ".airgap-check.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AirgapCrashRisks) != 1 || report.AirgapCrashRisks[0].Component != "internal-embedder-sdk" {
		t.Fatalf("expected only custom rule finding after ignore_components, got %+v", report.AirgapCrashRisks)
	}
	if len(report.AllowedEgressManifest) != 1 || report.AllowedEgressManifest[0].Host != "models.corp.local" {
		t.Fatalf("expected only models.corp.local after ignore_hosts, got %+v", report.AllowedEgressManifest)
	}
}

func TestNormalizeCLIArgsOrder(t *testing.T) {
	got := normalizeCLIArgs([]string{"/tmp/repo", "--json", "--image", "img:1", "--fix"})
	want := []string{"--json", "--image", "img:1", "--fix", "/tmp/repo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeCLIArgs mismatch: got %v, want %v", got, want)
	}
}

func TestStandaloneDynamicUnderNetworkNone(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}

	dir := t.TempDir()
	script := `import subprocess, urllib.request
subprocess.run(["/usr/bin/getent", "hosts", "c-binary-dns.huggingface.co"], check=False)
try:
    urllib.request.urlopen("http://plain-http.huggingface.co/weights.bin?token=SECRET_SHOULD_STRIP", timeout=2)
except Exception:
    pass
urllib.request.urlopen("https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken", timeout=2)
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := RunDynamicAirgapCheck(context.Background(), dir, report, DynamicRunOptions{
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	mergeDynamicResultIntoReport(report, dyn)

	rawJSONBytes, _ := json.Marshal(report)
	rawJSON := string(rawJSONBytes)

	if strings.Contains(rawJSON, "SECRET_SHOULD_STRIP") {
		t.Fatalf("query string secret leaked in dynamic output: %s", rawJSON)
	}
	if !strings.Contains(rawJSON, "c-binary-dns.huggingface.co") {
		t.Fatalf("expected UDP:53 DNS sinkhole to capture c-binary-dns.huggingface.co, got %s", rawJSON)
	}
	if !strings.Contains(rawJSON, `"protocol":"http_egress"`) || !strings.Contains(rawJSON, "plain-http.huggingface.co") {
		t.Fatalf("expected loopback HTTP:80 sinkhole to capture http_egress for plain-http.huggingface.co, got %s", rawJSON)
	}
	if !strings.Contains(rawJSON, `"protocol":"tls_sni"`) || !strings.Contains(rawJSON, "openaipublic.blob.core.windows.net") {
		t.Fatalf("expected loopback TLS:443 ClientHello SNI to capture openaipublic.blob.core.windows.net, got %s", rawJSON)
	}
}

func TestNodeOnlyDynamicUnderNetworkNone(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
	nodeImg := "node:20-bookworm-slim"
	if err := exec.Command("docker", "image", "inspect", nodeImg).Run(); err != nil {
		t.Skipf("%s image not cached locally; skipping Node-only Docker test", nodeImg)
	}

	dir := t.TempDir()
	pkg := `{"name": "node-airgap-probe", "main": "index.js"}`
	js := `const https = require('https');
const http = require('http');
http.get('http://plain-node.huggingface.co/model.json?key=NODE_SECRET', () => {}).on('error', () => {});
https.get('https://cdn.huggingface.co/config.json', () => {}).on('error', (err) => {
  console.error('HTTPS_ERR:' + err.message);
});
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := RunDynamicAirgapCheck(context.Background(), dir, report, DynamicRunOptions{
		DockerImage: nodeImg,
		RunCmd:      "node index.js",
		Timeout:     30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	mergeDynamicResultIntoReport(report, dyn)

	rawJSONBytes, _ := json.Marshal(report)
	rawJSON := string(rawJSONBytes)

	if dyn.ObserverRuntime != "node+udp53+sni" {
		t.Fatalf("expected ObserverRuntime node+udp53+sni, got %q (raw=%s)", dyn.ObserverRuntime, rawJSON)
	}
	if strings.Contains(rawJSON, "NODE_SECRET") {
		t.Fatalf("query string secret leaked in Node HTTP sinkhole output: %s", rawJSON)
	}
	if !strings.Contains(rawJSON, `"protocol":"tls_sni"`) || !strings.Contains(rawJSON, "cdn.huggingface.co") {
		t.Fatalf("expected Node runner.js TLS:443 SNI sinkhole to capture cdn.huggingface.co, got %s", rawJSON)
	}
	if !strings.Contains(rawJSON, `"protocol":"http_egress"`) || !strings.Contains(rawJSON, "plain-node.huggingface.co") {
		t.Fatalf("expected Node runner.js HTTP:80 sinkhole to capture plain-node.huggingface.co, got %s", rawJSON)
	}
}

func TestDynamicNxdomainAndDockerfileBuild(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
	pyImg := "python:3.12-slim-bookworm"
	if err := exec.Command("docker", "image", "inspect", pyImg).Run(); err != nil {
		t.Skipf("%s image not cached locally; skipping Docker --build / nxdomain test", pyImg)
	}

	dir := t.TempDir()
	dockerfile := "FROM python:3.12-slim-bookworm\nWORKDIR /app\nCOPY probe.py /app/probe.py\n"
	probePy := `import urllib.request
urllib.request.urlopen("https://models.unknown-registry.dev/weights.onnx", timeout=2)
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.py"), []byte(probePy), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verify BuildDockerfile (--build) with default sinkhole mode captures TLS ClientHello SNI.
	dynBuild, err := RunDynamicAirgapCheck(context.Background(), dir, report, DynamicRunOptions{
		RunCmd:          "python3 /app/probe.py",
		Timeout:         30 * time.Second,
		BuildDockerfile: true,
	})
	if err != nil {
		t.Fatalf("RunDynamicAirgapCheck (--build): %v", err)
	}
	if !dynBuild.AutoBuiltImage || !dynBuild.CrashedInAirgap {
		t.Fatalf("expected AutoBuiltImage=true and CrashedInAirgap=true, got %+v", dynBuild)
	}
	bJSON, _ := json.Marshal(dynBuild)
	if !strings.Contains(string(bJSON), `"protocol":"tls_sni"`) || !strings.Contains(string(bJSON), "models.unknown-registry.dev") {
		t.Fatalf("expected --build container to capture TLS SNI for models.unknown-registry.dev, got %s", string(bJSON))
	}

	// 2. Verify --dns-action nxdomain immediately fails DNS lookup without completing TLS handshake.
	dynNx, err := RunDynamicAirgapCheck(context.Background(), dir, report, DynamicRunOptions{
		DockerImage: pyImg,
		RunCmd:      "python3 /workspace/probe.py",
		Timeout:     30 * time.Second,
		DnsAction:   "nxdomain",
	})
	if err != nil {
		t.Fatalf("RunDynamicAirgapCheck (nxdomain): %v", err)
	}
	nxJSON, _ := json.Marshal(dynNx)
	if dynNx.FailureCategory != "DNS_RESOLUTION_BLOCKED_IN_AIRGAP" {
		t.Fatalf("expected DNS_RESOLUTION_BLOCKED_IN_AIRGAP under nxdomain, got %q (raw=%s)", dynNx.FailureCategory, string(nxJSON))
	}
	if strings.Contains(string(nxJSON), `"protocol":"tls_sni"`) {
		t.Fatalf("expected no TLS SNI connection under nxdomain, got %s", string(nxJSON))
	}
}

func TestClassifyDynamicFailureAndTracebackURLs(t *testing.T) {
	// 1. ModuleNotFoundError / ImportError / FileNotFoundError must NOT match "enotfound" DNS failure.
	importErrStderr := "Traceback (most recent call last):\n  File \"/workspace/app.py\", line 1\nImportError: Failed optional dependency 'nltk'. Original error: No module named 'nltk'"
	if got := classifyDynamicFailure(1, importErrStderr, nil); !strings.HasPrefix(got, "DEPENDENCY_NOT_INSTALLED_IN_BASE_IMAGE") {
		t.Fatalf("expected DEPENDENCY_NOT_INSTALLED_IN_BASE_IMAGE for ImportError/No module named, got %q", got)
	}
	fileErrStderr := "Traceback (most recent call last):\nFileNotFoundError: [Errno 2] No such file or directory: '/app/local.bin'"
	if got := classifyDynamicFailure(1, fileErrStderr, nil); got != "NON_ZERO_EXIT_IN_AIRGAP" {
		t.Fatalf("expected NON_ZERO_EXIT_IN_AIRGAP for FileNotFoundError, got %q", got)
	}
	// Real Node ENOTFOUND must still classify as DNS_RESOLUTION_BLOCKED_IN_AIRGAP.
	if got := classifyDynamicFailure(1, "Error: getaddrinfo ENOTFOUND models.huggingface.co", nil); got != "DNS_RESOLUTION_BLOCKED_IN_AIRGAP" {
		t.Fatalf("expected DNS_RESOLUTION_BLOCKED_IN_AIRGAP for real ENOTFOUND, got %q", got)
	}

	// 2. Consistent exitCode == 0 handling even when caught network warning was logged to stderr.
	caughtWarning := "WARNING: Cannot connect to host api.github.com:443 ssl:default [sslv3 alert handshake failure]"
	att := []DynamicEgressAttempt{{Protocol: "tls_sni", Host: "api.github.com", Port: 443, Detail: "sni"}}
	if got := classifyDynamicFailure(0, caughtWarning, att); got != "SILENT_EGRESS_ATTEMPTED_AND_DROPPED" {
		t.Fatalf("expected consistent SILENT_EGRESS_ATTEMPTED_AND_DROPPED on exit=0 with attempts, got %q", got)
	}

	// 3. Traceback documentation / warning URLs must not pollute ObservedAttempts,
	//    while genuine download failure URLs without hook logs still extract cleanly.
	tracebackWithDocs := strings.Join([]string{
		"===AIRGAP_CHECK_LOG_BEGIN===",
		`{"protocol":"dns_getaddrinfo","host":"b'api.openai.com'","port":443,"detail":"socket.getaddrinfo"}`,
		"===AIRGAP_CHECK_LOG_END===",
		"ValidationError: 1 validation error for OpenAICredentials",
		"    For further information visit https://errors.pydantic.dev/2.12/v/missing",
		"FutureWarning: For more details, visit: https://cloud.google.com/security/resources/post-quantum-cryptography",
		"Error: Could not load sharp. See https://sharp.pixelplumbing.com/install for details",
		"urllib.error.URLError: <urlopen error [Errno -2] Name or service not known> fetching https://weights.internal.example.org/model.onnx?token=secret123",
	}, "\n")

	attempts, _ := extractDynamicAttemptsFromStderr(tracebackWithDocs, "")
	if attempts == nil {
		t.Fatalf("expected non-nil ObservedAttempts slice")
	}
	rawAtt, _ := json.Marshal(attempts)
	sAtt := string(rawAtt)
	for _, banned := range []string{"errors.pydantic.dev", "cloud.google.com", "sharp.pixelplumbing.com", "b'api.openai.com'", "secret123"} {
		if strings.Contains(sAtt, banned) {
			t.Fatalf("unexpected pollution %q in ObservedAttempts: %s", banned, sAtt)
		}
	}
	if !strings.Contains(sAtt, `"host":"api.openai.com"`) {
		t.Fatalf("expected normalized api.openai.com from bytes literal, got %s", sAtt)
	}
	if !strings.Contains(sAtt, "weights.internal.example.org") {
		t.Fatalf("expected real fetch failure URL weights.internal.example.org, got %s", sAtt)
	}
}

func TestPnpmV9ImportersGraphUVDefaultGroupsAndSetuptoolsDynamic(t *testing.T) {
	dir := t.TempDir()

	// Multi-document pnpm-lock.yaml v9: dev playwright in importers.web.devDependencies must be excluded;
	// prod langchainhub in importers.server.dependencies + transitive @huggingface/transformers via snapshots must be included.
	pnpmLock := `---
lockfileVersion: '9.0'
importers:
  .:
    packageManagerDependencies:
      pnpm:
        specifier: 12.0.0
        version: 12.0.0
packages:
  '@pnpm/exe.linux-x64@12.0.0':
    resolution: {integrity: sha512-x}
---
lockfileVersion: '9.0'
importers:
  web:
    dependencies:
      react:
        specifier: ^19.0.0
        version: 19.0.0
    devDependencies:
      playwright:
        specifier: 1.64.1
        version: 1.64.1
      '@vitest/browser-playwright':
        specifier: 5.1.0
        version: 5.1.0
  server:
    dependencies:
      langchainhub:
        specifier: ^0.0.11
        version: 0.0.11
packages:
  playwright@1.64.1:
    resolution: {integrity: sha512-pw}
  langchainhub@0.0.11:
    resolution: {integrity: sha512-lh}
  '@huggingface/transformers@3.5.0':
    resolution: {integrity: sha512-hf}
snapshots:
  playwright@1.64.1: {}
  langchainhub@0.0.11:
    dependencies:
      '@huggingface/transformers': 3.5.0
  '@huggingface/transformers@3.5.0': {}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(pnpmLock), 0o644); err != nil {
		t.Fatal(err)
	}

	// uv [tool.uv] default-groups + optional unstructured -> spacy in uv.lock
	subUv := filepath.Join(dir, "py-svc")
	if err := os.MkdirAll(subUv, 0o755); err != nil {
		t.Fatal(err)
	}
	pyUV := `[project]
name = "py-svc"
dependencies = []

[project.optional-dependencies]
docs-rag = ["unstructured>=0.16"]

[tool.uv]
default-groups = ["tools", "trace-all"]

[dependency-groups]
dev = ["playwright>=1.50"]
tools = ["nltk>=3.10"]
trace-all = ["openai-agents>=0.20"]
`
	uvLock := `version = 1

[[package]]
name = "py-svc"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "unstructured"
version = "0.22.0"
dependencies = [
    { name = "spacy" },
]

[[package]]
name = "spacy"
version = "3.8.0"
`
	if err := os.WriteFile(filepath.Join(subUv, "pyproject.toml"), []byte(pyUV), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subUv, "uv.lock"), []byte(uvLock), 0o644); err != nil {
		t.Fatal(err)
	}

	// setuptools dynamic files precedence + optional-dependencies mapping (aider pattern)
	subAider := filepath.Join(dir, "cli-svc")
	if err := os.MkdirAll(filepath.Join(subAider, "requirements"), 0o755); err != nil {
		t.Fatal(err)
	}
	pySetuptools := `[project]
name = "cli-svc"
dynamic = ["dependencies", "optional-dependencies"]

[tool.setuptools.dynamic]
dependencies = { file = "requirements.txt" }

[tool.setuptools.dynamic.optional-dependencies]
dev = { file = "requirements/requirements-dev.txt" }
help = { file = "requirements/requirements-help.txt" }
`
	if err := os.WriteFile(filepath.Join(subAider, "pyproject.toml"), []byte(pySetuptools), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subAider, "requirements.txt"), []byte("tiktoken==0.12.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subAider, "requirements", "requirements-help.txt"), []byte("tiktoken==0.12.0\nsentence-transformers==5.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subAider, "requirements", "requirements-dev.txt"), []byte("playwright==1.50.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pinned spaCy wheel suppresses spacy crash risk (AutoGPT classic pattern)
	subSpacyPinned := filepath.Join(dir, "spacy-pinned")
	if err := os.MkdirAll(subSpacyPinned, 0o755); err != nil {
		t.Fatal(err)
	}
	pySpacyPinned := `[tool.poetry.dependencies]
python = "^3.12"
en-core-web-sm = { url = "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl" }
spacy = "^3.8.0"
`
	if err := os.WriteFile(filepath.Join(subSpacyPinned, "pyproject.toml"), []byte(pySpacyPinned), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	crashByComp := make(map[string]CheckRiskFinding)
	for _, f := range report.AirgapCrashRisks {
		crashByComp[f.Component] = f
	}
	if _, bad := crashByComp["playwright"]; bad {
		t.Fatalf("dev playwright from pnpm-lock v9 or requirements-dev.txt must not be flagged: %+v", bad)
	}
	if _, bad := crashByComp["spacy"]; bad {
		// Note: subSpacyPinned pinned spacy, while py-svc has spacy transitively in uv.lock via optional unstructured!
		// Verify specifically subSpacyPinned was not the source of spacy!
		if strings.Contains(crashByComp["spacy"].SourceFile, "spacy-pinned") {
			t.Fatalf("spacy with pinned en-core-web-sm wheel must be suppressed: %+v", crashByComp["spacy"])
		}
	}
	if f, ok := crashByComp["spacy"]; !ok || f.DependencyScope != "optional_extra" {
		t.Fatalf("expected transitive spacy under optional unstructured in uv.lock with scope optional_extra, got %+v", f)
	}
	if _, ok := crashByComp["langchainhub"]; !ok {
		t.Fatalf("expected langchainhub from pnpm-lock v9 importers.server.dependencies, got %+v", crashByComp)
	}
	if f, ok := crashByComp["transformers"]; !ok || f.DependencyScope != "transitive_lockfile" {
		t.Fatalf("expected @huggingface/transformers via pnpm-lock v9 snapshots BFS, got %+v", f)
	}
	if f, ok := crashByComp["nltk"]; !ok || f.DependencyScope != "prod" {
		t.Fatalf("expected nltk from [tool.uv] default-groups, got %+v", f)
	}
	if f, ok := crashByComp["tiktoken"]; !ok || !strings.HasSuffix(f.SourceFile, "cli-svc/requirements.txt") || f.DependencyScope != "prod" {
		t.Fatalf("expected root cli-svc/requirements.txt precedence for tiktoken, got %+v", f)
	}
	if f, ok := crashByComp["sentence-transformers"]; !ok || f.DependencyScope != "optional_extra" {
		t.Fatalf("expected sentence-transformers from [tool.setuptools.dynamic.optional-dependencies] help to be optional_extra, got %+v", f)
	}

	var hasOpenAIAgentsTel bool
	for _, tl := range report.TelemetryLeakRisks {
		if tl.Component == "openai-agents" {
			hasOpenAIAgentsTel = true
		}
	}
	if !hasOpenAIAgentsTel {
		t.Fatalf("expected openai-agents from default-groups trace-all in TelemetryLeakRisks, got %+v", report.TelemetryLeakRisks)
	}
}

func TestFPGuardsDocstringsHashMapsVertexAIAndDevScripts(t *testing.T) {
	dir := t.TempDir()
	// 1. Python docstring + Vertex AI + Go hash map + dev/eval script files
	pyDoc := `"""Helper documentation:
Example:
>>> from transformers import AutoTokenizer
>>> tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-32B-Instruct")
"""
from vertexai.language_models import TextEmbeddingModel

def embed():
    return TextEmbeddingModel.from_pretrained("textembedding-gecko@003")
`
	if err := os.WriteFile(filepath.Join(dir, "helper.py"), []byte(pyDoc), 0o644); err != nil {
		t.Fatal(err)
	}

	bpeLoader := `package tokenizer
/*
   tiktoken.get_encoding("cl100k_base")
   requests.get("https://ignored-block-comment.example.net/weights.onnx")
*/
var expectedBpeHashes = map[string]string{
	"https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken": "6494e42d5aad2bbb441ea9793af9e7db335c8d9c",
}
`
	if err := os.MkdirAll(filepath.Join(dir, "internal", "tokenizer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "tokenizer", "bpe_loader.go"), []byte(bpeLoader), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{
		"scripts/gen_tokenizer_oracle.py",
		"tools/scripts/download_dev_deps.py",
		"deps/download_deps.py",
		"backend/copilot/capabilities/eval/prefix.py",
		"backend/features/onboarding_dump/eval_corpus.py",
		"lib/devtools/litellm_catalog_update.py",
	} {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		src := "import tiktoken, requests\ntiktoken.get_encoding('cl100k_base')\nrequests.get('https://www.openslr.org/resources/31/dev.tar.gz')\n"
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AirgapCrashRisks) != 0 {
		t.Fatalf("expected 0 AirgapCrashRisks from docstrings, VertexAI, and dev/eval paths, got %+v", report.AirgapCrashRisks)
	}
	if len(report.BehavioralFindings) != 0 {
		t.Fatalf("expected 0 BehavioralFindings from hash map, block comments, and dev/eval paths, got %+v", report.BehavioralFindings)
	}
	if len(report.AllowedEgressManifest) != 0 {
		t.Fatalf("expected 0 AllowedEgressManifest hosts, got %+v", report.AllowedEgressManifest)
	}
}

func TestNewRulesHeuristicsAndSourceTelemetry(t *testing.T) {
	dir := t.TempDir()

	pkgJSON := `{"name": "app", "dependencies": {"tesseract.js": "^6.0.0", "kokoro-js": "^1.1.1"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	reqs := "gTTS==2.5.4\nopenai-agents==0.24.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatal(err)
	}

	// Multiline git clone subprocess + split URL + spacy.load() + version/pricing endpoints + raw telemetry URL
	pyCode := `import subprocess, urllib.request, spacy

subprocess.run([
    "git",
    "clone",
    "https://huggingface.co/spaces/org/repo",
])

MODEL_INFO_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/"
    "model_prices_and_context_window.json"
)
UPDATE_URL = "https://updates.example-ai.org"
PYPI_URL = "https://pypi.org/pypi/my-ai-cli/json"
GH_RELEASE_URL = "https://api.github.com/repos/org/app/releases/latest"
POSTHOG_HOST = "https://eu.i.posthog.com"
OTEL_HOST = "https://otel.dify.ai/v1/events"
TRACES_URL = "https://api.openai.com/v1/traces/ingest"

nlp = spacy.load("en_core_web_sm")
`
	if err := os.WriteFile(filepath.Join(dir, "worker.py"), []byte(pyCode), 0o644); err != nil {
		t.Fatal(err)
	}
	jsCode := `const REMOTE_URL = "https://models.dev/api.json";`
	if err := os.WriteFile(filepath.Join(dir, "pricing.js"), []byte(jsCode), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	crashComps := make(map[string]bool)
	for _, f := range report.AirgapCrashRisks {
		crashComps[f.Component] = true
	}
	for _, want := range []string{"tesseract.js", "kokoro-js", "gtts", "spacy.load()"} {
		if !crashComps[want] {
			t.Fatalf("expected %q in AirgapCrashRisks, got %+v", want, report.AirgapCrashRisks)
		}
	}

	behStr, _ := json.Marshal(report.BehavioralFindings)
	sBeh := string(behStr)
	for _, want := range []string{"behavioral_subprocess_download", "raw.githubusercontent.com", "models.dev", "updates.example-ai.org", "pypi.org", "api.github.com"} {
		if !strings.Contains(sBeh, want) {
			t.Fatalf("expected %q in BehavioralFindings, got %s", want, sBeh)
		}
	}

	telStr, _ := json.Marshal(report.TelemetryLeakRisks)
	sTel := string(telStr)
	for _, want := range []string{"openai-agents", "eu.i.posthog.com", "otel.dify.ai"} {
		if !strings.Contains(sTel, want) {
			t.Fatalf("expected %q in TelemetryLeakRisks, got %s", want, sTel)
		}
	}

	if !strings.Contains(report.RemediationDockerfileSnippet, "OPENAI_AGENTS_DISABLE_TRACING=1") {
		t.Fatalf("expected OPENAI_AGENTS_DISABLE_TRACING=1 in RemediationDockerfileSnippet")
	}
}

func TestDynamicEntrypointOverrideBytesHostAndDetachedChild(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
	pyImg := "python:3.12-slim-bookworm"
	if err := exec.Command("docker", "image", "inspect", pyImg).Run(); err != nil {
		t.Skipf("%s image not cached locally; skipping Docker test", pyImg)
	}

	dir := t.TempDir()
	dockerfile := "FROM python:3.12-slim-bookworm\nWORKDIR /app\nCOPY probe.py /app/probe.py\nENTRYPOINT [\"false\"]\n"
	probePy := `import atexit, os, socket, subprocess, sys
try:
    socket.getaddrinfo(b"bytes-host.huggingface.co", 443)
except Exception:
    pass

sender = """import urllib.request
try:
    urllib.request.urlopen("https://eu.i.posthog.com/batch/", timeout=2).read()
except Exception:
    pass
"""
atexit.register(lambda: subprocess.Popen([sys.executable, "-c", sender], start_new_session=True))
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.py"), []byte(probePy), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	dyn, err := RunDynamicAirgapCheck(context.Background(), dir, report, DynamicRunOptions{
		RunCmd:          "python3 /app/probe.py",
		Timeout:         30 * time.Second,
		BuildDockerfile: true,
	})
	if err != nil {
		t.Fatalf("RunDynamicAirgapCheck (--build with ENTRYPOINT): %v", err)
	}
	raw, _ := json.Marshal(dyn)
	sRaw := string(raw)

	if dyn.ExitCode != 0 {
		t.Fatalf("expected ENTRYPOINT [\"false\"] to be overridden cleanly so probe exits 0, got %s", sRaw)
	}
	if strings.Contains(sRaw, "b'bytes-host.huggingface.co'") {
		t.Fatalf("bytes literal host was not decoded in %s", sRaw)
	}
	if !strings.Contains(sRaw, `"host":"bytes-host.huggingface.co"`) {
		t.Fatalf("expected decoded bytes-host.huggingface.co in %s", sRaw)
	}
	if !strings.Contains(sRaw, "eu.i.posthog.com") {
		t.Fatalf("expected detached atexit child telemetry attempt to eu.i.posthog.com to be captured, got %s", sRaw)
	}
	if dyn.FailureCategory != "SILENT_EGRESS_ATTEMPTED_AND_DROPPED" {
		t.Fatalf("expected SILENT_EGRESS_ATTEMPTED_AND_DROPPED on exit=0 with attempts, got %q", dyn.FailureCategory)
	}
}

func TestDynamicTimeoutCleanupAndNodeFetch(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running")
	}
	pyImg := "python:3.12-slim-bookworm"
	nodeImg := "node:20-bookworm-slim"
	if err := exec.Command("docker", "image", "inspect", pyImg).Run(); err != nil {
		t.Skipf("%s not cached locally", pyImg)
	}
	if err := exec.Command("docker", "image", "inspect", nodeImg).Run(); err != nil {
		t.Skipf("%s not cached locally", nodeImg)
	}

	// 1. Timeout must stop and remove the container (no zombie containers) AND preserve attempts written before timeout.
	dirTimeout := t.TempDir()
	pySleep := `import time, urllib.request
try:
    urllib.request.urlopen("https://slow-model.huggingface.co/weights.bin", timeout=1).read()
except Exception:
    pass
time.sleep(15)
`
	if err := os.WriteFile(filepath.Join(dirTimeout, "app.py"), []byte(pySleep), 0o644); err != nil {
		t.Fatal(err)
	}
	repTo, _ := AnalyzeProjectAirgapAndEgress(dirTimeout)
	dynTo, err := RunDynamicAirgapCheck(context.Background(), dirTimeout, repTo, DynamicRunOptions{
		DockerImage: pyImg,
		RunCmd:      "python3 /workspace/app.py",
		Timeout:     2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunDynamicAirgapCheck timeout test failed: %v", err)
	}
	if !dynTo.CrashedInAirgap || dynTo.FailureCategory != "TIMEOUT_EXCEEDED_IN_AIRGAP" {
		t.Fatalf("expected TIMEOUT_EXCEEDED_IN_AIRGAP, got %+v", dynTo)
	}
	rawTo, _ := json.Marshal(dynTo)
	if !strings.Contains(string(rawTo), "slow-model.huggingface.co") {
		t.Fatalf("expected pre-timeout egress attempt slow-model.huggingface.co to be preserved even after timeout, got %s", string(rawTo))
	}
	psOut, _ := exec.Command("docker", "ps", "--filter", "name=airgap-check-", "-q").Output()
	if strings.TrimSpace(string(psOut)) != "" {
		t.Fatalf("expected zero lingering airgap-check-* containers after timeout, got %s", string(psOut))
	}

	// 2. Node 20 global fetch() (undici) must be captured cleanly via runner.js + node_preload.js.
	dirNode := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirNode, "package.json"), []byte(`{"name":"fetch-test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirNode, "fetch.js"), []byte(`fetch("https://fetch-api.huggingface.co/config.json").catch(() => {});`), 0o644); err != nil {
		t.Fatal(err)
	}
	repNode, _ := AnalyzeProjectAirgapAndEgress(dirNode)
	dynNode, err := RunDynamicAirgapCheck(context.Background(), dirNode, repNode, DynamicRunOptions{
		DockerImage: nodeImg,
		RunCmd:      "node /workspace/fetch.js",
		Timeout:     15 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunDynamicAirgapCheck node fetch test failed: %v", err)
	}
	rawNode, _ := json.Marshal(dynNode)
	if !strings.Contains(string(rawNode), "fetch-api.huggingface.co") {
		t.Fatalf("expected Node 20 global fetch() to be captured for fetch-api.huggingface.co, got %s", string(rawNode))
	}
}

func TestPythonMultilineExpressionTripleQuotesDoNotMaskSubsequentCode(t *testing.T) {
	dir := t.TempDir()

	modelsPy := `OPENAI_MODELS = """
gpt-4o
gpt-4o-mini
"""

ANTHROPIC_MODELS = f"""
claude-sonnet-4
"""

def docs_only():
    """Example doctest inside real docstring:
    >>> from transformers import AutoTokenizer
    >>> AutoTokenizer.from_pretrained("Qwen/Qwen2.5-0.5B")
    """
    return None

class ModelInfoManager:
    MODEL_INFO_URL = (
        "https://raw.githubusercontent.com/BerriAI/litellm/main/"
        "model_prices_and_context_window.json"
    )
`
	versionPy := `def warn(ver, img):
    if img:
        text = f"""
Newer version v{ver} is available.
"""
        return text

def check():
    import requests
    return requests.get("https://pypi.org/pypi/aider-chat/json", timeout=5)
`
	if err := os.WriteFile(filepath.Join(dir, "models.py"), []byte(modelsPy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "versioncheck.py"), []byte(versionPy), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AirgapCrashRisks) != 0 {
		t.Fatalf("docstring doctest should remain suppressed, got %+v", report.AirgapCrashRisks)
	}
	behBytes, _ := json.Marshal(report.BehavioralFindings)
	behStr := string(behBytes)
	for _, want := range []string{"raw.githubusercontent.com", "pypi.org"} {
		if !strings.Contains(behStr, want) {
			t.Fatalf("expected %q after multiline triple-quoted expression string, got %s", want, behStr)
		}
	}
}

func TestPnpmV9OptionalPeerDevPollutionAndTestRunnerExclusion(t *testing.T) {
	dir := t.TempDir()
	pnpmLock := `lockfileVersion: '9.0'

importers:

  web:
    dependencies:
      next:
        specifier: 16.4.5
        version: 16.4.5(@playwright/test@1.64.1)(react@19.3.1)
    devDependencies:
      '@playwright/test':
        specifier: 1.64.1
        version: 1.64.1
      playwright:
        specifier: 1.64.1
        version: 1.64.1

  server:
    dependencies:
      llamaindex:
        specifier: 0.3.13
        version: 0.3.13

packages:

  next@16.4.5:
    peerDependencies:
      '@playwright/test': ^1.51.1
    peerDependenciesMeta:
      '@playwright/test':
        optional: true

  '@playwright/test@1.64.1': {}
  playwright@1.64.1: {}
  llamaindex@0.3.13: {}
  '@xenova/transformers@2.17.1': {}

snapshots:

  next@16.4.5(@playwright/test@1.64.1)(react@19.3.1):
    optionalDependencies:
      '@playwright/test': 1.64.1

  '@playwright/test@1.64.1':
    dependencies:
      playwright: 1.64.1

  playwright@1.64.1: {}

  llamaindex@0.3.13:
    dependencies:
      '@xenova/transformers': 2.17.1

  '@xenova/transformers@2.17.1': {}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(pnpmLock), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	foundCrash := make(map[string]bool)
	for _, f := range report.AirgapCrashRisks {
		foundCrash[f.Component] = true
	}
	if !foundCrash["transformers"] {
		t.Fatalf("expected real transitive transformers via llamaindex, got %+v", report.AirgapCrashRisks)
	}
	if foundCrash["playwright"] {
		t.Fatalf("dev-satisfied optional peer @playwright/test on next must NOT flag playwright in prod BFS, got %+v", report.AirgapCrashRisks)
	}
}

func TestConftestNestedFrontendContextEnvTokensAndUITelemetry(t *testing.T) {
	dir := t.TempDir()

	// 1. conftest.py must be treated as test code and ignored.
	conftest := `SENTRY_DSN = "https://o1.ingest.us.sentry.io/12345"`
	if err := os.MkdirAll(filepath.Join(dir, "platform", "backend"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "platform", "backend", "conftest.py"), []byte(conftest), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Nested frontend/.ts must be tagged browser_client, not server_runtime.
	feDir := filepath.Join(dir, "platform", "frontend", "src", "services")
	if err := os.MkdirAll(feDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feDir, "env.ts"), []byte(`export const SENTRY_DSN = "https://o4505.ingest.us.sentry.io/999";`), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. UI placeholder, multiline window.open, and .credential.ts defaults must be ignored,
	//    while backend settings default PostHog host must remain detected.
	uiProviders := `export const providers = {
  langfuse: {
    docUrl: 'https://docs.langfuse.com',
    placeholder: 'https://cloud.langfuse.com',
  },
  langsmith: {
    placeholder: 'https://api.smith.langchain.com',
  },
};`
	uiCard := `export function Card({ id }: { id: string }) {
  const onView = () => {
    window.open(
      ` + "`" + `https://cloud.langfuse.com/project/${id}` + "`" + `,
      '_blank',
    );
  };
  return onView;
}`
	credTS := `class LangfuseApi implements INodeCredential {
  constructor() {
    this.inputs = [{ name: 'endpoint', default: 'https://cloud.langfuse.com' }];
  }
}`
	backendSettings := `class Settings:
    posthog_host: str = Field(default="https://eu.i.posthog.com")
`
	if err := os.MkdirAll(filepath.Join(dir, "web", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "web", "app", "providers.ts"), []byte(uiProviders), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "web", "app", "card.tsx"), []byte(uiCard), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "packages", "components", "credentials"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages", "components", "credentials", "LangfuseApi.credential.ts"), []byte(credTS), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "platform", "backend", "settings.py"), []byte(backendSettings), 0o644); err != nil {
		t.Fatal(err)
	}

	// 4. LLM token-count env vars must not be flagged as secrets, while GITHUB_TOKEN/API_TOKEN must.
	envFile := `RERANK_TOKEN_LIMIT_MODE=truncate
KNOWLEDGE_GRAPH_MIN_BATCH_TOKENS=2048
KNOWLEDGE_GRAPH_MAX_BATCH_TOKENS=4096
GITHUB_TOKEN=ghp_example123456
SERVICE_API_TOKEN=tok_live_999999
`
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envFile), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}

	var hasBrowserSentry, hasBackendPosthog bool
	for _, tl := range report.TelemetryLeakRisks {
		if strings.Contains(tl.SourceFile, "conftest.py") {
			t.Fatalf("conftest.py must be excluded, got %+v", tl)
		}
		if strings.Contains(tl.SourceFile, "providers.ts") || strings.Contains(tl.SourceFile, "card.tsx") || strings.Contains(tl.SourceFile, ".credential.ts") {
			t.Fatalf("UI placeholder/window.open/.credential.ts must not be flagged as telemetry leak, got %+v", tl)
		}
		if strings.Contains(tl.SourceFile, "frontend/src/services/env.ts") {
			if tl.ExecutionContext != "browser_client" {
				t.Fatalf("nested platform/frontend/... must be browser_client, got %+v", tl)
			}
			hasBrowserSentry = true
		}
		if strings.Contains(tl.SourceFile, "settings.py") && strings.Contains(tl.Component, "eu.i.posthog.com") {
			if tl.ExecutionContext != "server_runtime" {
				t.Fatalf("backend settings.py posthog must stay server_runtime, got %+v", tl)
			}
			hasBackendPosthog = true
		}
	}
	if !hasBrowserSentry || !hasBackendPosthog {
		t.Fatalf("expected nested frontend Sentry + backend PostHog, got %+v", report.TelemetryLeakRisks)
	}

	secretKeys := make(map[string]bool)
	for _, s := range report.EgressAndSecretRisks {
		secretKeys[s.Component] = true
	}
	for _, nonSecret := range []string{"RERANK_TOKEN_LIMIT_MODE", "KNOWLEDGE_GRAPH_MIN_BATCH_TOKENS", "KNOWLEDGE_GRAPH_MAX_BATCH_TOKENS"} {
		if secretKeys[nonSecret] {
			t.Fatalf("LLM token config %q must not be flagged as secret, got %+v", nonSecret, report.EgressAndSecretRisks)
		}
	}
	for _, realSecret := range []string{"GITHUB_TOKEN", "SERVICE_API_TOKEN"} {
		if !secretKeys[realSecret] {
			t.Fatalf("real secret %q must still be flagged, got %+v", realSecret, report.EgressAndSecretRisks)
		}
	}
}

func TestHumanetCLIBranding(t *testing.T) {
	dir := createTestFixture(t)
	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatalf("AnalyzeProjectAirgapAndEgress: %v", err)
	}

	var buf bytes.Buffer
	printCheckReportHuman(&buf, report, true)
	out := buf.String()

	lines := strings.Split(out, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 banner lines, got %d", len(lines))
	}
	if w0, w1, w2 := utf8.RuneCountInString(lines[0]), utf8.RuneCountInString(lines[1]), utf8.RuneCountInString(lines[2]); w0 != 79 || w1 != 79 || w2 != 79 {
		t.Fatalf("expected symmetrical 79-rune banner box widths, got top=%d mid=%d bot=%d", w0, w1, w2)
	}
	for _, want := range []string{
		"HUMANET AIRGAP-CHECK: OFFLINE & TELEMETRY AUDIT",
		"# --- BEGIN HUMANET AIRGAP-CHECK REMEDIATION (paste into your Dockerfile) ---",
		"# --- END HUMANET AIRGAP-CHECK REMEDIATION ---",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected human CLI report to contain %q, got:\n%s", want, out)
		}
	}

	if got := formatVersionString(); !strings.HasPrefix(got, "Humanet airgap-check ") {
		t.Fatalf("expected version string to start with 'Humanet airgap-check ', got %q", got)
	}

	var helpBuf bytes.Buffer
	fs, _ := newAirgapFlagSet(flag.ContinueOnError, &helpBuf)
	fs.Usage()
	helpOut := helpBuf.String()
	for _, want := range []string{
		"Humanet airgap-check " + version,
		"Usage of Humanet airgap-check: airgap-check [flags] [path]",
		"Print Humanet airgap-check version and exit",
	} {
		if !strings.Contains(helpOut, want) {
			t.Fatalf("expected help output to contain %q, got:\n%s", want, helpOut)
		}
	}
}
