package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
		"behavioral_unbounded_http_timeout",
		"behavioral_cache_dir_write",
	} {
		if !cats[want] {
			t.Fatalf("expected behavioral category %s, got %+v", want, report.BehavioralFindings)
		}
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
