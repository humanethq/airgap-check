package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected --fix output to contain %q, got:\n%s", want, out)
		}
	}

	if !isSelfOrCanonicalDomain("/workspace/projectx", "projectx.dev") {
		t.Fatalf("expected projectx.dev to be classified as self_or_canonical_domain")
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
urllib.request.urlopen("https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken", timeout=2)
`
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeProjectAirgapAndEgress(dir)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := RunDynamicAirgapCheck(context.Background(), dir, report, "", "", 30*1e9)
	if err != nil {
		t.Fatal(err)
	}
	mergeDynamicResultIntoReport(report, dyn)

	rawJSON, _ := json.Marshal(report)
	if !strings.Contains(string(rawJSON), "c-binary-dns.huggingface.co") {
		t.Fatalf("expected UDP:53 DNS sinkhole to capture c-binary-dns.huggingface.co, got %s", string(rawJSON))
	}
	if !strings.Contains(string(rawJSON), "openaipublic.blob.core.windows.net") {
		t.Fatalf("expected socket hook to capture openaipublic.blob.core.windows.net, got %s", string(rawJSON))
	}
}
