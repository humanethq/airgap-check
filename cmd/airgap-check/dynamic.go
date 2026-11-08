package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DynamicEgressAttempt represents a single outbound DNS, HTTP, TLS SNI, or TCP
// connection attempt observed at runtime inside a `--network none` container.
type DynamicEgressAttempt struct {
	Protocol string `json:"protocol"` // "dns_udp53", "dns_getaddrinfo", "tcp_connect", "dns_lookup_node", "tcp_connect_node", "runtime_error_url"
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// DynamicCheckResult holds the measured results of running the target workload
// inside `docker run --rm --network none`.
type DynamicCheckResult struct {
	Executed         bool                   `json:"executed"`
	DockerImage      string                 `json:"docker_image"`
	Command          string                 `json:"command"`
	NetworkMode      string                 `json:"network_mode"`
	ExitCode         int                    `json:"exit_code"`
	DurationMs       int64                  `json:"duration_ms"`
	CrashedInAirgap  bool                   `json:"crashed_in_airgap"`
	FailureCategory  string                 `json:"failure_category,omitempty"`
	ObservedAttempts []DynamicEgressAttempt `json:"observed_attempts"`
	StderrSnippet    string                 `json:"stderr_snippet,omitempty"`
}

const airgapObserverSiteCustomizePy = `import json
import os
import socket
import threading

_LOG_PATH = os.environ.get("AIRGAP_CHECK_LOG", "/tmp/airgap_check_attempts.jsonl")
_LOCK = threading.Lock()
_ORIG_GETADDRINFO = socket.getaddrinfo
_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex

def _record(proto, host, port=0, detail=""):
    if not host:
        return
    h = str(host).strip().lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", ""):
        return
    entry = {"protocol": proto, "host": h, "port": int(port or 0), "detail": str(detail or "")}
    with _LOCK:
        try:
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

def _hooked_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    p = 0
    try:
        p = int(port)
    except Exception:
        p = 0
    _record("dns_getaddrinfo", host, p, "socket.getaddrinfo")
    return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)

def _hooked_connect(self, address):
    if isinstance(address, tuple) and len(address) >= 2:
        _record("tcp_connect", address[0], address[1], "socket.connect")
    return _ORIG_CONNECT(self, address)

def _hooked_connect_ex(self, address):
    if isinstance(address, tuple) and len(address) >= 2:
        _record("tcp_connect", address[0], address[1], "socket.connect_ex")
    return _ORIG_CONNECT_EX(self, address)

socket.getaddrinfo = _hooked_getaddrinfo
socket.socket.connect = _hooked_connect
socket.socket.connect_ex = _hooked_connect_ex
`

const airgapObserverNodePreloadJS = `const fs = require('fs');
const dns = require('dns');
const net = require('net');

const logPath = process.env.AIRGAP_CHECK_LOG || '/tmp/airgap_check_attempts.jsonl';
function record(proto, host, port, detail) {
  if (!host) return;
  const h = String(host).trim().toLowerCase();
  if (!h || h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return;
  try {
    fs.appendFileSync(logPath, JSON.stringify({ protocol: proto, host: h, port: Number(port || 0), detail: String(detail || '') }) + '\n');
  } catch (_) {}
}

const origLookup = dns.lookup;
dns.lookup = function(hostname, options, callback) {
  record('dns_lookup_node', hostname, 0, 'dns.lookup');
  return origLookup.apply(this, arguments);
};

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  const opt = args[0];
  if (opt && typeof opt === 'object' && opt.host) {
    record('tcp_connect_node', opt.host, opt.port || 0, 'net.Socket.connect');
  }
  return origConnect.apply(this, args);
};
`

const airgapLoopbackRunnerPy = `import json
import os
import socket
import subprocess
import sys
import threading

LOG_PATH = "/tmp/airgap_check_attempts.jsonl"

def record(proto, host, port=0, detail=""):
    if not host:
        return
    h = str(host).strip().lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", ""):
        return
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps({"protocol": proto, "host": h, "port": int(port or 0), "detail": detail}) + "\n")

def start_dns_sinkhole():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 53))
    except Exception:
        return False
    def parse_qname(data):
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            labels.append(data[pos:pos+length].decode("ascii", errors="ignore"))
            pos += length
        return ".".join(labels)
    def loop():
        while True:
            try:
                data, addr = s.recvfrom(512)
                if len(data) >= 12:
                    qname = parse_qname(data)
                    if qname:
                        record("dns_udp53", qname, 53, "UDP:53 DNS query (language-agnostic)")
                    resp = data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:]
                    s.sendto(resp, addr)
            except Exception:
                break
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        with open("/etc/resolv.conf", "w", encoding="utf-8") as rf:
            rf.write("nameserver 127.0.0.1\noptions ndots:0 timeout:1 attempts:1\n")
    except Exception:
        pass
    return True

if __name__ == "__main__":
    open(LOG_PATH, "w").close()
    start_dns_sinkhole()
    cmd = sys.argv[1:]
    env = os.environ.copy()
    env["AIRGAP_CHECK_LOG"] = LOG_PATH
    hook_dir = "/tmp/airgap_hook"
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = hook_dir + (":" + existing_pp if existing_pp else "")
    proc = subprocess.run(cmd, env=env)
    print("===AIRGAP_CHECK_LOG_BEGIN===", file=sys.stderr)
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            sys.stderr.write(f.read())
    except Exception:
        pass
    print("===AIRGAP_CHECK_LOG_END===", file=sys.stderr)
    sys.exit(proc.returncode)
`

func RunDynamicAirgapCheck(ctx context.Context, absPath string, report *CheckReport, imageOverride, cmdOverride string, timeout time.Duration) (*DynamicCheckResult, error) {
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker CLI is required for --run dynamic air-gap verification: %w", err)
	}

	image := strings.TrimSpace(imageOverride)
	if image == "" {
		image = selectDefaultDynamicImage(absPath)
	}

	userCmd := strings.TrimSpace(cmdOverride)
	if userCmd == "" {
		userCmd = synthesizeDynamicProbeCommand(absPath)
	}

	hookHostDir, err := os.MkdirTemp("", "airgap-check-hook-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp hook dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(hookHostDir) }()

	if err := os.WriteFile(filepath.Join(hookHostDir, "sitecustomize.py"), []byte(airgapObserverSiteCustomizePy), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hookHostDir, "node_preload.js"), []byte(airgapObserverNodePreloadJS), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hookHostDir, "runner.py"), []byte(airgapLoopbackRunnerPy), 0o644); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shellWrapper := fmt.Sprintf(
		`: > /tmp/airgap_check_attempts.jsonl; if command -v python3 >/dev/null 2>&1; then python3 /tmp/airgap_hook/runner.py sh -c %s; else (%s); rc=$?; echo "===AIRGAP_CHECK_LOG_BEGIN===" >&2; cat /tmp/airgap_check_attempts.jsonl >&2 2>/dev/null; echo "===AIRGAP_CHECK_LOG_END===" >&2; exit $rc; fi`,
		shellSingleQuote(userCmd),
		userCmd,
	)

	dockerArgs := []string{
		"run", "--rm",
		"--network", "none",
		"-e", "AIRGAP_CHECK_LOG=/tmp/airgap_check_attempts.jsonl",
		"-e", "PYTHONPATH=/tmp/airgap_hook",
		"-e", "NODE_OPTIONS=--require /tmp/airgap_hook/node_preload.js",
		"-v", fmt.Sprintf("%s:/workspace:ro", absPath),
		"-v", fmt.Sprintf("%s:/tmp/airgap_hook:ro", hookHostDir),
		"-w", "/workspace",
		image,
		"sh", "-c",
		shellWrapper,
	}

	start := time.Now()
	cmd := exec.CommandContext(runCtx, "docker", dockerArgs...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	durationMs := time.Since(start).Milliseconds()

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	rawStderr := stderrBuf.String()
	attempts, cleanStderr := extractDynamicAttemptsFromStderr(rawStderr, stdoutBuf.String())
	failureCat := classifyDynamicFailure(exitCode, cleanStderr, attempts)

	return &DynamicCheckResult{
		Executed:         true,
		DockerImage:      image,
		Command:          userCmd,
		NetworkMode:      "none (kernel-isolated --network none)",
		ExitCode:         exitCode,
		DurationMs:       durationMs,
		CrashedInAirgap:  exitCode != 0 || failureCat != "",
		FailureCategory:  failureCat,
		ObservedAttempts: attempts,
		StderrSnippet:    truncateLines(cleanStderr, 12),
	}, nil
}

func selectDefaultDynamicImage(absPath string) string {
	for _, f := range []string{"requirements.txt", "pyproject.toml", "Pipfile", "backend/requirements.txt"} {
		if _, err := os.Stat(filepath.Join(absPath, f)); err == nil {
			return "python:3.12-slim-bookworm"
		}
	}
	if _, err := os.Stat(filepath.Join(absPath, "package.json")); err == nil {
		return "node:20-bookworm-slim"
	}
	return "python:3.12-slim-bookworm"
}

func synthesizeDynamicProbeCommand(absPath string) string {
	for _, entry := range []string{"app.py", "main.py", "server.py", "backend/server.py", "backend/main.py"} {
		if _, err := os.Stat(filepath.Join(absPath, entry)); err == nil {
			return "python3 " + entry
		}
	}
	if _, err := os.Stat(filepath.Join(absPath, "index.js")); err == nil {
		return "node index.js"
	}
	return "python3 -c 'print(\"airgap-probe\")'"
}

func extractDynamicAttemptsFromStderr(rawStderr, rawStdout string) ([]DynamicEgressAttempt, string) {
	const beginMarker = "===AIRGAP_CHECK_LOG_BEGIN==="
	const endMarker = "===AIRGAP_CHECK_LOG_END==="

	var attempts []DynamicEgressAttempt
	seen := make(map[string]bool)

	cleanStderr := rawStderr
	if idxBegin := strings.Index(rawStderr, beginMarker); idxBegin >= 0 {
		after := rawStderr[idxBegin+len(beginMarker):]
		if idxEnd := strings.Index(after, endMarker); idxEnd >= 0 {
			logBlock := after[:idxEnd]
			cleanStderr = strings.TrimSpace(rawStderr[:idxBegin] + after[idxEnd+len(endMarker):])
			for _, line := range strings.Split(logBlock, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var att DynamicEgressAttempt
				if err := json.Unmarshal([]byte(line), &att); err == nil && att.Host != "" {
					key := fmt.Sprintf("%s|%s|%d", att.Protocol, att.Host, att.Port)
					if !seen[key] {
						seen[key] = true
						attempts = append(attempts, att)
					}
				}
			}
		}
	}

	combined := cleanStderr + "\n" + rawStdout
	for _, m := range httpsURLRegex.FindAllStringSubmatch(combined, -1) {
		if len(m) >= 2 {
			host := strings.ToLower(strings.TrimSpace(m[1]))
			if host != "" && !isIgnoredLocalOrDocHost(host) {
				key := "runtime_error_url|" + host + "|443"
				if !seen[key] {
					seen[key] = true
					attempts = append(attempts, DynamicEgressAttempt{
						Protocol: "runtime_error_url",
						Host:     host,
						Port:     443,
						Detail:   m[0],
					})
				}
			}
		}
	}

	return attempts, cleanStderr
}

func classifyDynamicFailure(exitCode int, stderr string, attempts []DynamicEgressAttempt) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "temporary failure in name resolution") ||
		strings.Contains(lower, "gaierror") ||
		strings.Contains(lower, "name or service not known") ||
		strings.Contains(lower, "enotfound"):
		return "DNS_RESOLUTION_BLOCKED_IN_AIRGAP"
	case strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "connectionerror") ||
		strings.Contains(lower, "connecterror") ||
		strings.Contains(lower, "maxretryerror") ||
		strings.Contains(lower, "econnrefused") ||
		strings.Contains(lower, "enetunreach"):
		return "NETWORK_EGRESS_BLOCKED_IN_AIRGAP"
	case strings.Contains(lower, "executable doesn't exist") ||
		strings.Contains(lower, "can't load") ||
		strings.Contains(lower, "local_files_only") ||
		strings.Contains(lower, "cannotloadmodel") ||
		(strings.Contains(lower, "resource ") && strings.Contains(lower, "not found")):
		return "MISSING_OFFLINE_ASSET_OR_WEIGHTS"
	case strings.Contains(lower, "read-only file system") ||
		strings.Contains(lower, "permission denied: '/root/.cache"):
		return "READONLY_ROOTFS_CACHE_WRITE_FAILURE"
	case exitCode != 0 && (strings.Contains(lower, "modulenotfounderror") ||
		strings.Contains(lower, "no module named ") ||
		strings.Contains(lower, "cannot find module")):
		return "DEPENDENCY_NOT_INSTALLED_IN_BASE_IMAGE (pass --image <built-app-image>)"
	case exitCode != 0:
		return "NON_ZERO_EXIT_IN_AIRGAP"
	case len(attempts) > 0:
		return "SILENT_EGRESS_ATTEMPTED_AND_DROPPED"
	default:
		return ""
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncateLines(s string, maxLines int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[len(lines)-maxLines:], "\n")
}
