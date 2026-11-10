package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var version = "v0.2.2"

var (
	httpsURLRegex        = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::[0-9]+)?(/[^\s"'` + "`" + `)]*)?`)
	envKeyRegex          = regexp.MustCompile(`^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=\s*(.+)$`)
	spacyModelWheelPkgRe = regexp.MustCompile(`^[a-z]{2,3}-(?:core|dep|ent|sent)-(?:web|news|wiki|ud)-(?:sm|md|lg|trf)$`)
)

// normalizeCLIArgs reorders flags before positional arguments so invocations like
// `airgap-check /path/to/repo --json --fix` work identically to `airgap-check --json --fix /path/to/repo`.
func normalizeCLIArgs(raw []string) []string {
	valueFlags := map[string]bool{
		"-image": true, "--image": true,
		"-run-cmd": true, "--run-cmd": true,
		"-timeout": true, "--timeout": true,
		"-dns-action": true, "--dns-action": true,
		"-rules": true, "--rules": true,
	}
	var flagsPart, posPart []string
	for i := 0; i < len(raw); i++ {
		arg := raw[i]
		if arg == "--" {
			posPart = append(posPart, raw[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagsPart = append(flagsPart, arg)
			if valueFlags[arg] && !strings.Contains(arg, "=") && i+1 < len(raw) {
				i++
				flagsPart = append(flagsPart, raw[i])
			}
			continue
		}
		posPart = append(posPart, arg)
	}
	return append(flagsPart, posPart...)
}

func main() {
	var (
		jsonOutput  bool
		dynamicRun  bool
		showFix     bool
		buildImage  bool
		showVersion bool
		dockerImage string
		runCmd      string
		timeoutSec  int
		dnsAction   string
		rulesPath   string
	)

	fs := flag.NewFlagSet("airgap-check", flag.ExitOnError)
	fs.BoolVar(&jsonOutput, "json", false, "Output audit report in JSON format")
	fs.BoolVar(&dynamicRun, "run", false, "Run dynamic air-gap verification inside `docker run --rm --network none` and capture DNS/TLS SNI/HTTP attempts")
	fs.BoolVar(&showFix, "fix", false, "Print a ready-to-paste Dockerfile snippet (ENV + build-time pre-warming RUN lines)")
	fs.BoolVar(&buildImage, "build", false, "Auto-build a temporary image from the repo's Dockerfile when --run is used without --image")
	fs.StringVar(&dockerImage, "image", "", "Docker image to use with --run (defaults to detected ecosystem base image)")
	fs.StringVar(&runCmd, "run-cmd", "", "Custom command to execute inside the --network none container with --run")
	fs.IntVar(&timeoutSec, "timeout", 45, "Timeout in seconds for --run dynamic execution")
	fs.StringVar(&dnsAction, "dns-action", "sinkhole", "UDP:53 sinkhole behavior under --run: 'sinkhole' (return 127.0.0.1 for TLS SNI/HTTP capture) or 'nxdomain'")
	fs.StringVar(&rulesPath, "rules", "", "Optional path to custom JSON rules file (default: auto-loads .airgap-check.json in repo root)")
	fs.BoolVar(&showVersion, "version", false, "Print airgap-check version and exit")
	_ = fs.Parse(normalizeCLIArgs(os.Args[1:]))

	if showVersion {
		fmt.Printf("airgap-check %s\n", version)
		return
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	report, err := AnalyzeProjectAirgapAndEgressWithRules(target, rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airgap-check error: %v\n", err)
		os.Exit(1)
	}
	if dynamicRun {
		dynRes, dynErr := RunDynamicAirgapCheck(
			context.Background(),
			report.TargetPath,
			report,
			DynamicRunOptions{
				DockerImage:     dockerImage,
				RunCmd:          runCmd,
				Timeout:         time.Duration(timeoutSec) * time.Second,
				DnsAction:       dnsAction,
				BuildDockerfile: buildImage,
			},
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
	return AnalyzeProjectAirgapAndEgressWithRules(targetDir, "")
}

func AnalyzeProjectAirgapAndEgressWithRules(targetDir, customRulesPath string) (*CheckReport, error) {
	absPath, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("path %s must be a directory", absPath)
	}

	customRules, err := LoadCustomRules(absPath, customRulesPath)
	if err != nil {
		return nil, err
	}

	report := &CheckReport{
		TargetPath: absPath,
		Scope: CheckScope{
			Mode:               "static",
			InspectedManifests: []string{},
			InspectedLockfiles: []string{},
			InspectedEnvFiles:  []EnvFileScopeInfo{},
			LimitationsNote:    "Static scan inspects production manifest sections (ignoring dev/test/lint/docs groups), lockfile dependency graphs (uv.lock, poetry.lock, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock) via built-in minimal TOML/YAML/JSON readers (no external parser, so unusual formatting may be missed), runtime source code (known downloaders + generic download heuristics), and .env key names (values never read or logged). Runtime code paths require `airgap-check --run`.",
		},
		AirgapCrashRisks:      []CheckRiskFinding{},
		BehavioralFindings:    []CheckRiskFinding{},
		RobustnessHints:       []CheckRiskFinding{},
		TelemetryLeakRisks:    []CheckRiskFinding{},
		EgressAndSecretRisks:  []CheckRiskFinding{},
		AllowedEgressManifest: []EgressManifestEntry{},
		SecretRecommendations: []SecretRecommendation{},
		HermeticBuildEnv:      strings.Fields(defaultHermeticRuntimeEnv),
	}

	allPkgRules := make([]knownPackageRule, 0, len(knownAirgapAndTelemetryRules)+len(customRules.PkgRules))
	allPkgRules = append(allPkgRules, knownAirgapAndTelemetryRules...)
	allPkgRules = append(allPkgRules, customRules.PkgRules...)

	rulesByPkg := make(map[string][]knownPackageRule)
	for _, r := range allPkgRules {
		for _, pkg := range r.packages {
			n := strings.ToLower(strings.TrimSpace(pkg))
			if n != "" {
				rulesByPkg[n] = append(rulesByPkg[n], r)
			}
		}
	}

	type parsedManifestInfo struct {
		relSlash  string
		dirSlash  string
		lowerName string
		isBrowser bool
		deps      []ManifestDep
	}
	type lockfileInfo struct {
		absPath   string
		relSlash  string
		dirSlash  string
		lowerName string
		isBrowser bool
	}

	var manifests []parsedManifestInfo
	var lockfiles []lockfileInfo
	dynamicProdFiles := make(map[string]bool)
	dynamicExtraRoles := make(map[string]string) // normalized relSlash -> extraName

	seenCodeRules := make(map[string]bool)
	seenBehavioral := make(map[string]bool)
	discoveredHosts := make(map[string]string)
	seenSecrets := make(map[string]bool)

	isHostIgnored := func(h string) bool {
		return customRules.IgnoreHosts[strings.ToLower(strings.TrimSpace(h))]
	}
	isCompIgnored := func(comp, pkg string) bool {
		if customRules.IgnoreComponents[strings.ToLower(strings.TrimSpace(comp))] {
			return true
		}
		if pkg != "" && customRules.IgnoreComponents[strings.ToLower(strings.TrimSpace(pkg))] {
			return true
		}
		return false
	}

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
		lowerName := strings.ToLower(name)
		isEnvFile := !fi.IsDir() && strings.HasPrefix(lowerName, ".env")
		if !isEnvFile && shouldSkipPath(relPath, name, fi.IsDir()) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() || !fi.Mode().IsRegular() {
			return nil
		}

		maxSize := int64(4 * 1024 * 1024)
		if IsLockfileName(lowerName) {
			maxSize = 32 * 1024 * 1024
		}
		if fi.Size() > maxSize {
			return nil
		}

		relSlash := filepath.ToSlash(relPath)
		dirSlash := filepath.ToSlash(filepath.Dir(relSlash))
		isBrowserContext := isFrontendOrBrowserPath(relSlash, lowerName)

		if IsManifestFileName(lowerName) && !IsDevOrTestManifestPath(relSlash, lowerName) {
			report.Scope.InspectedManifests = append(report.Scope.InspectedManifests, relSlash)
			rawBytes, err := os.ReadFile(p)
			if err == nil {
				deps, _ := ParseManifestFile(relSlash, lowerName, rawBytes)
				if lowerName == "pyproject.toml" {
					pFiles, eFiles := ParsePyprojectDynamicFileRefs(rawBytes)
					for _, pf := range pFiles {
						targetRel := filepath.ToSlash(filepath.Clean(filepath.Join(dirSlash, pf)))
						dynamicProdFiles[targetRel] = true
					}
					for exName, files := range eFiles {
						for _, ef := range files {
							targetRel := filepath.ToSlash(filepath.Clean(filepath.Join(dirSlash, ef)))
							dynamicExtraRoles[targetRel] = exName
						}
					}
				}
				manifests = append(manifests, parsedManifestInfo{
					relSlash:  relSlash,
					dirSlash:  dirSlash,
					lowerName: lowerName,
					isBrowser: isBrowserContext,
					deps:      deps,
				})
			}
		}

		if IsLockfileName(lowerName) {
			report.Scope.InspectedLockfiles = append(report.Scope.InspectedLockfiles, relSlash)
			lockfiles = append(lockfiles, lockfileInfo{
				absPath:   p,
				relSlash:  relSlash,
				dirSlash:  dirSlash,
				lowerName: lowerName,
				isBrowser: isBrowserContext,
			})
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
								if !isHostIgnored(h) {
									if _, exists := discoveredHosts[h]; !exists {
										discoveredHosts[h] = "static_manifest"
									}
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

		if isSourceCodeFile(lowerName) && !isTestSourceFile(relSlash, lowerName) && !IsNonRuntimeSourcePath(relSlash, lowerName) {
			report.Scope.ScannedSourceFiles++
			rawBytes, err := os.ReadFile(p)
			if err == nil {
				content := string(rawBytes)
				lines := strings.Split(content, "\n")
				nonCodeLines := BuildNonCodeLineMask(content, lowerName)

				if strings.Contains(content, "next/font/google") && !seenCodeRules["next/font/google"] && !isCompIgnored("next/font/google", "") {
					for lineIdx, rawL := range lines {
						if nonCodeLines[lineIdx] || isCommentLine(strings.TrimSpace(rawL)) {
							continue
						}
						if strings.Contains(rawL, "next/font/google") {
							seenCodeRules["next/font/google"] = true
							report.AirgapCrashRisks = append(report.AirgapCrashRisks, CheckRiskFinding{
								Category:         "runtime_model_asset",
								Severity:         "HIGH",
								Component:        "next/font/google",
								SourceFile:       relSlash,
								DependencyScope:  "source_call",
								ExecutionContext: "server_runtime",
								EgressHosts:      []string{"fonts.googleapis.com", "fonts.gstatic.com"},
								FailureImpact:    "Fetches Google Fonts over HTTPS during build; fails in offline build environments.",
								Mitigation:       "Self-host font files with next/font/local for offline builds.",
								AutoSealedByEnv:  false,
							})
							break
						}
					}
				}

				var candidateCodeRules []sourceCodePatternRule
				for _, codeRule := range sourceCodeDownloadRules {
					if !isCompIgnored(codeRule.component, "") && hasAnySubstring(content, codeRule.hints) && codeRule.re.MatchString(content) {
						candidateCodeRules = append(candidateCodeRules, codeRule)
					}
				}
				if len(candidateCodeRules) > 0 {
					offset := 0
					for lineIdx, rawL := range lines {
						lineLen := len(rawL) + 1
						trimmed := strings.TrimSpace(rawL)
						if !nonCodeLines[lineIdx] && trimmed != "" && !isCommentLine(trimmed) {
							for _, codeRule := range candidateCodeRules {
								dedupKey := codeRule.component + "|" + relSlash
								if seenCodeRules[dedupKey] {
									continue
								}
								loc := codeRule.re.FindStringIndex(rawL)
								if loc == nil {
									continue
								}
								if strings.Contains(codeRule.component, "from_pretrained") && isManagedRemoteSDKFromPretrained(rawL) {
									continue
								}
								if codeRule.component == "gtts.gTTS()" && (strings.Contains(trimmed, "def gTTS") || strings.Contains(trimmed, "class gTTS")) {
									continue
								}
								if (strings.Contains(codeRule.component, "huggingface") || strings.Contains(codeRule.component, "TextEmbedding")) &&
									hasLocalFilesOnlyTrueNearby(content, offset+loc[1]) {
									continue
								}
								seenCodeRules[dedupKey] = true
								report.AirgapCrashRisks = append(report.AirgapCrashRisks, CheckRiskFinding{
									Category:         codeRule.category,
									Severity:         codeRule.severity,
									Component:        codeRule.component,
									SourceFile:       relSlash,
									DependencyScope:  "source_call",
									ExecutionContext: "server_runtime",
									EgressHosts:      codeRule.hosts,
									FailureImpact:    codeRule.impact,
									Mitigation:       codeRule.mitigation,
									AutoSealedByEnv:  codeRule.autoSealed,
								})
								if codeRule.component != "spacy.load()" {
									for _, h := range codeRule.hosts {
										if !isHostIgnored(h) {
											if _, exists := discoveredHosts[h]; !exists {
												discoveredHosts[h] = "static_code"
											}
										}
									}
								}
							}
						}
						offset += lineLen
					}
				}

				behFindings, robHints, behHosts := AnalyzeBehavioralPatterns(relSlash, content, seenBehavioral)
				for _, bf := range behFindings {
					if !isCompIgnored(bf.Component, "") {
						report.BehavioralFindings = append(report.BehavioralFindings, bf)
					}
				}
				for _, rh := range robHints {
					if !isCompIgnored(rh.Component, "") {
						report.RobustnessHints = append(report.RobustnessHints, rh)
					}
				}
				for h, src := range behHosts {
					if !isHostIgnored(h) {
						if _, exists := discoveredHosts[h]; !exists {
							discoveredHosts[h] = src
						}
					}
				}

				telSrcFindings, telSrcHosts := AnalyzeSourceTelemetryURLs(relSlash, content, nonCodeLines, isBrowserContext, seenCodeRules)
				for _, tf := range telSrcFindings {
					if !isCompIgnored(tf.Component, "") {
						report.TelemetryLeakRisks = append(report.TelemetryLeakRisks, tf)
					}
				}
				for h, src := range telSrcHosts {
					if !isHostIgnored(h) {
						if _, exists := discoveredHosts[h]; !exists {
							discoveredHosts[h] = src
						}
					}
				}

				if !isBrowserContext && (strings.Contains(content, "http://") || strings.Contains(content, "https://")) {
					hasHTTP := FileHasHTTPClient(content) && HasActiveHTTPClient(lines, nonCodeLines)
					for lineIdx, rawL := range lines {
						trimmed := strings.TrimSpace(rawL)
						if nonCodeLines[lineIdx] || trimmed == "" || isCommentLine(trimmed) {
							continue
						}
						if IsHashVerificationLine(rawL, content, hasHTTP) {
							continue
						}
						for _, m := range httpsURLRegex.FindAllStringSubmatch(rawL, -1) {
							if len(m) >= 2 {
								parsed, uErr := url.Parse(m[0])
								if uErr != nil || parsed.Hostname() == "" {
									continue
								}
								h := strings.ToLower(parsed.Hostname())
								if isIgnoredLocalOrDocHost(h) || isHostIgnored(h) {
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
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// Phase 2: Remap setuptools dynamic optional files, sort manifests deterministically
	// (shallowest + canonical/prod manifests first), and evaluate dependencies with scope priority:
	// prod (3) > transitive_lockfile (2) > optional_extra (1).
	for i := range manifests {
		if extraName, ok := dynamicExtraRoles[manifests[i].relSlash]; ok {
			if isDevOrNonRuntimeGroupName(extraName) {
				manifests[i].deps = nil
				continue
			}
			for j := range manifests[i].deps {
				manifests[i].deps[j].Scope = "optional_extra"
				manifests[i].deps[j].Extra = extraName
			}
		}
	}

	manifestPriority := func(m parsedManifestInfo) int {
		if dynamicProdFiles[m.relSlash] {
			return 0
		}
		switch m.lowerName {
		case "pyproject.toml", "package.json", "cargo.toml", "go.mod", "gemfile", "pipfile":
			return 1
		case "requirements.txt":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(manifests, func(i, j int) bool {
		di := strings.Count(manifests[i].relSlash, "/")
		dj := strings.Count(manifests[j].relSlash, "/")
		if di != dj {
			return di < dj
		}
		pi := manifestPriority(manifests[i])
		pj := manifestPriority(manifests[j])
		if pi != pj {
			return pi < pj
		}
		return manifests[i].relSlash < manifests[j].relSlash
	})

	spacyPinnedByDir := make(map[string]bool)
	for _, m := range manifests {
		for _, dep := range m.deps {
			if dep.Scope == "prod" && spacyModelWheelPkgRe.MatchString(dep.Name) {
				spacyPinnedByDir[m.dirSlash] = true
			}
		}
	}
	isSpacyPinnedForDir := func(dirSlash string) bool {
		if len(spacyPinnedByDir) == 0 {
			return false
		}
		cur := filepath.ToSlash(filepath.Clean(dirSlash))
		for {
			if spacyPinnedByDir[cur] {
				return true
			}
			if cur == "." || cur == "/" || cur == "" {
				break
			}
			parent := filepath.ToSlash(filepath.Dir(cur))
			if parent == cur {
				break
			}
			cur = parent
		}
		return false
	}

	scopeRank := func(s string) int {
		switch s {
		case "prod":
			return 3
		case "transitive_lockfile":
			return 2
		case "optional_extra":
			return 1
		default:
			return 0
		}
	}

	crashIndexByKey := make(map[string]int)
	telIndexByKey := make(map[string]int)

	recordDep := func(dep ManifestDep, sourceLabel, dirSlash string, isBrowser bool) {
		rules := rulesByPkg[dep.Name]
		for _, rule := range rules {
			if !matchesEcosystem(rule.ecosystems, dep.Format) {
				continue
			}
			if isCompIgnored(rule.component, dep.Name) {
				continue
			}
			if rule.component == "spacy" && isSpacyPinnedForDir(dirSlash) {
				continue
			}
			execCtx := "server_runtime"
			autoSealed := rule.autoSealed
			mitigation := rule.mitigation
			impact := rule.impact

			if isBrowser && rule.category == "telemetry_analytics" {
				execCtx = "browser_client"
				autoSealed = false
				targetHost := strings.Join(rule.hosts, ", ")
				if targetHost == "" {
					targetHost = "external telemetry endpoints"
				}
				impact = fmt.Sprintf("Client-side package in %s sends telemetry from the end-user's browser to %s. In air-gapped networks the server does not crash, but browser requests fail/timeout.", sourceLabel, targetHost)
				mitigation = "Server environment variables do NOT disable browser SDKs; gate SDK initialization in frontend source code."
			}

			dedupKey := rule.component + "|" + execCtx
			finding := CheckRiskFinding{
				Category:         rule.category,
				Severity:         rule.severity,
				Component:        rule.component,
				SourceFile:       sourceLabel,
				DependencyScope:  dep.Scope,
				ExecutionContext: execCtx,
				EgressHosts:      rule.hosts,
				FailureImpact:    impact,
				Mitigation:       mitigation,
				AutoSealedByEnv:  autoSealed,
			}

			if rule.category == "runtime_model_asset" {
				if idx, exists := crashIndexByKey[dedupKey]; exists {
					if scopeRank(dep.Scope) > scopeRank(report.AirgapCrashRisks[idx].DependencyScope) {
						report.AirgapCrashRisks[idx].DependencyScope = dep.Scope
						report.AirgapCrashRisks[idx].SourceFile = sourceLabel
					}
					continue
				}
				crashIndexByKey[dedupKey] = len(report.AirgapCrashRisks)
				report.AirgapCrashRisks = append(report.AirgapCrashRisks, finding)
			} else {
				if idx, exists := telIndexByKey[dedupKey]; exists {
					if scopeRank(dep.Scope) > scopeRank(report.TelemetryLeakRisks[idx].DependencyScope) {
						report.TelemetryLeakRisks[idx].DependencyScope = dep.Scope
						report.TelemetryLeakRisks[idx].SourceFile = sourceLabel
					}
					continue
				}
				telIndexByKey[dedupKey] = len(report.TelemetryLeakRisks)
				report.TelemetryLeakRisks = append(report.TelemetryLeakRisks, finding)
			}

			for _, h := range rule.hosts {
				if !isHostIgnored(h) {
					if _, exists := discoveredHosts[h]; !exists {
						discoveredHosts[h] = "static_manifest"
					}
				}
			}
		}

		if dep.Scope == "prod" || dep.Scope == "transitive_lockfile" {
			if host, ok := knownExternalHostSDKs[dep.Name]; ok && !isHostIgnored(host) {
				if _, exists := discoveredHosts[host]; !exists {
					discoveredHosts[host] = "static_manifest"
				}
			}
		}
	}

	// Pass 2a: direct prod dependencies from manifests
	allProdByDir := make(map[string][]ManifestDep)
	var allProdGlobal []ManifestDep
	allManifestByDir := make(map[string][]ManifestDep)
	var allManifestGlobal []ManifestDep
	for _, m := range manifests {
		for _, dep := range m.deps {
			if dep.Scope == "prod" || dep.Scope == "optional_extra" {
				allManifestByDir[m.dirSlash] = append(allManifestByDir[m.dirSlash], dep)
				allManifestGlobal = append(allManifestGlobal, dep)
			}
			if dep.Scope == "prod" {
				allProdByDir[m.dirSlash] = append(allProdByDir[m.dirSlash], dep)
				allProdGlobal = append(allProdGlobal, dep)
				recordDep(dep, m.relSlash, m.dirSlash, m.isBrowser)
			}
		}
	}

	// Pass 2b: lockfile BFS graph dependencies
	for _, lf := range lockfiles {
		var roots []ManifestDep
		if lf.lowerName == "uv.lock" || lf.lowerName == "poetry.lock" {
			roots = allManifestByDir[lf.dirSlash]
			if len(roots) == 0 {
				roots = allManifestGlobal
			}
		} else {
			roots = allProdByDir[lf.dirSlash]
			if len(roots) == 0 {
				roots = allProdGlobal
			}
		}
		transitive := ParseLockfileGraph(lf.absPath, lf.lowerName, roots)
		for _, dep := range transitive {
			if dep.Scope == "transitive_lockfile" && spacyModelWheelPkgRe.MatchString(dep.Name) {
				spacyPinnedByDir[lf.dirSlash] = true
			}
		}
		for _, dep := range transitive {
			src := lf.relSlash
			if dep.Via != "" {
				src = fmt.Sprintf("%s (via %s)", lf.relSlash, dep.Via)
			}
			recordDep(dep, src, lf.dirSlash, lf.isBrowser)
		}
	}

	// Pass 2c: optional_extra dependencies from manifests
	for _, m := range manifests {
		for _, dep := range m.deps {
			if dep.Scope == "optional_extra" {
				src := m.relSlash
				if dep.Extra != "" {
					src = fmt.Sprintf("%s [extra: %s]", m.relSlash, dep.Extra)
				}
				recordDep(dep, src, m.dirSlash, m.isBrowser)
			}
		}
	}

	// Post-Phase-2: suppress source-level spacy.load() in dirs where a spaCy model wheel is pinned,
	// and register hosts for unsuppressed spacy.load() findings.
	if len(report.AirgapCrashRisks) > 0 {
		filteredCrash := make([]CheckRiskFinding, 0, len(report.AirgapCrashRisks))
		for _, f := range report.AirgapCrashRisks {
			if f.Component == "spacy.load()" {
				srcDir := filepath.ToSlash(filepath.Dir(f.SourceFile))
				if isSpacyPinnedForDir(srcDir) {
					continue
				}
				for _, h := range f.EgressHosts {
					if !isHostIgnored(h) {
						if _, exists := discoveredHosts[h]; !exists {
							discoveredHosts[h] = "static_code"
						}
					}
				}
			}
			filteredCrash = append(filteredCrash, f)
		}
		report.AirgapCrashRisks = filteredCrash
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
		case ".git", "node_modules", ".next", "dist", "build", "out",
			"venv", ".venv", "__pycache__", "vendor", ".cache",
			"tests", "test", "__tests__", "testing",
			"ci_cd", ".github", ".agents", ".claude", ".codex",
			"fixtures", "testdata", "benchmarks", "benchmark", "examples", "docs", "cookbook":
			return true
		}
	}
	return false
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
	if lowerName == "conftest.py" || strings.Contains(relSlash, "/__tests__/") || strings.Contains(relSlash, "/test/") || strings.Contains(relSlash, "/tests/") {
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
		strings.HasPrefix(h, "otel.") || strings.HasPrefix(h, "telemetry.") || strings.Contains(h, ".otel.") ||
		strings.Contains(h, "smith.langchain.com") || strings.Contains(h, "langfuse.com") ||
		strings.Contains(h, "wandb.ai") || strings.Contains(h, "gradio.app") ||
		strings.Contains(h, "datadoghq.com") || strings.Contains(h, "segment.io") ||
		strings.Contains(h, "mixpanel.com") || strings.Contains(h, "amplitude.com"):
		return "telemetry_analytics"
	case strings.Contains(h, "huggingface.co") || strings.Contains(h, "hf.co") ||
		strings.Contains(h, "openaipublic.blob.core.windows.net") ||
		strings.Contains(h, "openaipublic.azureedge.net") ||
		strings.Contains(h, "chroma-onnx-models.s3.amazonaws.com") ||
		strings.Contains(h, "playwright.azureedge.net") ||
		strings.Contains(h, "raw.githubusercontent.com") ||
		strings.Contains(h, "download.pytorch.org") ||
		strings.Contains(h, "releases.jaided.ai") ||
		strings.Contains(h, "modelscope.cn") ||
		strings.Contains(h, "paddleocr.bj.bcebos.com"):
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
	if len(report.AirgapCrashRisks) > 0 || len(report.BehavioralFindings) > 0 || len(report.TelemetryLeakRisks) > 0 || len(report.EgressAndSecretRisks) > 0 {
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
		"Executed `%s` inside `docker run --rm --network none` (%s, observer=%s, %dms). Captures UDP:53 DNS queries, loopback TLS ClientHello SNI (:443), HTTP Host/Method/Path (:80 & proxy fallback without query strings), plus Python/Node hooks. Only code paths exercised by this command were tested.",
		dyn.Command, dyn.DockerImage, dyn.ObserverRuntime, dyn.DurationMs,
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
	report.RemediationDockerfileSnippet = generateRemediationDockerfileSnippet(report)

	if dyn.CrashedInAirgap {
		report.AirgapReadinessVerdict = fmt.Sprintf("DYNAMIC_AIRGAP_FAILURE (%s, exit=%d)", dyn.FailureCategory, dyn.ExitCode)
	} else if len(report.AirgapCrashRisks) > 0 || len(report.BehavioralFindings) > 0 {
		report.AirgapReadinessVerdict = "ACTION_REQUIRED_STATIC_FINDINGS (startup probe passed, but static runtime downloaders/patterns exist)"
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
	lower := strings.ToLower(relSlash)
	for _, seg := range []string{"frontend/", "client/", "web/", "apps/web/", "apps/frontend/", "src/components/", "packages/ui/"} {
		if strings.HasPrefix(lower, seg) || strings.Contains(lower, "/"+seg) {
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
	for _, token := range []string{"KEY", "SECRET", "PASSWORD", "DSN", "WEBHOOK"} {
		if strings.Contains(upper, token) {
			return true
		}
	}
	if strings.Contains(upper, "TOKEN") {
		for _, nonSecret := range []string{"_TOKENS", "TOKENS_", "TOKEN_LIMIT", "TOKEN_COUNT", "TOKEN_BUDGET", "TOKENIZER"} {
			if strings.Contains(upper, nonSecret) {
				return false
			}
		}
		return true
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
