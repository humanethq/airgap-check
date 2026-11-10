package main

// EnvFileScopeInfo records an inspected .env file and whether it is tracked in git.
type EnvFileScopeInfo struct {
	RelPath    string `json:"rel_path"`
	GitTracked bool   `json:"git_tracked"`
}

// CheckScope explicitly states what was scanned and tested during `airgap-check`.
type CheckScope struct {
	Mode               string             `json:"mode"`
	InspectedManifests []string           `json:"inspected_manifests"`
	InspectedLockfiles []string           `json:"inspected_lockfiles,omitempty"`
	InspectedEnvFiles  []EnvFileScopeInfo `json:"inspected_env_files"`
	ScannedSourceFiles int                `json:"scanned_source_files"`
	LimitationsNote    string             `json:"limitations_note"`
}

// CheckRiskFinding describes a static, behavioral, or runtime air-gap / telemetry / egress risk.
type CheckRiskFinding struct {
	Category         string   `json:"category"`
	Severity         string   `json:"severity"`
	Component        string   `json:"component"`
	SourceFile       string   `json:"source_file"`
	DependencyScope  string   `json:"dependency_scope,omitempty"` // "prod", "optional_extra", "transitive_lockfile", "source_call", "behavioral_heuristic"
	ExecutionContext string   `json:"execution_context"`          // "server_runtime" or "browser_client"
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

// CheckReport is the complete audit output of `airgap-check [path]`.
type CheckReport struct {
	TargetPath                   string                 `json:"target_path"`
	Scope                        CheckScope             `json:"scope"`
	AirgapCrashRisks             []CheckRiskFinding     `json:"airgap_crash_risks"`
	BehavioralFindings           []CheckRiskFinding     `json:"behavioral_findings"`
	TelemetryLeakRisks           []CheckRiskFinding     `json:"telemetry_leak_risks"`
	EgressAndSecretRisks         []CheckRiskFinding     `json:"egress_and_secret_risks"`
	AllowedEgressManifest        []EgressManifestEntry  `json:"allowed_egress_manifest"`
	SecretRecommendations        []SecretRecommendation `json:"secret_recommendations"`
	HermeticBuildEnv             []string               `json:"hermetic_build_env"`
	RemediationDockerfileSnippet string                 `json:"remediation_dockerfile_snippet,omitempty"`
	DynamicRun                   *DynamicCheckResult    `json:"dynamic_run,omitempty"`
	AirgapReadinessVerdict       string                 `json:"airgap_readiness_verdict"`
}

// DynamicEgressAttempt represents a single outbound DNS, HTTP, TLS SNI, or TCP
// connection attempt observed at runtime inside a `--network none` container.
type DynamicEgressAttempt struct {
	Protocol string `json:"protocol"` // "dns_udp53", "tls_sni", "http_egress", "http_proxy_connect", "dns_getaddrinfo", "tcp_connect", "dns_lookup_node", "tcp_connect_node", "runtime_error_url"
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// DynamicCheckResult holds the measured results of running the target workload
// inside `docker run --rm --network none`.
type DynamicCheckResult struct {
	Executed         bool                   `json:"executed"`
	DockerImage      string                 `json:"docker_image"`
	AutoBuiltImage   bool                   `json:"auto_built_image,omitempty"`
	Command          string                 `json:"command"`
	NetworkMode      string                 `json:"network_mode"`
	ObserverRuntime  string                 `json:"observer_runtime,omitempty"` // "python3+udp53+sni", "node+udp53+sni", "shell_only"
	ExitCode         int                    `json:"exit_code"`
	DurationMs       int64                  `json:"duration_ms"`
	CrashedInAirgap  bool                   `json:"crashed_in_airgap"`
	FailureCategory  string                 `json:"failure_category,omitempty"`
	ObservedAttempts []DynamicEgressAttempt `json:"observed_attempts"`
	StderrSnippet    string                 `json:"stderr_snippet,omitempty"`
}

// CustomRuleEntry allows extending airgap-check via `.airgap-check.json` or `--rules`.
type CustomRuleEntry struct {
	PackageOrPattern string   `json:"package_or_pattern"`
	Component        string   `json:"component"`
	Category         string   `json:"category"` // "runtime_model_asset" or "telemetry_analytics"
	Severity         string   `json:"severity"`
	Hosts            []string `json:"hosts"`
	Impact           string   `json:"impact"`
	Mitigation       string   `json:"mitigation"`
	PythonOnly       bool     `json:"python_only,omitempty"`
}

type CustomRulesFile struct {
	Rules []CustomRuleEntry `json:"rules"`
}
