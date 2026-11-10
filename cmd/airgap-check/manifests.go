package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestDep represents a parsed dependency from a package manifest or lockfile.
type ManifestDep struct {
	Name   string // normalized package name (lowercase, "_" -> "-" for Python/Rust)
	Scope  string // "prod", "optional_extra", "transitive_lockfile"
	Extra  string // optional extra name when Scope == "optional_extra"
	Via    string // originating parent package when discovered transitively
	Format string // "python", "node", "rust", "go", "ruby"
}

type tomlKV struct {
	section   string
	arrayIdx  int // >0 inside [[package]]-style blocks
	arrayName string
	key       string
	rawVal    string
}

// NormalizePackageName normalizes Python/Rust package names per PEP 503 (lowercase, _ and . -> -),
// while preserving npm scoped names like @huggingface/transformers.
func NormalizePackageName(raw string, format string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.Trim(s, `"'`)
	if s == "" {
		return ""
	}
	if format == "node" || strings.HasPrefix(s, "@") {
		return s
	}
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if r == '_' || r == '.' || r == '-' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		} else {
			b.WriteRune(r)
			prevDash = false
		}
	}
	return strings.Trim(b.String(), "-")
}

// ExtractDepNameAndExtras parses a PEP 508 / Cargo / pip dependency string such as:
//
//	"docling-slim[standard,cli]>=2.149.0 ; python_version >= '3.10'"
//
// returning normalized package name ("docling-slim") and requested extras (["standard", "cli"]).
func ExtractDepNameAndExtras(spec string, format string) (string, []string) {
	s := strings.TrimSpace(spec)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "-") {
		return "", nil
	}
	if idx := strings.Index(s, ";"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, " @ "); idx >= 0 {
		s = s[:idx]
	} else if idx := strings.Index(s, "@"); idx > 0 && !strings.HasPrefix(s, "@") {
		s = s[:idx]
	}

	var extras []string
	if lb := strings.Index(s, "["); lb >= 0 {
		if rb := strings.Index(s[lb:], "]"); rb > 0 {
			extraPart := s[lb+1 : lb+rb]
			for _, ex := range strings.Split(extraPart, ",") {
				ex = NormalizePackageName(ex, format)
				if ex != "" {
					extras = append(extras, ex)
				}
			}
			s = s[:lb] + s[lb+rb+1:]
		}
	}

	// Cut at version comparators or whitespace
	cut := len(s)
	for i, ch := range s {
		if ch == ' ' || ch == '\t' || ch == '=' || ch == '<' || ch == '>' || ch == '!' || ch == '~' || ch == ',' || ch == '(' {
			cut = i
			break
		}
	}
	name := NormalizePackageName(s[:cut], format)
	return name, extras
}

func isDevOrNonRuntimeGroupName(group string) bool {
	g := strings.ToLower(strings.TrimSpace(group))
	if g == "" {
		return false
	}
	exactIgnored := map[string]bool{
		"dev": true, "dev-dependencies": true, "development": true,
		"test": true, "tests": true, "testing": true,
		"lint": true, "linting": true, "format": true, "formatting": true,
		"typing": true, "typecheck": true, "type-check": true, "typechecking": true,
		"docs": true, "doc": true, "documentation": true,
		"ci": true, "coverage": true, "cov": true, "e2e": true, "e2e-dev": true,
		"benchmark": true, "benchmarks": true, "bench": true,
		"examples": true, "example": true, "constraints": true,
		"pr-fast-checks": true, "build": true, "release": true,
		"admin-mcp": true, "proxy-dev": true, "clai2-browser": true, "gh-aw-tracing": true,
		"healthcheck": true,
	}
	if exactIgnored[g] {
		return true
	}
	for _, prefix := range []string{"dev-", "test-", "lint-", "doc-", "docs-", "ci-", "e2e-"} {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	for _, suffix := range []string{"-dev", "-test", "-tests", "-lint", "-docs"} {
		if strings.HasSuffix(g, suffix) {
			return true
		}
	}
	return false
}

// IsDevOrTestManifestPath returns true for manifest filenames or paths dedicated to dev/test/CI.
func IsDevOrTestManifestPath(relSlash, lowerName string) bool {
	if strings.HasPrefix(lowerName, "requirements") && strings.HasSuffix(lowerName, ".txt") {
		base := strings.TrimSuffix(lowerName, ".txt")
		for _, tag := range []string{"-dev", "_dev", "-test", "_test", "-tests", "_tests", "-lint", "_lint", "-docs", "_docs", "-ci", "_ci"} {
			if strings.Contains(base, tag) {
				return true
			}
		}
	}
	return false
}

// IsManifestFileName returns true for direct dependency manifests (excluding lockfiles).
func IsManifestFileName(lowerName string) bool {
	switch lowerName {
	case "requirements.txt", "pyproject.toml", "pipfile", "package.json", "go.mod", "cargo.toml", "gemfile":
		return true
	}
	return strings.HasPrefix(lowerName, "requirements") && strings.HasSuffix(lowerName, ".txt")
}

// IsLockfileName returns true for supported lockfiles.
func IsLockfileName(lowerName string) bool {
	switch lowerName {
	case "uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "cargo.lock":
		return true
	}
	return false
}

// ParseManifestFile parses a manifest file structurally into ManifestDep records.
func ParseManifestFile(relSlash, lowerName string, rawBytes []byte) (deps []ManifestDep, requestedWorkspaceExtras map[string][]string) {
	switch {
	case lowerName == "package.json":
		return parsePackageJSONDeps(rawBytes), nil
	case lowerName == "pyproject.toml":
		return parsePyprojectTOML(rawBytes)
	case lowerName == "pipfile":
		return parsePipfileTOML(rawBytes), nil
	case lowerName == "cargo.toml":
		return parseCargoTOML(rawBytes), nil
	case lowerName == "go.mod":
		return parseGoMod(rawBytes), nil
	case lowerName == "gemfile":
		return parseGemfile(rawBytes), nil
	case strings.HasPrefix(lowerName, "requirements") && strings.HasSuffix(lowerName, ".txt"):
		return parseRequirementsTxt(rawBytes), nil
	}
	return nil, nil
}

func parsePackageJSONDeps(rawBytes []byte) []ManifestDep {
	var parsed struct {
		Dependencies         map[string]any `json:"dependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(rawBytes, &parsed); err != nil {
		return nil
	}
	var out []ManifestDep
	for k := range parsed.Dependencies {
		n := NormalizePackageName(k, "node")
		if n != "" {
			out = append(out, ManifestDep{Name: n, Scope: "prod", Format: "node"})
		}
	}
	for k := range parsed.OptionalDependencies {
		n := NormalizePackageName(k, "node")
		if n != "" {
			out = append(out, ManifestDep{Name: n, Scope: "optional_extra", Extra: "optionalDependencies", Format: "node"})
		}
	}
	return out
}

func parseRequirementsTxt(rawBytes []byte) []ManifestDep {
	var out []ManifestDep
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(string(rawBytes)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		name, _ := ExtractDepNameAndExtras(line, "python")
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, ManifestDep{Name: name, Scope: "prod", Format: "python"})
		}
	}
	return out
}

func parsePyprojectTOML(rawBytes []byte) ([]ManifestDep, map[string][]string) {
	kvs := scanTOMLKeyValues(string(rawBytes))
	var out []ManifestDep
	requestedExtras := make(map[string][]string)
	seen := make(map[string]bool)

	addDep := func(spec, scope, extra string) {
		name, exList := ExtractDepNameAndExtras(spec, "python")
		if name == "" || name == "python" {
			return
		}
		if scope == "prod" && len(exList) > 0 {
			requestedExtras[name] = append(requestedExtras[name], exList...)
		}
		key := scope + "|" + extra + "|" + name
		if !seen[key] {
			seen[key] = true
			out = append(out, ManifestDep{
				Name:   name,
				Scope:  scope,
				Extra:  extra,
				Format: "python",
			})
		}
	}

	for _, kv := range kvs {
		sec := strings.ToLower(strings.TrimSpace(kv.section))
		keyLower := strings.ToLower(strings.TrimSpace(kv.key))

		switch {
		case sec == "project" && keyLower == "dependencies":
			for _, item := range parseTOMLStringArray(kv.rawVal) {
				addDep(item, "prod", "")
			}
		case sec == "tool.hatch.metadata.hooks.uv-dynamic-versioning" && keyLower == "dependencies":
			for _, item := range parseTOMLStringArray(kv.rawVal) {
				addDep(item, "prod", "")
			}
		case sec == "tool.poetry.dependencies":
			pkg := NormalizePackageName(keyLower, "python")
			if pkg == "" || pkg == "python" {
				continue
			}
			// Check inline table `{ version = "...", optional = true }`
			if strings.Contains(strings.ToLower(kv.rawVal), "optional") && strings.Contains(strings.ToLower(kv.rawVal), "true") {
				addDep(pkg, "optional_extra", "poetry-optional")
			} else {
				addDep(pkg, "prod", "")
			}
		case sec == "project.optional-dependencies" ||
			sec == "tool.poetry.extras" ||
			sec == "tool.hatch.metadata.hooks.uv-dynamic-versioning.optional-dependencies":
			if isDevOrNonRuntimeGroupName(keyLower) {
				continue
			}
			for _, item := range parseTOMLStringArray(kv.rawVal) {
				addDep(item, "optional_extra", keyLower)
			}
		default:
			// Explicitly ignore [dependency-groups], [tool.poetry.group.*], [tool.poetry.dev-dependencies],
			// [tool.uv*], [tool.ruff*], [tool.mypy*], [tool.pyright*], [tool.ty*], [tool.pytest*],
			// [tool.hatch.envs*], [build-system], etc.
			continue
		}
	}
	return out, requestedExtras
}

func parsePipfileTOML(rawBytes []byte) []ManifestDep {
	kvs := scanTOMLKeyValues(string(rawBytes))
	var out []ManifestDep
	seen := make(map[string]bool)
	for _, kv := range kvs {
		if strings.ToLower(strings.TrimSpace(kv.section)) == "packages" {
			pkg := NormalizePackageName(kv.key, "python")
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				out = append(out, ManifestDep{Name: pkg, Scope: "prod", Format: "python"})
			}
		}
	}
	return out
}

func parseCargoTOML(rawBytes []byte) []ManifestDep {
	kvs := scanTOMLKeyValues(string(rawBytes))
	var out []ManifestDep
	seen := make(map[string]bool)
	for _, kv := range kvs {
		sec := strings.ToLower(strings.TrimSpace(kv.section))
		if sec == "dependencies" || sec == "workspace.dependencies" {
			pkg := NormalizePackageName(kv.key, "rust")
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				out = append(out, ManifestDep{Name: pkg, Scope: "prod", Format: "rust"})
			}
		} else if strings.HasPrefix(sec, "target.") && strings.HasSuffix(sec, ".dependencies") && !strings.Contains(sec, "dev-dependencies") {
			pkg := NormalizePackageName(kv.key, "rust")
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				out = append(out, ManifestDep{Name: pkg, Scope: "prod", Format: "rust"})
			}
		}
	}
	return out
}

func parseGoMod(rawBytes []byte) []ManifestDep {
	var out []ManifestDep
	seen := make(map[string]bool)
	inRequire := false
	sc := bufio.NewScanner(strings.NewReader(string(rawBytes)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
			fields := strings.Fields(line)
			if len(fields) >= 1 && !seen[fields[0]] {
				seen[fields[0]] = true
				out = append(out, ManifestDep{Name: strings.ToLower(fields[0]), Scope: "prod", Format: "go"})
			}
			continue
		}
		if inRequire {
			fields := strings.Fields(line)
			if len(fields) >= 1 && !seen[fields[0]] {
				seen[fields[0]] = true
				out = append(out, ManifestDep{Name: strings.ToLower(fields[0]), Scope: "prod", Format: "go"})
			}
		}
	}
	return out
}

func parseGemfile(rawBytes []byte) []ManifestDep {
	var out []ManifestDep
	seen := make(map[string]bool)
	inDevGroup := 0
	sc := bufio.NewScanner(strings.NewReader(string(rawBytes)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "group ") && (strings.Contains(lower, ":development") || strings.Contains(lower, ":test")) && strings.HasSuffix(lower, " do") {
			inDevGroup++
			continue
		}
		if inDevGroup > 0 && lower == "end" {
			inDevGroup--
			continue
		}
		if inDevGroup > 0 || strings.Contains(lower, ":development") || strings.Contains(lower, ":test") {
			continue
		}
		if strings.HasPrefix(lower, "gem ") {
			rest := strings.TrimSpace(line[4:])
			parts := strings.Split(rest, ",")
			if len(parts) > 0 {
				pkg := NormalizePackageName(parts[0], "ruby")
				if pkg != "" && !seen[pkg] {
					seen[pkg] = true
					out = append(out, ManifestDep{Name: pkg, Scope: "prod", Format: "ruby"})
				}
			}
		}
	}
	return out
}

// ParseLockfileGraph parses a lockfile and performs BFS from production dependencies
// so transitive dependencies are detected WITHOUT leaking dev/test packages.
func ParseLockfileGraph(lockAbsPath string, lowerName string, prodRoots []ManifestDep) []ManifestDep {
	rawBytes, err := os.ReadFile(lockAbsPath)
	if err != nil {
		return nil
	}
	switch lowerName {
	case "uv.lock":
		return parseUVLockBFS(rawBytes, prodRoots)
	case "poetry.lock":
		return parsePoetryLockBFS(rawBytes, prodRoots)
	case "package-lock.json":
		return parsePackageLockJSON(rawBytes)
	case "pnpm-lock.yaml":
		return parsePnpmLockYAML(rawBytes)
	case "yarn.lock":
		return parseYarnLockBFS(rawBytes, prodRoots)
	case "cargo.lock":
		return parseCargoLockBFS(rawBytes, prodRoots)
	}
	return nil
}

type lockEdge struct {
	name   string
	extras []string
}

type uvLockPkg struct {
	name       string
	sourceRaw  string
	deps       []lockEdge
	optDeps    map[string][]lockEdge
	isEditable bool
}

func parseUVLockBFS(rawBytes []byte, prodRoots []ManifestDep) []ManifestDep {
	kvs := scanTOMLKeyValues(string(rawBytes))
	var pkgs []*uvLockPkg
	byName := make(map[string][]*uvLockPkg)

	var cur *uvLockPkg
	curIdx := -1

	parseEdgeList := func(rawVal string) []lockEdge {
		var edges []lockEdge
		for _, tbl := range parseTOMLInlineTables(rawVal) {
			name := NormalizePackageName(tbl["name"], "python")
			if name == "" {
				continue
			}
			var extras []string
			if exRaw, ok := tbl["extra"]; ok {
				for _, ex := range parseTOMLStringArray(exRaw) {
					nEx := NormalizePackageName(ex, "python")
					if nEx != "" {
						extras = append(extras, nEx)
					}
				}
			}
			edges = append(edges, lockEdge{name: name, extras: extras})
		}
		return edges
	}

	for _, kv := range kvs {
		if kv.arrayName != "package" {
			continue
		}
		if kv.arrayIdx != curIdx {
			curIdx = kv.arrayIdx
			cur = &uvLockPkg{optDeps: make(map[string][]lockEdge)}
			pkgs = append(pkgs, cur)
		}
		if cur == nil {
			continue
		}
		sec := strings.ToLower(kv.section)
		key := strings.ToLower(kv.key)
		switch sec {
		case "package":
			switch key {
			case "name":
				cur.name = NormalizePackageName(kv.rawVal, "python")
				if cur.name != "" {
					byName[cur.name] = append(byName[cur.name], cur)
				}
			case "source":
				cur.sourceRaw = strings.ToLower(kv.rawVal)
				if strings.Contains(cur.sourceRaw, "editable") || strings.Contains(cur.sourceRaw, "virtual") {
					cur.isEditable = true
				}
			case "dependencies":
				cur.deps = append(cur.deps, parseEdgeList(kv.rawVal)...)
			}
		case "package.optional-dependencies":
			if !isDevOrNonRuntimeGroupName(key) {
				cur.optDeps[key] = append(cur.optDeps[key], parseEdgeList(kv.rawVal)...)
			}
		}
	}

	// Start BFS from editable/virtual workspace packages (excluding examples/tests/benchmarks members)
	type qNode struct {
		name  string
		extra string
		via   string
	}
	var queue []qNode
	isWorkspaceRoot := make(map[string]bool)

	for _, p := range pkgs {
		if !p.isEditable || p.name == "" {
			continue
		}
		// Skip example / test / eval / docs workspace packages unless they are root "."
		srcLower := p.sourceRaw
		if !strings.Contains(srcLower, `"."`) && !strings.Contains(srcLower, `'.'`) {
			isNonProdMember := false
			for _, seg := range []string{`example`, `test`, `eval`, `docs/`, `benchmark`} {
				if strings.Contains(srcLower, seg) {
					isNonProdMember = true
					break
				}
			}
			if isNonProdMember {
				continue
			}
		}
		isWorkspaceRoot[p.name] = true
		queue = append(queue, qNode{name: p.name, via: p.name})
	}
	if len(queue) == 0 && len(prodRoots) > 0 {
		for _, pr := range prodRoots {
			if pr.Format == "python" && pr.Scope == "prod" {
				queue = append(queue, qNode{name: pr.Name, via: pr.Name})
			}
		}
	}

	visitedNode := make(map[string]bool)
	discovered := make(map[string]string) // pkg -> via

	for len(queue) > 0 {
		curN := queue[0]
		queue = queue[1:]
		visitKey := curN.name + "|" + curN.extra
		if visitedNode[visitKey] {
			continue
		}
		visitedNode[visitKey] = true
		if !isWorkspaceRoot[curN.name] {
			if _, exists := discovered[curN.name]; !exists {
				discovered[curN.name] = curN.via
			}
		}
		for _, p := range byName[curN.name] {
			if curN.extra == "" {
				for _, ed := range p.deps {
					via := curN.via
					if via == "" {
						via = curN.name
					}
					queue = append(queue, qNode{name: ed.name, extra: "", via: via})
					for _, reqEx := range ed.extras {
						queue = append(queue, qNode{name: ed.name, extra: reqEx, via: via})
					}
				}
			} else {
				for _, ed := range p.optDeps[curN.extra] {
					queue = append(queue, qNode{name: ed.name, extra: "", via: curN.name + "[" + curN.extra + "]"})
					for _, reqEx := range ed.extras {
						queue = append(queue, qNode{name: ed.name, extra: reqEx, via: curN.name + "[" + curN.extra + "]"})
					}
				}
			}
		}
	}

	var out []ManifestDep
	for pkg, via := range discovered {
		out = append(out, ManifestDep{
			Name:   pkg,
			Scope:  "transitive_lockfile",
			Via:    via,
			Format: "python",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parsePoetryLockBFS(rawBytes []byte, prodRoots []ManifestDep) []ManifestDep {
	kvs := scanTOMLKeyValues(string(rawBytes))
	type poetryPkg struct {
		name     string
		optional bool
		category string
		groups   []string
		deps     []string
	}
	var pkgs []*poetryPkg
	byName := make(map[string]*poetryPkg)

	var cur *poetryPkg
	curIdx := -1
	for _, kv := range kvs {
		if kv.arrayName != "package" {
			continue
		}
		if kv.arrayIdx != curIdx {
			curIdx = kv.arrayIdx
			cur = &poetryPkg{}
			pkgs = append(pkgs, cur)
		}
		if cur == nil {
			continue
		}
		sec := strings.ToLower(kv.section)
		key := strings.ToLower(kv.key)
		switch sec {
		case "package":
			switch key {
			case "name":
				cur.name = NormalizePackageName(kv.rawVal, "python")
				if cur.name != "" {
					byName[cur.name] = cur
				}
			case "optional":
				cur.optional = strings.TrimSpace(strings.ToLower(kv.rawVal)) == "true"
			case "category":
				cur.category = strings.Trim(strings.ToLower(strings.TrimSpace(kv.rawVal)), `"'`)
			case "groups":
				for _, g := range parseTOMLStringArray(kv.rawVal) {
					cur.groups = append(cur.groups, strings.ToLower(strings.TrimSpace(g)))
				}
			}
		case "package.dependencies":
			dep := NormalizePackageName(key, "python")
			if dep != "" && dep != "python" {
				cur.deps = append(cur.deps, dep)
			}
		}
	}

	// Build BFS roots from manifest prod dependencies if available; otherwise non-dev, non-optional packages.
	type qNode struct {
		name string
		via  string
	}
	var queue []qNode
	hasProdRoots := false
	for _, pr := range prodRoots {
		if pr.Format == "python" && pr.Scope == "prod" {
			hasProdRoots = true
			queue = append(queue, qNode{name: pr.Name, via: pr.Name})
		}
	}
	if !hasProdRoots {
		for _, p := range pkgs {
			if p.name == "" || p.optional {
				continue
			}
			if p.category == "dev" {
				continue
			}
			if len(p.groups) > 0 {
				hasMain := false
				for _, g := range p.groups {
					if g == "main" {
						hasMain = true
					}
				}
				if !hasMain {
					continue
				}
			}
			queue = append(queue, qNode{name: p.name, via: p.name})
		}
	}

	visited := make(map[string]bool)
	discovered := make(map[string]string)
	for len(queue) > 0 {
		curN := queue[0]
		queue = queue[1:]
		if visited[curN.name] {
			continue
		}
		visited[curN.name] = true
		p := byName[curN.name]
		if p == nil {
			continue
		}
		if curN.via != curN.name {
			discovered[curN.name] = curN.via
		} else {
			discovered[curN.name] = curN.name
		}
		for _, dep := range p.deps {
			if !visited[dep] {
				queue = append(queue, qNode{name: dep, via: curN.via})
			}
		}
	}

	var out []ManifestDep
	for pkg, via := range discovered {
		out = append(out, ManifestDep{
			Name:   pkg,
			Scope:  "transitive_lockfile",
			Via:    via,
			Format: "python",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parsePackageLockJSON(rawBytes []byte) []ManifestDep {
	var v23 struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Dev         bool `json:"dev"`
			DevOptional bool `json:"devOptional"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Dev bool `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(rawBytes, &v23); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []ManifestDep
	if len(v23.Packages) > 0 {
		for pathKey, entry := range v23.Packages {
			if pathKey == "" || entry.Dev || entry.DevOptional {
				continue
			}
			idx := strings.LastIndex(pathKey, "node_modules/")
			if idx < 0 {
				continue
			}
			pkg := NormalizePackageName(pathKey[idx+len("node_modules/"):], "node")
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				out = append(out, ManifestDep{Name: pkg, Scope: "transitive_lockfile", Format: "node"})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	for name, entry := range v23.Dependencies {
		if entry.Dev {
			continue
		}
		pkg := NormalizePackageName(name, "node")
		if pkg != "" && !seen[pkg] {
			seen[pkg] = true
			out = append(out, ManifestDep{Name: pkg, Scope: "transitive_lockfile", Format: "node"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parsePnpmLockYAML(rawBytes []byte) []ManifestDep {
	// Parse pnpm-lock.yaml v5/v6/v9 packages/snapshots entries excluding `dev: true` blocks.
	lines := strings.Split(string(rawBytes), "\n")
	inPackages := false
	curPkg := ""
	curIsDev := false
	seen := make(map[string]bool)
	var entries []string

	flush := func() {
		if curPkg != "" && !curIsDev && !seen[curPkg] {
			seen[curPkg] = true
			entries = append(entries, curPkg)
		}
		curPkg = ""
		curIsDev = false
	}

	extractPnpmKeyPkg := func(key string) string {
		k := strings.TrimSpace(key)
		k = strings.TrimSuffix(k, ":")
		k = strings.Trim(k, `"'`)
		k = strings.TrimPrefix(k, "/")
		if k == "" {
			return ""
		}
		if idx := strings.Index(k, "("); idx > 0 {
			k = k[:idx]
		}
		if strings.HasPrefix(k, "@") {
			slash := strings.Index(k, "/")
			if slash < 0 {
				return ""
			}
			rest := k[slash+1:]
			if at := strings.Index(rest, "@"); at > 0 {
				rest = rest[:at]
			}
			return NormalizePackageName(k[:slash+1]+rest, "node")
		}
		if at := strings.Index(k, "@"); at > 0 {
			k = k[:at]
		}
		return NormalizePackageName(k, "node")
	}

	for _, line := range lines {
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			flush()
			trimmed := strings.TrimSpace(line)
			inPackages = trimmed == "packages:" || trimmed == "snapshots:"
			continue
		}
		if !inPackages {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			curPkg = extractPnpmKeyPkg(trimmed)
			continue
		}
		if curPkg != "" && (trimmed == "dev: true" || trimmed == "dev:true") {
			curIsDev = true
		}
	}
	flush()

	var out []ManifestDep
	for _, pkg := range entries {
		out = append(out, ManifestDep{Name: pkg, Scope: "transitive_lockfile", Format: "node"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseYarnLockBFS(rawBytes []byte, prodRoots []ManifestDep) []ManifestDep {
	// Parse yarn.lock v1 blocks (`pkg@ver:` with indented `dependencies:` map)
	lines := strings.Split(string(rawBytes), "\n")
	adj := make(map[string][]string)
	var allPkgs []string
	seenAll := make(map[string]bool)

	var curPkg string
	inDeps := false

	extractYarnName := func(header string) string {
		h := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(header), ":"))
		if idx := strings.Index(h, ","); idx > 0 {
			h = strings.TrimSpace(h[:idx])
		}
		h = strings.Trim(h, `"'`)
		if strings.HasPrefix(h, "@") {
			slash := strings.Index(h, "/")
			if slash > 0 {
				if at := strings.Index(h[slash+1:], "@"); at > 0 {
					return NormalizePackageName(h[:slash+1+at], "node")
				}
			}
			return ""
		}
		if at := strings.Index(h, "@"); at > 0 {
			return NormalizePackageName(h[:at], "node")
		}
		return NormalizePackageName(h, "node")
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			curPkg = ""
			inDeps = false
			continue
		}
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(trimmed, ":") {
			curPkg = extractYarnName(trimmed)
			inDeps = false
			if curPkg != "" && !seenAll[curPkg] {
				seenAll[curPkg] = true
				allPkgs = append(allPkgs, curPkg)
			}
			continue
		}
		if curPkg == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 2 {
			inDeps = trimmed == "dependencies:" || trimmed == "optionalDependencies:"
			continue
		}
		if inDeps && indent >= 4 {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				dep := NormalizePackageName(parts[0], "node")
				if dep != "" {
					adj[curPkg] = append(adj[curPkg], dep)
				}
			}
		}
	}

	var out []ManifestDep
	if len(prodRoots) > 0 {
		visited := make(map[string]bool)
		var q []string
		for _, r := range prodRoots {
			if r.Format == "node" {
				q = append(q, r.Name)
			}
		}
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if visited[cur] {
				continue
			}
			visited[cur] = true
			out = append(out, ManifestDep{Name: cur, Scope: "transitive_lockfile", Format: "node"})
			for _, nxt := range adj[cur] {
				if !visited[nxt] {
					q = append(q, nxt)
				}
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}

	for _, pkg := range allPkgs {
		out = append(out, ManifestDep{Name: pkg, Scope: "transitive_lockfile", Format: "node"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseCargoLockBFS(rawBytes []byte, prodRoots []ManifestDep) []ManifestDep {
	kvs := scanTOMLKeyValues(string(rawBytes))
	adj := make(map[string][]string)
	var allPkgs []string

	curName := ""
	curIdx := -1
	for _, kv := range kvs {
		if kv.arrayName != "package" {
			continue
		}
		if kv.arrayIdx != curIdx {
			curIdx = kv.arrayIdx
			curName = ""
		}
		if kv.section != "package" {
			continue
		}
		key := strings.ToLower(kv.key)
		switch key {
		case "name":
			curName = NormalizePackageName(kv.rawVal, "rust")
			if curName != "" {
				allPkgs = append(allPkgs, curName)
			}
		case "dependencies":
			if curName != "" {
				for _, item := range parseTOMLStringArray(kv.rawVal) {
					fields := strings.Fields(item)
					if len(fields) >= 1 {
						dep := NormalizePackageName(fields[0], "rust")
						if dep != "" {
							adj[curName] = append(adj[curName], dep)
						}
					}
				}
			}
		}
	}

	if len(prodRoots) > 0 {
		visited := make(map[string]bool)
		var q []string
		for _, r := range prodRoots {
			if r.Format == "rust" {
				q = append(q, r.Name)
			}
		}
		var out []ManifestDep
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if visited[cur] {
				continue
			}
			visited[cur] = true
			out = append(out, ManifestDep{Name: cur, Scope: "transitive_lockfile", Format: "rust"})
			for _, nxt := range adj[cur] {
				if !visited[nxt] {
					q = append(q, nxt)
				}
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}

	seen := make(map[string]bool)
	var out []ManifestDep
	for _, p := range allPkgs {
		if !seen[p] {
			seen[p] = true
			out = append(out, ManifestDep{Name: p, Scope: "transitive_lockfile", Format: "rust"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- Zero-dependency Quote-Aware TOML Scanner ---

func scanTOMLKeyValues(src string) []tomlKV {
	var out []tomlKV
	n := len(src)
	i := 0
	curSection := ""
	curArrayName := ""
	curArrayIdx := 0

	skipWSAndComments := func(stopAtNewline bool) {
		for i < n {
			c := src[i]
			if c == ' ' || c == '\t' || c == '\r' {
				i++
				continue
			}
			if !stopAtNewline && c == '\n' {
				i++
				continue
			}
			if c == '#' {
				for i < n && src[i] != '\n' {
					i++
				}
				if stopAtNewline {
					return
				}
				continue
			}
			break
		}
	}

	readQuoted := func() string {
		start := i
		if i+2 < n && (src[i:i+3] == `"""` || src[i:i+3] == `'''`) {
			delim := src[i : i+3]
			i += 3
			for i < n {
				if delim == `"""` && src[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if i+2 < n && src[i:i+3] == delim {
					i += 3
					break
				}
				i++
			}
			return src[start:i]
		}
		quote := src[i]
		i++
		for i < n && src[i] != '\n' {
			if quote == '"' && src[i] == '\\' && i+1 < n {
				i += 2
				continue
			}
			if src[i] == quote {
				i++
				break
			}
			i++
		}
		return src[start:i]
	}

	readBalanced := func(openCh, closeCh byte) string {
		start := i
		depth := 0
		for i < n {
			c := src[i]
			if c == '"' || c == '\'' {
				readQuoted()
				continue
			}
			if c == '#' {
				for i < n && src[i] != '\n' {
					i++
				}
				continue
			}
			if c == openCh {
				depth++
			} else if c == closeCh {
				depth--
				if depth <= 0 {
					i++
					break
				}
			}
			i++
		}
		return src[start:i]
	}

	for i < n {
		skipWSAndComments(false)
		if i >= n {
			break
		}

		// Table header [section] or [[array]]
		if src[i] == '[' {
			if i+1 < n && src[i+1] == '[' {
				i += 2
				end := strings.Index(src[i:], "]]")
				if end < 0 {
					break
				}
				name := strings.TrimSpace(src[i : i+end])
				i += end + 2
				curArrayIdx++
				curArrayName = name
				curSection = name
			} else {
				i++
				end := strings.Index(src[i:], "]")
				if end < 0 {
					break
				}
				name := strings.TrimSpace(src[i : i+end])
				i += end + 1
				if curArrayName == "" || !strings.HasPrefix(name, curArrayName+".") {
					curArrayName = ""
				}
				curSection = name
			}
			// skip remainder of header line
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}

		// Read key
		var key string
		if src[i] == '"' || src[i] == '\'' {
			key = strings.Trim(readQuoted(), `"'`)
		} else {
			start := i
			for i < n && src[i] != '=' && src[i] != '\n' && src[i] != '#' {
				i++
			}
			key = strings.TrimSpace(src[start:i])
		}

		skipWSAndComments(true)
		if i >= n || src[i] != '=' {
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		i++ // consume '='
		skipWSAndComments(true)
		if i >= n || src[i] == '\n' {
			continue
		}

		var rawVal string
		switch src[i] {
		case '[':
			rawVal = readBalanced('[', ']')
		case '{':
			rawVal = readBalanced('{', '}')
		case '"', '\'':
			rawVal = readQuoted()
		default:
			start := i
			for i < n && src[i] != '\n' && src[i] != '#' {
				i++
			}
			rawVal = strings.TrimSpace(src[start:i])
		}

		if key != "" {
			out = append(out, tomlKV{
				section:   curSection,
				arrayIdx:  curArrayIdx,
				arrayName: curArrayName,
				key:       key,
				rawVal:    rawVal,
			})
		}
	}
	return out
}

func parseTOMLStringArray(rawVal string) []string {
	s := strings.TrimSpace(rawVal)
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	s = s[1 : len(s)-1]
	var items []string
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c == '#' {
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote := c
			i++
			start := i
			for i < n {
				if quote == '"' && s[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if s[i] == quote {
					items = append(items, s[start:i])
					i++
					break
				}
				i++
			}
			continue
		}
		if c == '{' {
			// Skip inline table items inside mixed arrays (e.g. { include-group = "dev" })
			depth := 0
			for i < n {
				if s[i] == '{' {
					depth++
				} else if s[i] == '}' {
					depth--
					if depth <= 0 {
						i++
						break
					}
				}
				i++
			}
			continue
		}
		i++
	}
	return items
}

func parseTOMLInlineTables(rawVal string) []map[string]string {
	s := strings.TrimSpace(rawVal)
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	var out []map[string]string
	i := 0
	n := len(s)
	for i < n {
		if s[i] != '{' {
			i++
			continue
		}
		start := i + 1
		depth := 0
		for i < n {
			c := s[i]
			if c == '"' || c == '\'' {
				q := c
				i++
				for i < n {
					if q == '"' && s[i] == '\\' && i+1 < n {
						i += 2
						continue
					}
					if s[i] == q {
						i++
						break
					}
					i++
				}
				continue
			}
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth <= 0 {
					break
				}
			}
			i++
		}
		end := i
		if end > start {
			tblStr := s[start:end]
			kvMap := make(map[string]string)
			for _, field := range splitTopLevelCommas(tblStr) {
				eq := strings.Index(field, "=")
				if eq <= 0 {
					continue
				}
				k := strings.ToLower(strings.TrimSpace(field[:eq]))
				v := strings.TrimSpace(field[eq+1:])
				if strings.HasPrefix(v, `"`) || strings.HasPrefix(v, `'`) {
					v = strings.Trim(v, `"'`)
				}
				kvMap[k] = v
			}
			if len(kvMap) > 0 {
				out = append(out, kvMap)
			}
		}
		i++
	}
	return out
}

func splitTopLevelCommas(s string) []string {
	var parts []string
	start := 0
	bracket := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' {
			q := c
			i++
			for i < len(s) {
				if q == '"' && s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == q {
					break
				}
				i++
			}
			continue
		}
		switch c {
		case '[', '{':
			bracket++
		case ']', '}':
			if bracket > 0 {
				bracket--
			}
		case ',':
			if bracket == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(s) {
		parts = append(parts, strings.TrimSpace(s[start:]))
	}
	return parts
}

func lockfileDirMatches(lockRelSlash string, manifestDir string) bool {
	return filepath.ToSlash(filepath.Dir(lockRelSlash)) == manifestDir
}
