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
	} else if format == "python" && (strings.Contains(s, "://") || strings.HasSuffix(strings.ToLower(strings.TrimSpace(s)), ".whl")) {
		base := s
		if sl := strings.LastIndex(base, "/"); sl >= 0 {
			base = base[sl+1:]
		}
		if q := strings.IndexAny(base, "?#"); q >= 0 {
			base = base[:q]
		}
		// Extract distribution name from wheel filename like `en_core_web_sm-3.8.0-py3-none-any.whl`
		if strings.HasSuffix(strings.ToLower(base), ".whl") {
			if dash := strings.Index(base, "-"); dash > 0 {
				s = base[:dash]
			}
		}
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
		"doc-dev": true, "docs-dev": true, "doc-build": true, "docs-build": true, "docs-api": true, "mkdocs": true, "sphinx": true,
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
	for _, prefix := range []string{"dev-", "test-", "lint-", "ci-", "e2e-"} {
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

	var uvDefaultGroups []string
	uvDefaultGroupsAll := false
	depGroups := make(map[string][]string)
	depGroupIncludes := make(map[string][]string)

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
		case sec == "tool.uv" && (keyLower == "default-groups" || keyLower == "default_groups"):
			valClean := strings.Trim(strings.ToLower(strings.TrimSpace(kv.rawVal)), `"'`)
			if valClean == "all" {
				uvDefaultGroupsAll = true
			} else {
				for _, g := range parseTOMLStringArray(kv.rawVal) {
					gn := strings.ToLower(strings.TrimSpace(g))
					if gn != "" {
						uvDefaultGroups = append(uvDefaultGroups, gn)
					}
				}
			}
		case sec == "dependency-groups":
			depGroups[keyLower] = append(depGroups[keyLower], parseTOMLStringArray(kv.rawVal)...)
			for _, tbl := range parseTOMLInlineTables(kv.rawVal) {
				if inc := strings.ToLower(strings.TrimSpace(tbl["include-group"])); inc != "" {
					depGroupIncludes[keyLower] = append(depGroupIncludes[keyLower], inc)
				}
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
			// Ignore non-default [dependency-groups], [tool.poetry.group.*], lint/type/test sections, etc.
			continue
		}
	}

	if uvDefaultGroupsAll {
		for g := range depGroups {
			if !isDevOrNonRuntimeGroupName(g) {
				uvDefaultGroups = append(uvDefaultGroups, g)
			}
		}
		sort.Strings(uvDefaultGroups)
	}
	if len(uvDefaultGroups) > 0 && len(depGroups) > 0 {
		visitedGroup := make(map[string]bool)
		queue := append([]string(nil), uvDefaultGroups...)
		for len(queue) > 0 {
			g := queue[0]
			queue = queue[1:]
			if visitedGroup[g] || isDevOrNonRuntimeGroupName(g) {
				continue
			}
			visitedGroup[g] = true
			for _, item := range depGroups[g] {
				addDep(item, "prod", "")
			}
			for _, inc := range depGroupIncludes[g] {
				if !visitedGroup[inc] && !isDevOrNonRuntimeGroupName(inc) {
					queue = append(queue, inc)
				}
			}
		}
	}

	return out, requestedExtras
}

// ParsePyprojectDynamicFileRefs extracts file paths referenced under
// `[tool.setuptools.dynamic]` (`dependencies`) and `[tool.setuptools.dynamic.optional-dependencies]`.
func ParsePyprojectDynamicFileRefs(rawBytes []byte) ([]string, map[string][]string) {
	kvs := scanTOMLKeyValues(string(rawBytes))
	var prodFiles []string
	extraFiles := make(map[string][]string)

	extractFiles := func(rawVal string) []string {
		s := strings.TrimSpace(rawVal)
		if s == "" {
			return nil
		}
		var fileVals []string
		if strings.HasPrefix(s, "{") {
			tbl := parseTOMLSingleInlineTable(s)
			if fv, ok := tbl["file"]; ok {
				if strings.HasPrefix(strings.TrimSpace(fv), "[") {
					fileVals = parseTOMLStringArray(fv)
				} else if cleaned := strings.Trim(strings.TrimSpace(fv), `"'`); cleaned != "" {
					fileVals = []string{cleaned}
				}
			}
		} else if strings.HasPrefix(s, "[") {
			fileVals = parseTOMLStringArray(s)
		} else {
			if cleaned := strings.Trim(s, `"'`); cleaned != "" {
				fileVals = []string{cleaned}
			}
		}
		var cleanedOut []string
		for _, f := range fileVals {
			cf := filepath.ToSlash(filepath.Clean(strings.TrimSpace(f)))
			if cf != "" && cf != "." {
				cleanedOut = append(cleanedOut, cf)
			}
		}
		return cleanedOut
	}

	for _, kv := range kvs {
		sec := strings.ToLower(strings.TrimSpace(kv.section))
		keyLower := strings.ToLower(strings.TrimSpace(kv.key))
		switch sec {
		case "tool.setuptools.dynamic":
			if keyLower == "dependencies" {
				prodFiles = append(prodFiles, extractFiles(kv.rawVal)...)
			}
		case "tool.setuptools.dynamic.optional-dependencies":
			files := extractFiles(kv.rawVal)
			if len(files) > 0 {
				extraFiles[keyLower] = append(extraFiles[keyLower], files...)
			}
		}
	}
	return prodFiles, extraFiles
}

func parseTOMLSingleInlineTable(s string) map[string]string {
	out := make(map[string]string)
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return out
	}
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	for _, field := range splitTopLevelCommas(inner) {
		eq := strings.Index(field, "=")
		if eq <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(field[:eq]))
		v := strings.TrimSpace(field[eq+1:])
		if !strings.HasPrefix(v, "[") && !strings.HasPrefix(v, "{") {
			v = strings.Trim(v, `"'`)
		}
		out[k] = v
	}
	return out
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

func parseUVLockBFS(rawBytes []byte, manifestDeps []ManifestDep) []ManifestDep {
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

	type qNode struct {
		name       string
		extra      string
		via        string
		extraLabel string
	}
	var prodQueue []qNode
	var optQueue []qNode
	isWorkspaceRoot := make(map[string]bool)
	var optExtraNames []string

	for _, p := range pkgs {
		if !p.isEditable || p.name == "" {
			continue
		}
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
		prodQueue = append(prodQueue, qNode{name: p.name, via: p.name})
		for exName := range p.optDeps {
			optExtraNames = append(optExtraNames, exName)
		}
	}
	if len(prodQueue) == 0 && len(manifestDeps) > 0 {
		for _, pr := range manifestDeps {
			if pr.Format == "python" && pr.Scope == "prod" {
				prodQueue = append(prodQueue, qNode{name: pr.Name, via: pr.Name})
			}
		}
	}

	visitedProd := make(map[string]bool)
	discoveredProd := make(map[string]string) // pkg -> via
	for len(prodQueue) > 0 {
		curN := prodQueue[0]
		prodQueue = prodQueue[1:]
		visitKey := curN.name + "|" + curN.extra
		if visitedProd[visitKey] {
			continue
		}
		visitedProd[visitKey] = true
		if !isWorkspaceRoot[curN.name] {
			if _, exists := discoveredProd[curN.name]; !exists {
				discoveredProd[curN.name] = curN.via
			}
		}
		for _, p := range byName[curN.name] {
			if curN.extra == "" {
				for _, ed := range p.deps {
					via := curN.via
					if via == "" {
						via = curN.name
					}
					prodQueue = append(prodQueue, qNode{name: ed.name, extra: "", via: via})
					for _, reqEx := range ed.extras {
						prodQueue = append(prodQueue, qNode{name: ed.name, extra: reqEx, via: via})
					}
				}
			} else {
				for _, ed := range p.optDeps[curN.extra] {
					prodQueue = append(prodQueue, qNode{name: ed.name, extra: "", via: curN.name + "[" + curN.extra + "]"})
					for _, reqEx := range ed.extras {
						prodQueue = append(prodQueue, qNode{name: ed.name, extra: reqEx, via: curN.name + "[" + curN.extra + "]"})
					}
				}
			}
		}
	}

	sort.Slice(optExtraNames, func(i, j int) bool {
		if optExtraNames[i] == "all" && optExtraNames[j] != "all" {
			return false
		}
		if optExtraNames[i] != "all" && optExtraNames[j] == "all" {
			return true
		}
		return optExtraNames[i] < optExtraNames[j]
	})
	for _, pr := range manifestDeps {
		if pr.Format == "python" && pr.Scope == "optional_extra" && !isDevOrNonRuntimeGroupName(pr.Extra) {
			viaLabel := pr.Name
			if pr.Extra != "" {
				viaLabel = pr.Name + " [extra: " + pr.Extra + "]"
			}
			optQueue = append(optQueue, qNode{name: pr.Name, extra: "", via: viaLabel, extraLabel: pr.Extra})
		}
	}
	for _, p := range pkgs {
		if !isWorkspaceRoot[p.name] {
			continue
		}
		for _, exName := range optExtraNames {
			for _, ed := range p.optDeps[exName] {
				optQueue = append(optQueue, qNode{name: ed.name, extra: "", via: p.name + "[" + exName + "]", extraLabel: exName})
				for _, reqEx := range ed.extras {
					optQueue = append(optQueue, qNode{name: ed.name, extra: reqEx, via: p.name + "[" + exName + "]", extraLabel: exName})
				}
			}
		}
	}

	type optDiscovery struct {
		via   string
		extra string
	}
	visitedOpt := make(map[string]bool)
	discoveredOpt := make(map[string]optDiscovery)
	for len(optQueue) > 0 {
		curN := optQueue[0]
		optQueue = optQueue[1:]
		visitKey := curN.name + "|" + curN.extra
		if visitedOpt[visitKey] {
			continue
		}
		visitedOpt[visitKey] = true
		if !isWorkspaceRoot[curN.name] {
			if _, inProd := discoveredProd[curN.name]; !inProd {
				if _, exists := discoveredOpt[curN.name]; !exists {
					discoveredOpt[curN.name] = optDiscovery{via: curN.via, extra: curN.extraLabel}
				}
			}
		}
		for _, p := range byName[curN.name] {
			if curN.extra == "" {
				for _, ed := range p.deps {
					optQueue = append(optQueue, qNode{name: ed.name, extra: "", via: curN.via, extraLabel: curN.extraLabel})
					for _, reqEx := range ed.extras {
						optQueue = append(optQueue, qNode{name: ed.name, extra: reqEx, via: curN.via, extraLabel: curN.extraLabel})
					}
				}
			} else {
				for _, ed := range p.optDeps[curN.extra] {
					optQueue = append(optQueue, qNode{name: ed.name, extra: "", via: curN.via, extraLabel: curN.extraLabel})
					for _, reqEx := range ed.extras {
						optQueue = append(optQueue, qNode{name: ed.name, extra: reqEx, via: curN.via, extraLabel: curN.extraLabel})
					}
				}
			}
		}
	}

	var out []ManifestDep
	for pkg, via := range discoveredProd {
		out = append(out, ManifestDep{
			Name:   pkg,
			Scope:  "transitive_lockfile",
			Via:    via,
			Format: "python",
		})
	}
	for pkg, info := range discoveredOpt {
		out = append(out, ManifestDep{
			Name:   pkg,
			Scope:  "optional_extra",
			Extra:  info.extra,
			Via:    info.via,
			Format: "python",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Scope < out[j].Scope
	})
	return out
}

func parsePoetryLockBFS(rawBytes []byte, manifestDeps []ManifestDep) []ManifestDep {
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

	type qNode struct {
		name  string
		via   string
		extra string
	}
	var prodQueue []qNode
	var optQueue []qNode
	hasProdRoots := false
	for _, pr := range manifestDeps {
		if pr.Format == "python" && pr.Scope == "prod" {
			hasProdRoots = true
			prodQueue = append(prodQueue, qNode{name: pr.Name, via: pr.Name})
		} else if pr.Format == "python" && pr.Scope == "optional_extra" && !isDevOrNonRuntimeGroupName(pr.Extra) {
			via := pr.Name
			if pr.Extra != "" {
				via = pr.Name + " [extra: " + pr.Extra + "]"
			}
			optQueue = append(optQueue, qNode{name: pr.Name, via: via, extra: pr.Extra})
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
			prodQueue = append(prodQueue, qNode{name: p.name, via: p.name})
		}
	}

	visited := make(map[string]bool)
	discovered := make(map[string]string)
	for len(prodQueue) > 0 {
		curN := prodQueue[0]
		prodQueue = prodQueue[1:]
		if visited[curN.name] {
			continue
		}
		visited[curN.name] = true
		p := byName[curN.name]
		if p == nil {
			continue
		}
		discovered[curN.name] = curN.via
		for _, dep := range p.deps {
			if !visited[dep] {
				prodQueue = append(prodQueue, qNode{name: dep, via: curN.via})
			}
		}
	}

	type optDisc struct {
		via   string
		extra string
	}
	visitedOpt := make(map[string]bool)
	discoveredOpt := make(map[string]optDisc)
	for len(optQueue) > 0 {
		curN := optQueue[0]
		optQueue = optQueue[1:]
		if visitedOpt[curN.name] {
			continue
		}
		visitedOpt[curN.name] = true
		p := byName[curN.name]
		if p == nil {
			continue
		}
		if _, inProd := discovered[curN.name]; !inProd {
			if _, exists := discoveredOpt[curN.name]; !exists {
				discoveredOpt[curN.name] = optDisc{via: curN.via, extra: curN.extra}
			}
		}
		for _, dep := range p.deps {
			if !visitedOpt[dep] {
				optQueue = append(optQueue, qNode{name: dep, via: curN.via, extra: curN.extra})
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
	for pkg, info := range discoveredOpt {
		out = append(out, ManifestDep{
			Name:   pkg,
			Scope:  "optional_extra",
			Extra:  info.extra,
			Via:    info.via,
			Format: "python",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Scope < out[j].Scope
	})
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

func splitYAMLMapLine(trimmed string) (key, val string, ok bool) {
	if trimmed == "" || strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if trimmed[0] == '\'' || trimmed[0] == '"' {
		q := trimmed[0]
		end := strings.IndexByte(trimmed[1:], q)
		if end >= 0 {
			rest := strings.TrimSpace(trimmed[end+2:])
			if strings.HasPrefix(rest, ":") {
				k := trimmed[1 : end+1]
				v := strings.TrimSpace(rest[1:])
				return k, v, true
			}
		}
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == ':' && (i+1 == len(trimmed) || trimmed[i+1] == ' ' || trimmed[i+1] == '\t') {
			return strings.TrimSpace(trimmed[:i]), strings.TrimSpace(trimmed[i+1:]), true
		}
	}
	return "", "", false
}

func cleanPnpmScalar(s string) string {
	v := strings.TrimSpace(s)
	v = strings.Trim(v, `"'`)
	return strings.TrimSpace(v)
}

func isNonProdPnpmImporter(importer string) bool {
	imp := strings.ToLower(cleanPnpmScalar(importer))
	imp = strings.TrimSuffix(imp, ":")
	imp = strings.Trim(imp, "/")
	if imp == "" || imp == "." {
		return false
	}
	for _, seg := range strings.Split(imp, "/") {
		switch seg {
		case "e2e", "test", "tests", "__tests__", "testing", "benchmark", "benchmarks",
			"example", "examples", "docs", "doc", "dev-proxy", "tooling", ".storybook":
			return true
		}
		if strings.HasPrefix(seg, "migrate-") || strings.HasSuffix(seg, "-dev") || strings.HasSuffix(seg, "-test") {
			return true
		}
	}
	return false
}

func isLockfileTestRunnerPkg(pkg string) bool {
	switch strings.ToLower(strings.TrimSpace(pkg)) {
	case "@playwright/test", "@vitest/browser-playwright", "@axe-core/playwright",
		"@chromatic-com/playwright", "playwright-test", "pytest-playwright",
		"vitest", "jest", "cypress", "@testing-library/dom",
		"@storybook/nextjs-vite", "@storybook/addon-vitest", "storybook":
		return true
	default:
		return false
	}
}

func parsePnpmLockYAML(rawBytes []byte) []ManifestDep {
	// Parse multi-document (`---`) pnpm-lock.yaml v5/v6/v9.
	// In v9, devDependencies are excluded by running BFS from non-dev `importers:`
	// (`dependencies` + `optionalDependencies`) across `snapshots:` (`dependencies` + `optionalDependencies`),
	// skipping optional peer edges declared optional in `packages.*.peerDependenciesMeta` and test runners.
	lines := strings.Split(string(rawBytes), "\n")

	cleanKey := func(raw string) string {
		k := cleanPnpmScalar(strings.TrimSuffix(strings.TrimSpace(raw), ":"))
		k = strings.TrimPrefix(k, "/")
		return k
	}

	stripPnpmPeers := func(key string) string {
		if idx := strings.Index(key, "("); idx > 0 {
			return key[:idx]
		}
		return key
	}

	extractPnpmKeyPkg := func(key string) string {
		k := cleanKey(key)
		if k == "" {
			return ""
		}
		k = stripPnpmPeers(k)
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

	type pnpmNodeRef struct {
		pkg      string
		exactKey string
	}

	type pnpmEdge struct {
		ref           pnpmNodeRef
		isOptional    bool
		sourceBaseKey string
	}

	resolvePnpmTarget := func(depPkg, depVerRaw string) pnpmNodeRef {
		ver := cleanPnpmScalar(depVerRaw)
		if ver == "" || ver == "{}" || strings.HasPrefix(ver, "link:") || strings.HasPrefix(ver, "workspace:") {
			return pnpmNodeRef{pkg: depPkg}
		}
		verNoPeer := stripPnpmPeers(ver)
		// Detect npm aliases such as `lexical-code-no-prism@0.41.0(...)`
		hasAliasAt := strings.Contains(verNoPeer, "@") && (!strings.HasPrefix(verNoPeer, "@") || strings.Contains(verNoPeer[strings.Index(verNoPeer, "/")+1:], "@"))
		if hasAliasAt {
			aliasPkg := extractPnpmKeyPkg(ver)
			if aliasPkg != "" {
				return pnpmNodeRef{pkg: aliasPkg, exactKey: ver}
			}
			return pnpmNodeRef{pkg: depPkg, exactKey: ver}
		}
		return pnpmNodeRef{pkg: depPkg, exactKey: depPkg + "@" + ver}
	}

	hasImportersSection := false
	hasSnapshotsSection := false

	var importerRoots []pnpmNodeRef
	seenRoots := make(map[string]bool)

	snapEdgesByKey := make(map[string][]pnpmEdge)
	snapEdgesByPkg := make(map[string][]pnpmEdge)
	knownSnapKey := make(map[string]bool)

	pkgEdgesByKey := make(map[string][]pnpmEdge)
	pkgEdgesByPkg := make(map[string][]pnpmEdge)
	knownPkgKey := make(map[string]bool)
	optionalPeerByBasePkg := make(map[string]map[string]bool)

	var legacyEntries []string
	seenLegacy := make(map[string]bool)

	section := "" // "importers", "packages", "snapshots"

	// Importer parser state
	curImpSkipped := false
	curImpDepSection := "" // "dependencies" | "optionalDependencies"
	pendingImpDepPkg := ""
	pendingImpDepVer := ""

	flushImporterDep := func() {
		if pendingImpDepPkg != "" && !curImpSkipped {
			ref := resolvePnpmTarget(pendingImpDepPkg, pendingImpDepVer)
			if ref.pkg != "" {
				rk := ref.pkg + "|" + ref.exactKey
				if !seenRoots[rk] {
					seenRoots[rk] = true
					importerRoots = append(importerRoots, ref)
				}
			}
		}
		pendingImpDepPkg = ""
		pendingImpDepVer = ""
	}

	// Packages / snapshots parser state
	curEntryKey := ""
	curEntryBaseKey := ""
	curEntryPkg := ""
	curEntrySubSection := "" // "dependencies" | "optionalDependencies" | "peerDependenciesMeta"
	curPeerMetaPkg := ""
	curIsDev := false

	flushPkgOrSnap := func() {
		if section == "packages" && curEntryPkg != "" && !curIsDev && !seenLegacy[curEntryPkg] {
			seenLegacy[curEntryPkg] = true
			legacyEntries = append(legacyEntries, curEntryPkg)
		} else if section == "snapshots" && curEntryPkg != "" && !seenLegacy[curEntryPkg] {
			seenLegacy[curEntryPkg] = true
			legacyEntries = append(legacyEntries, curEntryPkg)
		}
		curEntryKey = ""
		curEntryBaseKey = ""
		curEntryPkg = ""
		curEntrySubSection = ""
		curPeerMetaPkg = ""
		curIsDev = false
	}

	resetSection := func() {
		flushImporterDep()
		flushPkgOrSnap()
		section = ""
		curImpSkipped = false
		curImpDepSection = ""
	}

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" || trimmed == "..." {
			resetSection()
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 && line[0] != '\t' {
			resetSection()
			switch trimmed {
			case "importers:":
				section = "importers"
				hasImportersSection = true
			case "snapshots:":
				section = "snapshots"
				hasSnapshotsSection = true
			case "packages:":
				section = "packages"
			}
			continue
		}

		switch section {
		case "importers":
			if indent == 2 {
				flushImporterDep()
				curImpDepSection = ""
				curImpSkipped = isNonProdPnpmImporter(trimmed)
				continue
			}
			if curImpSkipped {
				continue
			}
			if indent == 4 {
				flushImporterDep()
				k, v, ok := splitYAMLMapLine(trimmed)
				if ok && v != "{}" && (k == "dependencies" || k == "optionalDependencies") {
					curImpDepSection = k
				} else {
					curImpDepSection = ""
				}
				continue
			}
			if curImpDepSection == "" {
				continue
			}
			if indent == 6 {
				flushImporterDep()
				k, v, ok := splitYAMLMapLine(trimmed)
				if ok {
					pendingImpDepPkg = extractPnpmKeyPkg(k)
					if v != "" && v != "{}" {
						pendingImpDepVer = v
					}
				}
				continue
			}
			if indent >= 8 && pendingImpDepPkg != "" {
				k, v, ok := splitYAMLMapLine(trimmed)
				if ok && k == "version" {
					pendingImpDepVer = v
				}
			}

		case "snapshots", "packages":
			if indent == 2 {
				flushPkgOrSnap()
				k, _, ok := splitYAMLMapLine(trimmed)
				if !ok {
					continue
				}
				curEntryKey = cleanKey(k)
				curEntryBaseKey = stripPnpmPeers(curEntryKey)
				curEntryPkg = extractPnpmKeyPkg(curEntryKey)
				if section == "snapshots" && curEntryKey != "" {
					knownSnapKey[curEntryKey] = true
				} else if section == "packages" && curEntryKey != "" {
					knownPkgKey[curEntryKey] = true
				}
				continue
			}
			if curEntryPkg == "" {
				continue
			}
			if indent == 4 {
				curPeerMetaPkg = ""
				if section == "packages" && (trimmed == "dev: true" || trimmed == "dev:true") {
					curIsDev = true
					curEntrySubSection = ""
					continue
				}
				k, v, ok := splitYAMLMapLine(trimmed)
				if ok && v != "{}" && (k == "dependencies" || k == "optionalDependencies" || (section == "packages" && k == "peerDependenciesMeta")) {
					curEntrySubSection = k
				} else {
					curEntrySubSection = ""
				}
				continue
			}
			if curEntrySubSection == "peerDependenciesMeta" && section == "packages" {
				if indent == 6 {
					k, _, ok := splitYAMLMapLine(trimmed)
					if ok {
						curPeerMetaPkg = extractPnpmKeyPkg(k)
					} else {
						curPeerMetaPkg = ""
					}
					continue
				}
				if indent >= 8 && curPeerMetaPkg != "" && (trimmed == "optional: true" || trimmed == "optional:true") {
					if optionalPeerByBasePkg[curEntryBaseKey] == nil {
						optionalPeerByBasePkg[curEntryBaseKey] = make(map[string]bool)
					}
					optionalPeerByBasePkg[curEntryBaseKey][curPeerMetaPkg] = true
				}
				continue
			}
			if indent == 6 && (curEntrySubSection == "dependencies" || curEntrySubSection == "optionalDependencies") && !curIsDev {
				k, v, ok := splitYAMLMapLine(trimmed)
				if !ok {
					continue
				}
				depPkg := extractPnpmKeyPkg(k)
				if depPkg == "" {
					continue
				}
				edge := pnpmEdge{
					ref:           resolvePnpmTarget(depPkg, v),
					isOptional:    curEntrySubSection == "optionalDependencies",
					sourceBaseKey: curEntryBaseKey,
				}
				if section == "snapshots" {
					snapEdgesByKey[curEntryKey] = append(snapEdgesByKey[curEntryKey], edge)
					snapEdgesByPkg[curEntryPkg] = append(snapEdgesByPkg[curEntryPkg], edge)
				} else {
					pkgEdgesByKey[curEntryKey] = append(pkgEdgesByKey[curEntryKey], edge)
					pkgEdgesByPkg[curEntryPkg] = append(pkgEdgesByPkg[curEntryPkg], edge)
				}
			}
		}
	}
	resetSection()

	if hasImportersSection {
		if len(importerRoots) == 0 {
			return nil
		}
		edgesByKey := pkgEdgesByKey
		edgesByPkg := pkgEdgesByPkg
		knownKey := knownPkgKey
		if hasSnapshotsSection {
			edgesByKey = snapEdgesByKey
			edgesByPkg = snapEdgesByPkg
			knownKey = knownSnapKey
		}

		queue := append([]pnpmNodeRef(nil), importerRoots...)
		visitedNodes := make(map[string]bool)
		discoveredPkgs := make(map[string]bool)

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			vk := cur.pkg + "|" + cur.exactKey
			if visitedNodes[vk] {
				continue
			}
			visitedNodes[vk] = true
			if cur.pkg != "" {
				discoveredPkgs[cur.pkg] = true
			}
			var nextEdges []pnpmEdge
			if cur.exactKey != "" && knownKey[cur.exactKey] {
				nextEdges = edgesByKey[cur.exactKey]
			} else {
				nextEdges = edgesByPkg[cur.pkg]
			}
			curBase := stripPnpmPeers(cur.exactKey)
			for _, edge := range nextEdges {
				if isLockfileTestRunnerPkg(edge.ref.pkg) {
					continue
				}
				if edge.isOptional {
					if peers := optionalPeerByBasePkg[edge.sourceBaseKey]; peers != nil && peers[edge.ref.pkg] {
						continue
					}
					if peers := optionalPeerByBasePkg[curBase]; peers != nil && peers[edge.ref.pkg] {
						continue
					}
				}
				nvk := edge.ref.pkg + "|" + edge.ref.exactKey
				if !visitedNodes[nvk] {
					queue = append(queue, edge.ref)
				}
			}
		}

		var out []ManifestDep
		for pkg := range discoveredPkgs {
			out = append(out, ManifestDep{Name: pkg, Scope: "transitive_lockfile", Format: "node"})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}

	var out []ManifestDep
	for _, pkg := range legacyEntries {
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
				if !visited[nxt] && !isLockfileTestRunnerPkg(nxt) {
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
				if !visited[nxt] && !isLockfileTestRunnerPkg(nxt) {
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
