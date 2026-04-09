// Package heuristic provides pattern-based malware detection for JavaScript
// and shell files inside node_modules directories. Unlike the rule-based
// scanner, heuristic scanning does not require rule files — it matches
// high-confidence code patterns that indicate supply chain compromise.
package heuristic

import "regexp"

// maxFileSize is the largest file (in bytes) the scanner will read.
// Legitimate malware payloads are small; large files are bundled libraries.
const maxFileSize = 512 * 1024

// maxFilesPerPackage caps the number of files scanned in a single package
// to bound scan time on very large packages.
const maxFilesPerPackage = 50

// severityHigh is the severity assigned to all heuristic findings.
const severityHigh = "high"

// scannableSubdirs lists subdirectories scanned one level deep inside each package.
var scannableSubdirs = []string{"lib", "src", "bin", "dist"}

// Pattern describes a single heuristic signal with a compiled regex.
type Pattern struct {
	// ID is a stable identifier for the pattern (e.g., "HEUR-EVAL-DECODE").
	ID string
	// Title is a short human-readable description of what the pattern detects.
	Title string
	// Extensions lists the file extensions this pattern applies to.
	Extensions []string
	// Regex is the compiled regular expression used for matching.
	Regex *regexp.Regexp
}

// lifecycleHooks lists the package.json script keys checked for suspicious commands.
var lifecycleHooks = []string{"preinstall", "postinstall", "preuninstall"}

// secretEnvVars lists environment variable names whose presence indicates
// credential harvesting when multiple appear in the same file alongside
// network calls.
var secretEnvVars = []*regexp.Regexp{
	regexp.MustCompile(`process\.env\.NPM_TOKEN`),
	regexp.MustCompile(`process\.env\.NPM_AUTH`),
	regexp.MustCompile(`process\.env\.AWS_SECRET_ACCESS_KEY`),
	regexp.MustCompile(`process\.env\.AWS_ACCESS_KEY_ID`),
	regexp.MustCompile(`process\.env\.GITHUB_TOKEN`),
	regexp.MustCompile(`process\.env\.GH_TOKEN`),
	regexp.MustCompile(`process\.env\.GITLAB_TOKEN`),
	regexp.MustCompile(`process\.env\.DOCKER_AUTH`),
	regexp.MustCompile(`process\.env\.REGISTRY_TOKEN`),
}

// envHarvestThreshold is the minimum number of distinct secret env vars
// that must appear in a single file (alongside a network call) to trigger
// the HEUR-ENV-HARVEST pattern.
const envHarvestThreshold = 3

// networkCallPattern matches common network call idioms in JavaScript.
var networkCallPattern = regexp.MustCompile(`https?://|fetch\s*\(|\.post\s*\(|\.get\s*\(|require\s*\(\s*['"]https?['"]`)

// hexExecThreshold is the minimum length of a hex literal (in characters)
// required for the HEUR-HEX-EXEC pattern.
const hexExecThreshold = 100

// hexLiteralPattern matches long contiguous hex strings.
var hexLiteralPattern = regexp.MustCompile(`[0-9a-f]{100,}`)

// execNearHexPattern matches execution functions that appear near hex literals.
var execNearHexPattern = regexp.MustCompile(`(?:eval|Function|exec)\s*\(`)

// jsExtensions are the JavaScript file extensions scanned by most patterns.
var jsExtensions = []string{".js", ".cjs", ".mjs"}

// jsAndShellExtensions includes shell scripts alongside JavaScript files.
var jsAndShellExtensions = []string{".js", ".cjs", ".mjs", ".sh"}

// Patterns is the list of all heuristic patterns applied during scanning.
var Patterns = []Pattern{
	{
		ID:         "HEUR-EVAL-DECODE",
		Title:      "Decoded payload execution",
		Extensions: jsExtensions,
		Regex:      regexp.MustCompile(`(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(`),
	},
	{
		ID:         "HEUR-PIPE-SHELL",
		Title:      "Download and execute via pipe",
		Extensions: jsAndShellExtensions,
		Regex:      regexp.MustCompile(`(?:curl|wget)\s[^\n]*\|\s*(?:sh|bash|node|zsh)`),
	},
}

// lifecycleExecPattern matches suspicious commands inside package.json
// lifecycle scripts (preinstall, postinstall, preuninstall).
var lifecycleExecPattern = regexp.MustCompile(`node\s+-e\s|curl\s|wget\s|eval\s`)

// benignPostinstallPattern matches the common "try{require('./postinstall')}catch"
// idiom used by legitimate packages (core-js, es5-ext, msw) for donation messages.
var benignPostinstallPattern = regexp.MustCompile(`^\s*node\s+-e\s+"try\{require\(`)

// hexExecProximity is the maximum byte distance between a hex literal and an
// execution function for the HEUR-HEX-EXEC pattern to fire.
const hexExecProximity = 500
