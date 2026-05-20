package rules

// Package ecosystem identifiers used in lockfile_ecosystems filtering and
// the rule schema. Keep in sync with the JSON Schema enum.
const (
	ecosystemNpm  = "npm"
	ecosystemPnpm = "pnpm"
	ecosystemYarn = "yarn"
	ecosystemBun  = "bun"
)

// Operating system identifiers used in host_indicators[].oses.
// Keep in sync with the JSON Schema enum.
const (
	osLinux   = "linux"
	osMacOS   = "macos"
	osWindows = "windows"
)

// Hash algorithm identifiers used in host_indicators[].hashes[].algorithm.
const (
	hashMD5    = "md5"
	hashSHA1   = "sha1"
	hashSHA256 = "sha256"
	hashSHA512 = "sha512"
)

// Rule kinds used in rules[].kind.
const (
	kindCompromisedRelease = "compromised-release"
	kindMaliciousPackage   = "malicious-package"
	kindVulnerability      = "vulnerability"
	kindDropper            = "dropper"
	kindSuspiciousArtifact = "suspicious-artifact"
)

// Severity levels used in rules[].severity.
const (
	severityLow      = "low"
	severityMedium   = "medium"
	severityHigh     = "high"
	severityCritical = "critical"
)

// Host indicator types used in host_indicators[].type.
const (
	indicatorFile        = "file"
	indicatorProcess     = "process"
	indicatorRegistry    = "registry"
	indicatorNetwork     = "network"
	indicatorEnvironment = "environment"
)
