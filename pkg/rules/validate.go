package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Allowed enum values, mirroring the JSON Schema definitions.
var (
	validKinds = map[string]bool{
		"compromised-release": true,
		"malicious-package":   true,
		"vulnerability":       true,
		"dropper":             true,
		"suspicious-artifact": true,
	}

	validSeverities = map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}

	validEcosystems = map[string]bool{
		"npm": true,
	}

	validAliasTypes = map[string]bool{
		"cve": true, "ghsa": true, "snyk": true,
		"article": true, "internal": true, "other": true,
	}

	validReferenceTypes = map[string]bool{
		"advisory": true, "article": true, "vendor": true,
		"repository": true, "other": true,
	}

	validIndicatorTypes = map[string]bool{
		"file": true, "process": true, "registry": true,
		"network": true, "environment": true,
	}

	validOSes = map[string]bool{
		"linux": true, "macos": true, "windows": true,
	}

	validConfidenceLevels = map[string]bool{
		"low": true, "medium": true, "high": true,
	}

	validLockfileEcosystems = map[string]bool{
		"npm": true, "pnpm": true, "yarn": true, "bun": true,
	}

	validHashAlgorithms = map[string]int{
		"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128,
	}

	hexPattern           = regexp.MustCompile(`^[A-Fa-f0-9]+$`)
	schemaVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// ValidationError collects all validation failures.
type ValidationError struct {
	Errors []string
}

// Error formats all collected validation failures into a single multi-line string.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed with %d errors:\n  - %s",
		len(e.Errors), strings.Join(e.Errors, "\n  - "))
}

// add appends a formatted validation error message to the list.
func (e *ValidationError) add(format string, args ...interface{}) {
	e.Errors = append(e.Errors, fmt.Sprintf(format, args...))
}

// hasErrors reports whether any validation errors have been collected.
func (e *ValidationError) hasErrors() bool {
	return len(e.Errors) > 0
}

// Validate checks that a RuleSet satisfies all constraints defined in the
// JSON Schema. Call this before serializing programmatically constructed
// rules to guarantee the output will be schema-valid.
func (rs *RuleSet) Validate() error {
	ve := &ValidationError{}

	if rs.SchemaVersion == "" {
		ve.add("schema_version: required")
	} else if !schemaVersionPattern.MatchString(rs.SchemaVersion) {
		ve.add("schema_version: must match pattern N.N.N, got %q", rs.SchemaVersion)
	}

	if len(rs.Rules) == 0 {
		ve.add("rules: must contain at least 1 item")
	}

	for i := range rs.Rules {
		rs.Rules[i].validate(ve, fmt.Sprintf("rules[%d]", i))
	}

	if ve.hasErrors() {
		return ve
	}

	return nil
}

// validate checks all required fields and enum constraints on a single Rule.
func (r *Rule) validate(ve *ValidationError, path string) {
	requireNonEmpty(ve, path+".id", r.ID)
	requireNonEmpty(ve, path+".title", r.Title)
	requireEnum(ve, path+".kind", r.Kind, validKinds)
	requireEnum(ve, path+".ecosystem", r.Ecosystem, validEcosystems)
	requireEnum(ve, path+".severity", r.Severity, validSeverities)

	if len(r.PackageRules) == 0 {
		ve.add("%s.package_rules: must contain at least 1 item", path)
	}

	for i := range r.Aliases {
		r.Aliases[i].validate(ve, fmt.Sprintf("%s.aliases[%d]", path, i))
	}

	for i := range r.References {
		r.References[i].validate(ve, fmt.Sprintf("%s.references[%d]", path, i))
	}

	for i := range r.PackageRules {
		r.PackageRules[i].validate(ve, fmt.Sprintf("%s.package_rules[%d]", path, i))
	}

	for i := range r.DropperPackages {
		r.DropperPackages[i].validate(ve, fmt.Sprintf("%s.dropper_packages[%d]", path, i))
	}

	for i := range r.HostIndicators {
		r.HostIndicators[i].validate(ve, fmt.Sprintf("%s.host_indicators[%d]", path, i))
	}
}

// validate checks that type is a known alias type and value is non-empty.
func (a *Alias) validate(ve *ValidationError, path string) {
	requireEnum(ve, path+".type", a.Type, validAliasTypes)
	requireNonEmpty(ve, path+".value", a.Value)
}

// validate checks that type is a known reference type and url is non-empty.
func (r *Reference) validate(ve *ValidationError, path string) {
	requireEnum(ve, path+".type", r.Type, validReferenceTypes)
	requireNonEmpty(ve, path+".url", r.URL)
}

// validate checks that package_name and affected_versions are present,
// and that lockfile_ecosystems values are from the allowed set.
func (pr *PackageRule) validate(ve *ValidationError, path string) {
	requireNonEmpty(ve, path+".package_name", pr.PackageName)

	if len(pr.AffectedVersions) == 0 {
		ve.add("%s.affected_versions: must contain at least 1 item", path)
	}

	for i, v := range pr.AffectedVersions {
		if v == "" {
			ve.add("%s.affected_versions[%d]: must not be empty", path, i)
		}
	}

	for i, eco := range pr.LockfileEcosystems {
		requireEnum(ve, fmt.Sprintf("%s.lockfile_ecosystems[%d]", path, i), eco, validLockfileEcosystems)
	}
}

// validate checks that package_name is non-empty.
func (dp *DropperPkg) validate(ve *ValidationError, path string) {
	requireNonEmpty(ve, path+".package_name", dp.PackageName)
}

// validate checks indicator type, OS values, confidence, and enforces allOf
// conditions: file indicators require path or file_name; hashes require type=file.
func (hi *HostIndicator) validate(ve *ValidationError, path string) {
	requireEnum(ve, path+".type", hi.Type, validIndicatorTypes)

	if len(hi.OSes) == 0 {
		ve.add("%s.oses: must contain at least 1 item", path)
	}

	for i, os := range hi.OSes {
		requireEnum(ve, fmt.Sprintf("%s.oses[%d]", path, i), os, validOSes)
	}

	if hi.Confidence != "" {
		requireEnum(ve, path+".confidence", hi.Confidence, validConfidenceLevels)
	}

	// allOf condition 1: if type=file, then path or file_name is required.
	if hi.Type == "file" && hi.Path == "" && hi.FileName == "" {
		ve.add("%s: file indicator must have at least one of path or file_name", path)
	}

	// allOf condition 2: if hashes present, type must be file.
	if len(hi.Hashes) > 0 && hi.Type != "file" {
		ve.add("%s: hashes are only allowed on file indicators, got type=%q", path, hi.Type)
	}

	for i := range hi.Hashes {
		hi.Hashes[i].validate(ve, fmt.Sprintf("%s.hashes[%d]", path, i))
	}
}

// validate checks that algorithm is known (md5/sha1/sha256/sha512),
// the value is hexadecimal, and its length matches the algorithm.
func (fh *FileHash) validate(ve *ValidationError, path string) {
	expectedLen, ok := validHashAlgorithms[fh.Algorithm]
	if !ok {
		ve.add("%s.algorithm: must be one of md5, sha1, sha256, sha512, got %q", path, fh.Algorithm)
		return
	}

	if !hexPattern.MatchString(fh.Value) {
		ve.add("%s.value: must be hexadecimal, got %q", path, fh.Value)
		return
	}

	// allOf conditions: hash length must match algorithm.
	if len(fh.Value) != expectedLen {
		ve.add("%s: %s hash must be %d hex chars, got %d", path, fh.Algorithm, expectedLen, len(fh.Value))
	}
}

// requireNonEmpty adds a validation error if value is empty.
func requireNonEmpty(ve *ValidationError, path, value string) {
	if value == "" {
		ve.add("%s: required, must not be empty", path)
	}
}

// requireEnum adds a validation error if value is empty or not in the allowed set.
func requireEnum(ve *ValidationError, path, value string, allowed map[string]bool) {
	if value == "" {
		ve.add("%s: required, must not be empty", path)
		return
	}

	if !allowed[value] {
		keys := make([]string, 0, len(allowed))
		for k := range allowed {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		ve.add("%s: must be one of [%s], got %q", path, strings.Join(keys, ", "), value)
	}
}
