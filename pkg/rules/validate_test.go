package rules

import (
	"errors"
	"strings"
	"testing"
)

// validMinimalRuleSet returns a minimal valid RuleSet for mutation testing.
func validMinimalRuleSet() *RuleSet {
	return &RuleSet{
		SchemaVersion: "1.0.0",
		Rules: []Rule{
			{
				ID: "V-001", Title: "Valid", Kind: "vulnerability",
				Ecosystem: "npm", Severity: "low",
				PackageRules: []PackageRule{
					{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}},
				},
			},
		},
	}
}

func TestValidate_MinimalValid(t *testing.T) {
	rs := validMinimalRuleSet()
	if err := rs.Validate(); err != nil {
		t.Errorf("expected valid, got: %v", err)
	}
}

func TestValidate_MissingSchemaVersion(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.SchemaVersion = ""
	assertValidationContains(t, rs, "schema_version: required")
}

func TestValidate_InvalidSchemaVersionFormat(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.SchemaVersion = "v1.0"
	assertValidationContains(t, rs, "schema_version: must match pattern")
}

func TestValidate_EmptyRules(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules = nil
	assertValidationContains(t, rs, "rules: must contain at least 1 item")
}

func TestValidate_MissingRuleID(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].ID = ""
	assertValidationContains(t, rs, "rules[0].id: required")
}

func TestValidate_MissingTitle(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Title = ""
	assertValidationContains(t, rs, "rules[0].title: required")
}

func TestValidate_InvalidKind(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Kind = "bad-kind"
	assertValidationContains(t, rs, "rules[0].kind: must be one of")
}

func TestValidate_InvalidEcosystem(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Ecosystem = "pypi"
	assertValidationContains(t, rs, "rules[0].ecosystem: must be one of")
}

func TestValidate_InvalidSeverity(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Severity = "extreme"
	assertValidationContains(t, rs, "rules[0].severity: must be one of")
}

func TestValidate_EmptyPackageRules(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].PackageRules = nil
	assertValidationContains(t, rs, "rules[0].package_rules: must contain at least 1 item")
}

func TestValidate_EmptyPackageName(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].PackageRules[0].PackageName = ""
	assertValidationContains(t, rs, "package_name: required")
}

func TestValidate_EmptyAffectedVersions(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].PackageRules[0].AffectedVersions = nil
	assertValidationContains(t, rs, "affected_versions: must contain at least 1 item")
}

func TestValidate_EmptyVersionString(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].PackageRules[0].AffectedVersions = []string{"1.0.0", ""}
	assertValidationContains(t, rs, "affected_versions[1]: must not be empty")
}

func TestValidate_InvalidLockfileEcosystem(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].PackageRules[0].LockfileEcosystems = []string{"npm", "invalid"}
	assertValidationContains(t, rs, "lockfile_ecosystems[1]: must be one of")
}

func TestValidate_InvalidAliasType(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Aliases = []Alias{{Type: "bad", Value: "v"}}
	assertValidationContains(t, rs, "aliases[0].type: must be one of")
}

func TestValidate_EmptyAliasValue(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].Aliases = []Alias{{Type: "cve", Value: ""}}
	assertValidationContains(t, rs, "aliases[0].value: required")
}

func TestValidate_InvalidReferenceType(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].References = []Reference{{Type: "bad", URL: "https://x.com"}}
	assertValidationContains(t, rs, "references[0].type: must be one of")
}

func TestValidate_EmptyReferenceURL(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].References = []Reference{{Type: "advisory", URL: ""}}
	assertValidationContains(t, rs, "references[0].url: required")
}

func TestValidate_EmptyDropperPackageName(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].DropperPackages = []DropperPkg{{PackageName: ""}}
	assertValidationContains(t, rs, "dropper_packages[0].package_name: required")
}

func TestValidate_InvalidIndicatorType(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{{Type: "bad", OSes: []string{"linux"}}}
	assertValidationContains(t, rs, "host_indicators[0].type: must be one of")
}

func TestValidate_EmptyOSes(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{{Type: "file", Path: "/tmp", OSes: nil}}
	assertValidationContains(t, rs, "host_indicators[0].oses: must contain at least 1 item")
}

func TestValidate_InvalidOS(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{{Type: "file", Path: "/tmp", OSes: []string{"freebsd"}}}
	assertValidationContains(t, rs, "oses[0]: must be one of")
}

func TestValidate_InvalidConfidence(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{{Type: "file", Path: "/tmp", OSes: []string{"linux"}, Confidence: "absolute"}}
	assertValidationContains(t, rs, "confidence: must be one of")
}

// allOf/if-then conditional logic tests.

func TestValidate_FileIndicatorMissingPathAndFilename(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "file", OSes: []string{"linux"}},
	}
	assertValidationContains(t, rs, "file indicator must have at least one of path or file_name")
}

func TestValidate_FileIndicatorWithPathOnly(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "file", Path: "/tmp/x", OSes: []string{"linux"}},
	}

	if err := rs.Validate(); err != nil {
		t.Errorf("file with path-only should be valid: %v", err)
	}
}

func TestValidate_FileIndicatorWithFilenameOnly(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "file", FileName: "x.bin", OSes: []string{"linux"}},
	}

	if err := rs.Validate(); err != nil {
		t.Errorf("file with filename-only should be valid: %v", err)
	}
}

func TestValidate_HashesOnNonFileIndicator(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "process", Value: "x", OSes: []string{"linux"}, Hashes: []FileHash{{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}},
	}
	assertValidationContains(t, rs, "hashes are only allowed on file indicators")
}

func TestValidate_HashesOnFileIndicator(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "file", Path: "/tmp", OSes: []string{"linux"}, Hashes: []FileHash{{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}},
	}

	if err := rs.Validate(); err != nil {
		t.Errorf("hashes on file should be valid: %v", err)
	}
}

// Hash length validation.

func TestValidate_MD5CorrectLength(t *testing.T) {
	rs := ruleSetWithHash("md5", strings.Repeat("a", 32))
	if err := rs.Validate(); err != nil {
		t.Errorf("valid md5: %v", err)
	}
}

func TestValidate_MD5WrongLength(t *testing.T) {
	rs := ruleSetWithHash("md5", strings.Repeat("a", 16))
	assertValidationContains(t, rs, "md5 hash must be 32 hex chars, got 16")
}

func TestValidate_SHA1CorrectLength(t *testing.T) {
	rs := ruleSetWithHash("sha1", strings.Repeat("b", 40))
	if err := rs.Validate(); err != nil {
		t.Errorf("valid sha1: %v", err)
	}
}

func TestValidate_SHA1WrongLength(t *testing.T) {
	rs := ruleSetWithHash("sha1", strings.Repeat("b", 20))
	assertValidationContains(t, rs, "sha1 hash must be 40 hex chars, got 20")
}

func TestValidate_SHA256CorrectLength(t *testing.T) {
	rs := ruleSetWithHash("sha256", strings.Repeat("c", 64))
	if err := rs.Validate(); err != nil {
		t.Errorf("valid sha256: %v", err)
	}
}

func TestValidate_SHA256WrongLength(t *testing.T) {
	rs := ruleSetWithHash("sha256", strings.Repeat("c", 32))
	assertValidationContains(t, rs, "sha256 hash must be 64 hex chars, got 32")
}

func TestValidate_SHA512CorrectLength(t *testing.T) {
	rs := ruleSetWithHash("sha512", strings.Repeat("d", 128))
	if err := rs.Validate(); err != nil {
		t.Errorf("valid sha512: %v", err)
	}
}

func TestValidate_SHA512WrongLength(t *testing.T) {
	rs := ruleSetWithHash("sha512", strings.Repeat("d", 64))
	assertValidationContains(t, rs, "sha512 hash must be 128 hex chars, got 64")
}

func TestValidate_InvalidHashAlgorithm(t *testing.T) {
	rs := ruleSetWithHash("sha384", strings.Repeat("e", 96))
	assertValidationContains(t, rs, "algorithm: must be one of")
}

func TestValidate_NonHexHashValue(t *testing.T) {
	rs := ruleSetWithHash("sha256", strings.Repeat("Z", 64))
	assertValidationContains(t, rs, "value: must be hexadecimal")
}

// Multiple errors collected.

func TestValidate_CollectsMultipleErrors(t *testing.T) {
	rs := &RuleSet{} // empty — multiple things wrong
	err := rs.Validate()

	if err == nil {
		t.Fatal("expected validation error")
	}

	var ve *ValidationError
	ok := errors.As(err, &ve)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if len(ve.Errors) < 2 {
		t.Errorf("expected multiple errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

// Non-file indicators don't need path/file_name.

func TestValidate_ProcessIndicatorWithoutPath(t *testing.T) {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{Type: "process", Value: "miner", OSes: []string{"linux"}},
	}

	if err := rs.Validate(); err != nil {
		t.Errorf("process without path should be valid: %v", err)
	}
}

func TestValidate_AllValidKinds(t *testing.T) {
	kinds := []string{"compromised-release", "malicious-package", "vulnerability", "dropper", "suspicious-artifact"}
	for _, kind := range kinds {
		rs := validMinimalRuleSet()
		rs.Rules[0].Kind = kind

		if err := rs.Validate(); err != nil {
			t.Errorf("kind %q should be valid: %v", kind, err)
		}
	}
}

func TestValidate_AllValidSeverities(t *testing.T) {
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		rs := validMinimalRuleSet()
		rs.Rules[0].Severity = sev

		if err := rs.Validate(); err != nil {
			t.Errorf("severity %q should be valid: %v", sev, err)
		}
	}
}

// Helpers.

func ruleSetWithHash(algo, value string) *RuleSet {
	rs := validMinimalRuleSet()
	rs.Rules[0].HostIndicators = []HostIndicator{
		{
			Type: "file", Path: "/tmp", OSes: []string{"linux"},
			Hashes: []FileHash{{Algorithm: algo, Value: value}},
		},
	}

	return rs
}

// requireEnum with empty value.

func TestRequireEnum_EmptyValue(t *testing.T) {
	ve := &ValidationError{}
	requireEnum(ve, "test.field", "", validKinds)

	if !ve.hasErrors() {
		t.Fatal("expected error for empty value in requireEnum")
	}

	found := false
	for _, e := range ve.Errors {
		if strings.Contains(e, "required, must not be empty") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'required, must not be empty' error, got: %v", ve.Errors)
	}
}

func assertValidationContains(t *testing.T, rs *RuleSet, substr string) {
	t.Helper()

	err := rs.Validate()
	if err == nil {
		t.Fatalf("expected validation error containing %q, got nil", substr)
	}

	if !strings.Contains(err.Error(), substr) {
		t.Errorf("expected error containing %q, got:\n%s", substr, err.Error())
	}
}
