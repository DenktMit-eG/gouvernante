package rules_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"gouvernante/pkg/rules"
)

// fixtureExpectation pairs a fixture JSON file path with the exact Go struct
// that the JSON must deserialize to, and that when serialized must reproduce
// the same JSON.
type fixtureExpectation struct {
	name     string
	path     string
	expected rules.RuleSet
}

func allFixtures() []fixtureExpectation {
	return []fixtureExpectation{
		fixtureMinimalRequiredOnly(),
		fixtureAllKindValues(),
		fixtureAllAliasTypes(),
		fixtureAllReferenceTypes(),
		fixtureHostIndicatorFileWithPath(),
		fixtureHostIndicatorFileWithFilename(),
		fixtureHostIndicatorFileWithBoth(),
		fixtureHostIndicatorNonFileTypes(),
		fixtureHostIndicatorFileWithHashes(),
		fixtureHostIndicatorFileMultipleHashVariants(),
		fixtureAllConfidenceLevels(),
		fixtureLockfileEcosystems(),
		fixtureDropperPackages(),
		fixtureRemediationAndMetadata(),
		fixtureMultipleRulesOneFile(),
		fixtureOSCombinations(),
		fixtureEmptyOptionalArrays(),
		fixtureFullMaximized(),
	}
}

// Fixture definitions.

func fixtureMinimalRequiredOnly() fixtureExpectation {
	return fixtureExpectation{
		name: "minimal_required_only",
		path: "../../testdata/rules/valid/minimal_required_only.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-001", Title: "Minimal rule with only required fields",
					Kind: "vulnerability", Ecosystem: "npm", Severity: "low",
					PackageRules: []rules.PackageRule{
						{PackageName: "some-pkg", AffectedVersions: []string{"1.0.0"}},
					},
				},
			},
		},
	}
}

func fixtureAllKindValues() fixtureExpectation {
	return fixtureExpectation{
		name: "all_kind_values",
		path: "../../testdata/rules/valid/all_kind_values.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-KIND-01", Title: "Kind: compromised-release", Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "a", AffectedVersions: []string{"1.0.0"}}},
				},
				{
					ID: "T-KIND-02", Title: "Kind: malicious-package", Kind: "malicious-package", Ecosystem: "npm", Severity: "high",
					PackageRules: []rules.PackageRule{{PackageName: "b", AffectedVersions: []string{"*"}}},
				},
				{
					ID: "T-KIND-03", Title: "Kind: vulnerability", Kind: "vulnerability", Ecosystem: "npm", Severity: "medium",
					PackageRules: []rules.PackageRule{{PackageName: "c", AffectedVersions: []string{"2.0.0"}}},
				},
				{
					ID: "T-KIND-04", Title: "Kind: dropper", Kind: "dropper", Ecosystem: "npm", Severity: "low",
					PackageRules: []rules.PackageRule{{PackageName: "d", AffectedVersions: []string{"0.1.0"}}},
				},
				{
					ID: "T-KIND-05", Title: "Kind: suspicious-artifact", Kind: "suspicious-artifact", Ecosystem: "npm", Severity: "medium",
					PackageRules: []rules.PackageRule{{PackageName: "e", AffectedVersions: []string{"3.0.0"}}},
				},
			},
		},
	}
}

func fixtureAllAliasTypes() fixtureExpectation {
	return fixtureExpectation{
		name: "all_alias_types",
		path: "../../testdata/rules/valid/all_alias_types.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-ALIAS-01", Title: "All alias types", Kind: "vulnerability", Ecosystem: "npm", Severity: "high",
					Aliases: []rules.Alias{
						{Type: "cve", Value: "CVE-2025-99999"},
						{Type: "ghsa", Value: "GHSA-xxxx-yyyy-zzzz"},
						{Type: "snyk", Value: "SNYK-JS-PKG-12345"},
						{Type: "article", Value: "Aikido blog post"},
						{Type: "internal", Value: "INC-2025-042"},
						{Type: "other", Value: "Vendor advisory ref"},
					},
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
				},
			},
		},
	}
}

func fixtureAllReferenceTypes() fixtureExpectation {
	return fixtureExpectation{
		name: "all_reference_types",
		path: "../../testdata/rules/valid/all_reference_types.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-REF-01", Title: "All reference types", Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					References: []rules.Reference{
						{Type: "advisory", URL: "https://example.com/advisory"},
						{Type: "article", URL: "https://example.com/blog"},
						{Type: "vendor", URL: "https://example.com/vendor"},
						{Type: "repository", URL: "https://github.com/org/repo"},
						{Type: "other", URL: "https://example.com/other"},
					},
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
				},
			},
		},
	}
}

func fixtureHostIndicatorFileWithPath() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_file_with_path",
		path: "../../testdata/rules/valid/host_indicator_file_with_path.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-FILE-PATH", Title: "File indicator with path only (no file_name)",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "file", Path: "/tmp/malware.bin", OSes: []string{"linux"}},
					},
				},
			},
		},
	}
}

func fixtureHostIndicatorFileWithFilename() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_file_with_filename",
		path: "../../testdata/rules/valid/host_indicator_file_with_filename.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-FILE-NAME", Title: "File indicator with file_name only (no path)",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "file", FileName: "malware.bin", OSes: []string{"macos"}},
					},
				},
			},
		},
	}
}

func fixtureHostIndicatorFileWithBoth() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_file_with_both",
		path: "../../testdata/rules/valid/host_indicator_file_with_both.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-FILE-BOTH", Title: "File indicator with both path and file_name",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "file", Path: "/tmp", FileName: "malware.bin", OSes: []string{"windows"}},
					},
				},
			},
		},
	}
}

func fixtureHostIndicatorNonFileTypes() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_non_file_types",
		path: "../../testdata/rules/valid/host_indicator_non_file_types.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-NONFILE", Title: "Non-file indicator types (no path/file_name required)",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "high",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "process", Value: "cryptominer", OSes: []string{"linux", "macos", "windows"}},
						{Type: "registry", Value: "HKLM\\Software\\Malware\\Key", OSes: []string{"windows"}},
						{Type: "network", Value: "evil.example.com:4444", OSes: []string{"linux", "macos"}},
						{Type: "environment", Value: "MALWARE_TOKEN", OSes: []string{"linux"}},
					},
				},
			},
		},
	}
}

func fixtureHostIndicatorFileWithHashes() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_file_with_hashes",
		path: "../../testdata/rules/valid/host_indicator_file_with_hashes.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-HASHES", Title: "File indicator with all hash algorithms",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{
							Type: "file", Path: "/tmp", FileName: "payload.bin", OSes: []string{"linux"},
							Hashes: []rules.FileHash{
								{Algorithm: "md5", Value: "d41d8cd98f00b204e9800998ecf8427e"},
								{Algorithm: "sha1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
								{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
								{Algorithm: "sha512", Value: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
							},
							Confidence: "high",
						},
					},
				},
			},
		},
	}
}

func fixtureHostIndicatorFileMultipleHashVariants() fixtureExpectation {
	return fixtureExpectation{
		name: "host_indicator_file_multiple_hash_variants",
		path: "../../testdata/rules/valid/host_indicator_file_multiple_hash_variants.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-HI-MULTI-HASH", Title: "File indicator with multiple sha256 variants (same algo, different builds)",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{
							Type: "file", Path: "/usr/local/bin", FileName: "rat", OSes: []string{"linux"},
							Hashes: []rules.FileHash{
								{Algorithm: "sha256", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
								{Algorithm: "sha256", Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
								{Algorithm: "sha256", Value: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
							},
						},
					},
				},
			},
		},
	}
}

func fixtureAllConfidenceLevels() fixtureExpectation {
	return fixtureExpectation{
		name: "all_confidence_levels",
		path: "../../testdata/rules/valid/all_confidence_levels.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-CONF", Title: "All confidence levels",
					Kind: "suspicious-artifact", Ecosystem: "npm", Severity: "medium",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "file", Path: "/tmp/low.bin", OSes: []string{"linux"}, Confidence: "low"},
						{Type: "file", Path: "/tmp/med.bin", OSes: []string{"linux"}, Confidence: "medium"},
						{Type: "file", Path: "/tmp/high.bin", OSes: []string{"linux"}, Confidence: "high"},
					},
				},
			},
		},
	}
}

func fixtureLockfileEcosystems() fixtureExpectation {
	return fixtureExpectation{
		name: "lockfile_ecosystems",
		path: "../../testdata/rules/valid/lockfile_ecosystems.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-ECO", Title: "All lockfile ecosystem values",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "high",
					PackageRules: []rules.PackageRule{
						{PackageName: "pkg-all", AffectedVersions: []string{"1.0.0"}, LockfileEcosystems: []string{"npm", "pnpm", "yarn", "bun"}},
						{PackageName: "pkg-npm-only", AffectedVersions: []string{"2.0.0"}, LockfileEcosystems: []string{"npm"}},
						{PackageName: "pkg-no-ecosystem", AffectedVersions: []string{"3.0.0"}},
					},
				},
			},
		},
	}
}

func fixtureDropperPackages() fixtureExpectation {
	return fixtureExpectation{
		name: "dropper_packages",
		path: "../../testdata/rules/valid/dropper_packages.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-DROPPER", Title: "Dropper packages with and without notes",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "main-pkg", AffectedVersions: []string{"1.0.0"}}},
					DropperPackages: []rules.DropperPkg{
						{PackageName: "dropper-with-notes", Notes: "Installed via postinstall script."},
						{PackageName: "dropper-no-notes"},
					},
				},
			},
		},
	}
}

func fixtureRemediationAndMetadata() fixtureExpectation {
	return fixtureExpectation{
		name: "remediation_and_metadata",
		path: "../../testdata/rules/valid/remediation_and_metadata.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-META", Title: "Remediation and metadata fully populated",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					Remediation: &rules.Remediation{
						Summary: "Upgrade to safe version.",
						Steps:   []string{"Pin to version 1.0.1.", "Regenerate lockfiles.", "Rotate credentials."},
					},
					Metadata: &rules.Metadata{
						PublishedAt:   "2025-09-15T00:00:00Z",
						LastUpdatedAt: "2025-09-16T12:30:00Z",
					},
				},
			},
		},
	}
}

func fixtureMultipleRulesOneFile() fixtureExpectation {
	return fixtureExpectation{
		name: "multiple_rules_one_file",
		path: "../../testdata/rules/valid/multiple_rules_one_file.json",
		expected: rules.RuleSet{
			SchemaVersion: "2.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-MULTI-01", Title: "First rule in a multi-rule file",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg-a", AffectedVersions: []string{"=1.0.0", "=1.0.1"}}},
				},
				{
					ID: "T-MULTI-02", Title: "Second rule with wildcard versions",
					Kind: "malicious-package", Ecosystem: "npm", Severity: "high",
					PackageRules: []rules.PackageRule{{PackageName: "pkg-b", AffectedVersions: []string{"*"}}},
				},
			},
		},
	}
}

func fixtureOSCombinations() fixtureExpectation {
	return fixtureExpectation{
		name: "os_combinations",
		path: "../../testdata/rules/valid/os_combinations.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-OS", Title: "Host indicators with different OS combinations",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					PackageRules: []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					HostIndicators: []rules.HostIndicator{
						{Type: "file", Path: "/tmp/linux-only", OSes: []string{"linux"}},
						{Type: "file", Path: "/Library/macos-only", OSes: []string{"macos"}},
						{Type: "file", Path: "%PROGRAMDATA%\\windows-only", OSes: []string{"windows"}},
						{Type: "file", Path: "/tmp/linux-and-macos", OSes: []string{"linux", "macos"}},
						{Type: "file", Path: "/tmp/all-platforms", OSes: []string{"linux", "macos", "windows"}},
					},
				},
			},
		},
	}
}

func fixtureEmptyOptionalArrays() fixtureExpectation {
	// JSON has explicit empty arrays ([], [], [], []) for optional fields.
	// Go's json.Unmarshal sets these to non-nil empty slices, which is
	// semantically equivalent to nil for our purposes. The parse test uses
	// DeepEqual which distinguishes nil vs empty, so we use empty slices
	// here to match the parsed result.
	//
	// However, json.Marshal with omitempty omits empty slices on output,
	// so the serialized JSON will not contain these keys. The serialize
	// test accounts for this by normalizing through the Go struct.
	return fixtureExpectation{
		name: "empty_optional_arrays",
		path: "../../testdata/rules/valid/empty_optional_arrays.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-EMPTY-ARRAYS", Title: "Explicit empty arrays for all optional array fields",
					Kind: "vulnerability", Ecosystem: "npm", Severity: "low",
					PackageRules:    []rules.PackageRule{{PackageName: "pkg", AffectedVersions: []string{"1.0.0"}}},
					Aliases:         []rules.Alias{},
					References:      []rules.Reference{},
					DropperPackages: []rules.DropperPkg{},
					HostIndicators:  []rules.HostIndicator{},
				},
			},
		},
	}
}

//nolint:funlen // intentionally exhaustive — maximal fixture covering every field
func fixtureFullMaximized() fixtureExpectation {
	return fixtureExpectation{
		name: "full_maximized",
		path: "../../testdata/rules/valid/full_maximized.json",
		expected: rules.RuleSet{
			SchemaVersion: "1.0.0",
			Rules: []rules.Rule{
				{
					ID: "T-FULL-01", Title: "Fully populated rule exercising every field and construct",
					Kind: "compromised-release", Ecosystem: "npm", Severity: "critical",
					Summary: "A comprehensive test rule that uses every optional field, all enum values for sub-objects, and all conditional paths.",
					Aliases: []rules.Alias{
						{Type: "cve", Value: "CVE-2025-00001"},
						{Type: "ghsa", Value: "GHSA-aaaa-bbbb-cccc"},
						{Type: "snyk", Value: "SNYK-JS-PKG-111111"},
						{Type: "article", Value: "Blog post by security researcher"},
						{Type: "internal", Value: "INC-2025-FULL"},
						{Type: "other", Value: "Vendor private disclosure"},
					},
					References: []rules.Reference{
						{Type: "advisory", URL: "https://example.com/advisory/1"},
						{Type: "article", URL: "https://example.com/blog/analysis"},
						{Type: "vendor", URL: "https://example.com/vendor/notice"},
						{Type: "repository", URL: "https://github.com/org/repo/issues/1"},
						{Type: "other", URL: "https://example.com/other-source"},
					},
					PackageRules: []rules.PackageRule{
						{PackageName: "compromised-pkg", AffectedVersions: []string{"=1.0.0", "=1.0.1", "=1.1.0"}, LockfileEcosystems: []string{"npm", "pnpm", "yarn", "bun"}, Notes: "All three versions contain obfuscated postinstall dropper."},
						{PackageName: "@scope/compromised-scoped", AffectedVersions: []string{"=2.0.0"}, LockfileEcosystems: []string{"npm", "pnpm"}},
						{PackageName: "wildcard-all-versions", AffectedVersions: []string{"*"}},
					},
					DropperPackages: []rules.DropperPkg{
						{PackageName: "crypto-helper-lib", Notes: "Payload delivery via postinstall."},
						{PackageName: "util-native-bridge"},
					},
					HostIndicators: []rules.HostIndicator{
						{
							Type: "file", Path: "/tmp", FileName: "ld.py", OSes: []string{"linux"},
							Hashes: []rules.FileHash{
								{Algorithm: "md5", Value: "d41d8cd98f00b204e9800998ecf8427e"},
								{Algorithm: "sha1", Value: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
								{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
								{Algorithm: "sha512", Value: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
							}, Confidence: "high", Notes: "Linux RAT payload.",
						},
						{Type: "file", Path: "/Library/Caches", FileName: "com.apple.act.mond", OSes: []string{"macos"}, Confidence: "high", Notes: "macOS RAT disguised as system daemon."},
						{
							Type: "file", Path: "%PROGRAMDATA%", FileName: "wt.exe", OSes: []string{"windows"},
							Hashes: []rules.FileHash{
								{Algorithm: "sha256", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
								{Algorithm: "sha256", Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
							}, Confidence: "medium",
						},
						{Type: "file", FileName: "suspicious.dat", OSes: []string{"linux", "macos", "windows"}, Confidence: "low", Notes: "File name only indicator \u2014 no fixed path."},
						{Type: "process", Value: "cryptominer-hidden", OSes: []string{"linux", "macos"}, Confidence: "medium", Notes: "Known mining process name."},
						{Type: "registry", Value: "HKLM\\Software\\MalwareKey", OSes: []string{"windows"}, Confidence: "high"},
						{Type: "network", Value: "c2.evil.example.com:8443", OSes: []string{"linux", "macos", "windows"}, Confidence: "high", Notes: "C2 callback domain."},
						{Type: "environment", Value: "MALWARE_EXFIL_TOKEN", OSes: []string{"linux"}, Confidence: "low"},
					},
					Remediation: &rules.Remediation{
						Summary: "Remove compromised versions, remove dropper packages, check for host artifacts, rotate all credentials.",
						Steps: []string{
							"Pin compromised-pkg to version >=1.2.0.",
							"Remove crypto-helper-lib and util-native-bridge from dependencies.",
							"Regenerate all lockfiles.",
							"Clear package manager caches.",
							"Run gouvernante with -host to check for filesystem IOCs.",
							"If host indicators found: isolate machine, rotate all credentials, follow IR procedure.",
						},
					},
					Metadata: &rules.Metadata{
						PublishedAt:   "2025-09-15T08:00:00Z",
						LastUpdatedAt: "2025-09-17T14:30:00Z",
					},
				},
			},
		},
	}
}

// Fidelity tests.

// TestFixtures_ParseMatchesExpectedStruct parses each fixture JSON and verifies
// every field matches the hand-written Go struct expectation.
func TestFixtures_ParseMatchesExpectedStruct(t *testing.T) {
	for _, fx := range allFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			rs, err := rules.LoadFile(fx.path)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}

			if !reflect.DeepEqual(*rs, fx.expected) {
				gotJSON, _ := json.MarshalIndent(rs, "", "  ")
				wantJSON, _ := json.MarshalIndent(fx.expected, "", "  ")
				t.Errorf("parsed struct does not match expected.\n--- got ---\n%s\n--- want ---\n%s",
					gotJSON, wantJSON)
			}
		})
	}
}

// TestFixtures_SerializeMatchesOriginalJSON verifies that the hand-written Go
// struct and the fixture JSON represent the same data. Both sides are normalized
// through the Go struct (parse → marshal) to account for omitempty behavior,
// which legitimately drops empty optional arrays on serialization.
func TestFixtures_SerializeMatchesOriginalJSON(t *testing.T) {
	for _, fx := range allFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			// Parse the fixture through the Go struct and re-marshal.
			// This normalizes omitempty behavior (empty arrays become absent).
			parsed, err := rules.LoadFile(fx.path)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}

			parsedBytes, err := json.Marshal(parsed)
			if err != nil {
				t.Fatalf("marshal parsed: %v", err)
			}

			// Marshal the expected Go struct.
			expectedBytes, err := json.Marshal(fx.expected)
			if err != nil {
				t.Fatalf("marshal expected: %v", err)
			}

			parsedCanonical := canonicalJSON(t, parsedBytes)
			expectedCanonical := canonicalJSON(t, expectedBytes)

			if !bytes.Equal(parsedCanonical, expectedCanonical) {
				parsedPretty, _ := json.MarshalIndent(json.RawMessage(parsedBytes), "", "  ")
				expectedPretty, _ := json.MarshalIndent(json.RawMessage(expectedBytes), "", "  ")
				t.Errorf("fixture→struct→JSON does not match expected→JSON.\n--- parsed ---\n%s\n--- expected ---\n%s",
					parsedPretty, expectedPretty)
			}
		})
	}
}

// TestFixtures_ExpectedStructsPassValidation ensures every hand-written expected
// struct passes Go-side Validate(). This proves the Go validation accepts
// everything the schema accepts.
func TestFixtures_ExpectedStructsPassValidation(t *testing.T) {
	for _, fx := range allFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			if err := fx.expected.Validate(); err != nil {
				t.Errorf("expected struct failed validation: %v", err)
			}
		})
	}
}

func canonicalJSON(t *testing.T, data []byte) []byte {
	t.Helper()

	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse JSON for canonicalization: %v", err)
	}

	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-marshal JSON: %v", err)
	}

	return out
}
