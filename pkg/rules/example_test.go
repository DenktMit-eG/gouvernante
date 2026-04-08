package rules_test

import (
	"fmt"

	"gouvernante/pkg/rules"
)

func ExampleVersionSet_Matches() {
	vs := &rules.VersionSet{
		Versions: map[string]bool{
			"1.7.8": true,
			"1.7.9": true,
		},
	}

	fmt.Println(vs.Matches("1.7.8"))
	fmt.Println(vs.Matches("1.7.9"))
	fmt.Println(vs.Matches("1.8.0"))

	// Output:
	// true
	// true
	// false
}

func ExampleVersionSet_Matches_wildcard() {
	vs := &rules.VersionSet{
		AnyVersion: true,
	}

	fmt.Println(vs.Matches("0.0.1"))
	fmt.Println(vs.Matches("99.0.0"))

	// Output:
	// true
	// true
}

func ExampleBuildPackageIndex() {
	ruleList := []rules.Rule{
		{
			ID:       "SSC-2025-001",
			Title:    "Axios compromise",
			Severity: "critical",
			PackageRules: []rules.PackageRule{
				{
					PackageName:      "axios",
					AffectedVersions: []string{"=1.7.8", "=1.7.9"},
				},
			},
			DropperPackages: []rules.DropperPkg{
				{PackageName: "plain-crypto-js"},
			},
		},
	}

	idx := rules.BuildPackageIndex(ruleList)

	fmt.Println("axios 1.7.8:", idx.Packages["axios"][0].Matches("1.7.8"))
	fmt.Println("axios 1.8.0:", idx.Packages["axios"][0].Matches("1.8.0"))
	fmt.Println("dropper any:", idx.Packages["plain-crypto-js"][0].AnyVersion)

	// Output:
	// axios 1.7.8: true
	// axios 1.8.0: false
	// dropper any: true
}
