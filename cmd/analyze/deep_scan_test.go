//go:build darwin

package main

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestIsDeepSystemPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/private", true},
		{"/private/var/folders", true},
		{"/private/var/folders/zz/abc/T/com.apple.idleassetsd", true},
		{"/private/var/vm", true},
		{"/private/../private/var", true}, // cleaned to /private/var
		{"", false},
		{"/Users/someone", false},
		{"/Applications", false},
		{"/Library", false},
		{"/privatex/y", false}, // must not match by raw prefix
		{"/var/folders/zz", false},
	}
	for _, c := range cases {
		if got := isDeepSystemPath(c.path); got != c.want {
			t.Errorf("isDeepSystemPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestDeepScanEnabledAndSudoGuards(t *testing.T) {
	// Disabled by default.
	t.Setenv("MO_ANALYZE_DEEP", "")
	t.Setenv("MOLE_TEST_NO_AUTH", "")
	t.Setenv("MOLE_TEST_MODE", "")
	if deepScanEnabled() {
		t.Fatal("deepScanEnabled() should be false when MO_ANALYZE_DEEP is unset")
	}
	if deepScanUsesSudo() {
		t.Fatal("deepScanUsesSudo() should be false when deep is disabled")
	}

	// Enabled, no test guard -> elevates.
	t.Setenv("MO_ANALYZE_DEEP", "1")
	if !deepScanEnabled() {
		t.Fatal("deepScanEnabled() should be true when MO_ANALYZE_DEEP=1")
	}
	if !deepScanUsesSudo() {
		t.Fatal("deepScanUsesSudo() should be true when deep is enabled and not under the test guard")
	}

	// Test no-auth guard must suppress sudo even when deep is enabled.
	t.Setenv("MOLE_TEST_NO_AUTH", "1")
	if deepScanUsesSudo() {
		t.Fatal("deepScanUsesSudo() must be false under MOLE_TEST_NO_AUTH=1")
	}

	// MOLE_TEST_MODE is the other project-wide auth guard and must suppress
	// sudo on its own, matching has_sudo_session() in lib/core/sudo.sh.
	t.Setenv("MOLE_TEST_NO_AUTH", "")
	t.Setenv("MOLE_TEST_MODE", "1")
	if deepScanUsesSudo() {
		t.Fatal("deepScanUsesSudo() must be false under MOLE_TEST_MODE=1")
	}
}

func TestDeepScanRequiresElevation(t *testing.T) {
	// Elevation is only required for system paths in an active deep scan;
	// everywhere else measureOverviewSize keeps its unprivileged fallbacks.
	t.Setenv("MO_ANALYZE_DEEP", "")
	t.Setenv("MOLE_TEST_NO_AUTH", "")
	t.Setenv("MOLE_TEST_MODE", "")
	if deepScanRequiresElevation("/private/var/folders") {
		t.Fatal("non-deep system path must not require elevation")
	}

	t.Setenv("MO_ANALYZE_DEEP", "1")
	if !deepScanRequiresElevation("/private/var/folders") {
		t.Fatal("deep system path must require elevation")
	}
	if deepScanRequiresElevation("/Users/someone") {
		t.Fatal("user path must never require elevation")
	}

	t.Setenv("MOLE_TEST_NO_AUTH", "1")
	if deepScanRequiresElevation("/private/var/folders") {
		t.Fatal("guarded deep system path must not require elevation")
	}
}

func TestDuCommandFor(t *testing.T) {
	// Not deep: always plain du, no matter the path.
	t.Setenv("MO_ANALYZE_DEEP", "")
	t.Setenv("MOLE_TEST_NO_AUTH", "")
	t.Setenv("MOLE_TEST_MODE", "")
	if name, lead := duCommandFor("/private/var/folders"); name != "du" || lead != nil {
		t.Fatalf("non-deep du for system path = (%q, %v), want (du, nil)", name, lead)
	}

	// Deep + system path (no test guard): elevate with sudo -n.
	t.Setenv("MO_ANALYZE_DEEP", "1")
	name, lead := duCommandFor("/private/var/folders")
	if name != "sudo" || !reflect.DeepEqual(lead, []string{"-n", "du"}) {
		t.Fatalf("deep du for system path = (%q, %v), want (sudo, [-n du])", name, lead)
	}

	// Deep + user path: never elevated.
	if name, lead := duCommandFor("/Users/someone/Downloads"); name != "du" || lead != nil {
		t.Fatalf("deep du for user path = (%q, %v), want (du, nil)", name, lead)
	}

	// Deep + system path but under the test guard: no sudo.
	t.Setenv("MOLE_TEST_NO_AUTH", "1")
	if name, lead := duCommandFor("/private/var/folders"); name != "du" || lead != nil {
		t.Fatalf("guarded deep du for system path = (%q, %v), want (du, nil)", name, lead)
	}
}

func TestDeepDuCommandArgs(t *testing.T) {
	ctx := context.Background()

	// Non-deep: exactly the plain du argv.
	t.Setenv("MO_ANALYZE_DEEP", "")
	t.Setenv("MOLE_TEST_NO_AUTH", "")
	t.Setenv("MOLE_TEST_MODE", "")
	cmd := deepDuCommand(ctx, "/tmp/x", "-sk", "/tmp/x")
	want := []string{"du", "-sk", "/tmp/x"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("non-deep argv = %v, want %v", cmd.Args, want)
	}

	// Deep + system path: sudo -n is prepended, du flags/target preserved.
	t.Setenv("MO_ANALYZE_DEEP", "1")
	cmd = deepDuCommand(ctx, "/private/var/folders", "-skPx", "/private/var/folders")
	want = []string{"sudo", "-n", "du", "-skPx", "/private/var/folders"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("deep argv = %v, want %v", cmd.Args, want)
	}
}

func TestCreateInsightEntriesDeepGating(t *testing.T) {
	// /private/var/folders exists on every macOS host; use it as the probe.
	const probe = "/private/var/folders"
	if info, err := os.Stat(probe); err != nil || !info.IsDir() {
		t.Skipf("%s not available on this host", probe)
	}

	hasProbe := func(entries []dirEntry) bool {
		for _, e := range entries {
			if e.Path == probe {
				return true
			}
		}
		return false
	}

	// Deep disabled: system temp must not appear.
	t.Setenv("MO_ANALYZE_DEEP", "")
	if hasProbe(createInsightEntries()) {
		t.Fatal("deep-only insight leaked into the default overview")
	}

	// Deep enabled: system temp must appear.
	t.Setenv("MO_ANALYZE_DEEP", "1")
	if !hasProbe(createInsightEntries()) {
		t.Fatalf("deep insight for %s missing when deep mode is enabled", probe)
	}
}
