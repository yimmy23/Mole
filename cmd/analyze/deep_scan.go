//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Deep scan surfaces root-owned system areas — most notably
// /private/var/folders, where daemons such as com.apple.idleassetsd can
// silently accumulate hundreds of gigabytes of aborted temporary downloads —
// that the normal, unprivileged analyze overview cannot measure. macOS folds
// these bytes into the opaque "System Data" bucket and the Finder never shows
// them, so a plain `du` run as the user hits "permission denied" on the
// root-owned trees and reports almost nothing.
//
// Deep scan is strictly opt-in via the --deep flag (or MO_ANALYZE_DEEP=1)
// because it requires sudo to read directories owned by root. Authentication is
// primed once, up front, before the TUI starts, and every later read uses
// `sudo -n` so the interface never blocks on a password prompt. Under the test
// no-auth guard it degrades to unprivileged du and never touches sudo.

// deepScanEnabled reports whether the opt-in deep system scan is active.
func deepScanEnabled() bool {
	return os.Getenv("MO_ANALYZE_DEEP") == "1"
}

// deepScanUsesSudo reports whether du should be elevated with `sudo -n` to read
// root-owned trees. It stays false under the test no-auth guard so tests and CI
// never trigger a real authentication prompt.
func deepScanUsesSudo() bool {
	if !deepScanEnabled() {
		return false
	}
	if os.Getenv("MOLE_TEST_NO_AUTH") == "1" {
		return false
	}
	return true
}

// isDeepSystemPath reports whether target lives under /private, i.e. a
// root-owned system area that only deep mode is allowed to elevate reads for.
// User paths (Home, ~/Library, /Applications, ...) are never elevated, so a
// deep scan runs sudo strictly against the system trees it exists to reveal.
func isDeepSystemPath(target string) bool {
	if target == "" {
		return false
	}
	clean := filepath.Clean(target)
	return clean == "/private" || strings.HasPrefix(clean, "/private"+string(filepath.Separator))
}

// duCommandFor returns the executable name and leading arguments for a du
// invocation against target. In deep mode, reads of root-owned system paths are
// elevated with `sudo -n` (non-interactive; relies on credentials primed before
// the TUI starts and never blocks on a password prompt). Everything else runs
// du unprivileged, exactly as before.
func duCommandFor(target string) (name string, leadingArgs []string) {
	if deepScanUsesSudo() && isDeepSystemPath(target) {
		return "sudo", []string{"-n", "du"}
	}
	return "du", nil
}

// deepDuCommand builds a du *exec.Cmd for target, transparently prefixing
// `sudo -n` when deep mode should elevate the read. duArgs are the du arguments
// (flags and the target path) exactly as they would be passed to a plain du.
func deepDuCommand(ctx context.Context, target string, duArgs ...string) *exec.Cmd {
	name, leading := duCommandFor(target)
	full := make([]string, 0, len(leading)+len(duArgs))
	full = append(full, leading...)
	full = append(full, duArgs...)
	return exec.CommandContext(ctx, name, full...)
}

// deepSystemInsightPaths lists the root-owned system areas surfaced only when
// deep mode is active. These are the locations macOS folds into "System Data"
// and that the Finder never shows.
func deepSystemInsightPaths() []struct {
	name string
	path string
} {
	return []struct {
		name string
		path string
	}{
		{"System Temp (var/folders)", "/private/var/folders"},
		{"System VM / Swap", "/private/var/vm"},
	}
}

// primeSudoForDeepScan authenticates once, up front and outside the TUI's alt
// screen, so later `sudo -n du` calls succeed without ever blocking the
// interface on a password prompt. If authentication fails or is declined, deep
// mode is disabled and analyze continues with normal, unprivileged output. It
// is a no-op unless deep mode is enabled, and always a no-op under the test
// no-auth guard.
func primeSudoForDeepScan() {
	if !deepScanEnabled() {
		return
	}
	if os.Getenv("MOLE_TEST_NO_AUTH") == "1" {
		return
	}

	fmt.Fprintln(os.Stderr, "Deep scan needs administrator access to measure root-owned system folders (e.g. /private/var/folders).")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Deep scan: administrator access unavailable; continuing without elevated system folders.")
		_ = os.Unsetenv("MO_ANALYZE_DEEP")
	}
}
