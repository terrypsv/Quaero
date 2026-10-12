// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"strings"
	"testing"
)

// Le titre garde la premiere phrase du message semgrep, le reste va dans la
// description.
func TestTitreSemgrepCourt(t *testing.T) {
	msg := "Detected non-static command inside Command. Audit the input to 'exec.Command'. If unverified user data can reach this call site, this is a code injection vulnerability."
	if got := shortMessage(msg); got != "Detected non-static command inside Command." {
		t.Errorf("titre %q", got)
	}
	long := strings.Repeat("motlong ", 30)
	if got := shortMessage(long); len(got) > 113 || !strings.HasSuffix(got, "...") {
		t.Errorf("titre long %q (%d)", got, len(got))
	}
	f := projectSemgrep(semgrepResult{
		CheckID: "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command",
		Path:    "a.go",
		Extra:   semgrepExtra{Message: msg},
	})
	if f.Title != "dangerous-exec-command: Detected non-static command inside Command." || f.Description != msg {
		t.Errorf("titre %q, description %q", f.Title, f.Description)
	}
}
