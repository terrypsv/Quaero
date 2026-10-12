// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

//go:build !unix && !windows

package proctree

import "os/exec"

// Ailleurs, seul le processus lance est arrete, comme exec le fait seul.
func prepare(cmd *exec.Cmd) {}
