// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"testing"
	"time"
)

// Le delai annonce avant l'analyse se lit sans conversion.
func TestDelaiLisible(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                       "15 min",
		15 * time.Minute:        "15 min",
		90 * time.Second:        "90 s",
		30 * time.Minute:        "30 min",
		1500 * time.Millisecond: "2 s",
	} {
		if got := minutes(d); got != want {
			t.Errorf("%v: %q, attendu %q", d, got, want)
		}
	}
}
