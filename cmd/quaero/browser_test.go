// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import "testing"

func TestBrowserCommand(t *testing.T) {
	const url = "http://127.0.0.1:7777/"
	cases := map[string]string{"windows": "rundll32", "darwin": "open", "linux": "xdg-open", "freebsd": "xdg-open"}
	for goos, want := range cases {
		name, args := browserCommand(goos, url)
		if name != want {
			t.Errorf("%s: commande %q, attendu %q", goos, name, want)
		}
		if len(args) == 0 || args[len(args)-1] != url {
			t.Errorf("%s: l'adresse doit etre le dernier argument, obtenu %v", goos, args)
		}
	}
}

func TestFolderCommand(t *testing.T) {
	const dir = `C:\Users\Terry PASSAVE\.quaero\rapports`
	cases := map[string]string{"windows": "explorer", "darwin": "open", "linux": "xdg-open", "freebsd": "xdg-open"}
	for goos, want := range cases {
		name, args := folderCommand(goos, dir)
		if name != want || len(args) != 1 || args[0] != dir {
			t.Errorf("%s: %s %v, attendu %s [%s]", goos, name, args, want, dir)
		}
	}
}
