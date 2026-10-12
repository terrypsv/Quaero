// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"

	"github.com/terrypsv/Quaero/internal/codescan"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/repo"
	"github.com/terrypsv/Quaero/internal/webui"
)

// webScan est l'analyse lancee depuis l'onglet audit. Elle fait ce que fait
// `-scan owner/repo`, et seulement cela: un depot github.com nomme a la main,
// clone dans un temporaire, analyse en mode non fiable, puis efface. Elle ne
// lit jamais un chemin local.
func webScan(ctx context.Context, ref repo.Ref, stage func(string)) (*finding.Report, error) {
	stage(webui.StageClone)
	dir, cleanup, err := cloneRepo(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	stage(webui.StageAnalyse)
	opt := codescan.Options{Timeout: codescan.DefaultTimeout, Untrusted: true}
	rep, err := codescan.RunWith(ctx, dir, version, opt, selectScanners(dir)...)
	if err != nil {
		return nil, err
	}
	rep.Run.Context["cible"] = "github.com/" + ref.String()
	if commit := headCommit(ctx, dir); commit != "" {
		rep.Run.Context["commit"] = commit
	}
	return rep, nil
}
