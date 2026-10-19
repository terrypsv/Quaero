// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"context"

	"github.com/terrypsv/Quaero/internal/codescan"
	"github.com/terrypsv/Quaero/internal/finding"
	"github.com/terrypsv/Quaero/internal/webui"
)

// webScan rend l'analyse lancee depuis l'onglet audit. Elle fait ce que fait
// `-scan`, et seulement cela. Un depot GitHub est clone dans un temporaire,
// analyse avec l'environnement durci du code tiers, puis efface; token ne sert
// que si GitHub refuse le clone anonyme (depot prive). Un dossier local est lu
// sur place, comme `-scan <chemin>`.
func webScan(token string) webui.ScanFunc {
	return func(ctx context.Context, t webui.ScanTarget, stage func(string)) (*finding.Report, error) {
		dir, label, untrusted := t.Dir, t.Dir, false
		if !t.Local() {
			stage(webui.StageClone)
			clone, cleanup, err := cloneRepo(ctx, t.Repo, token)
			if err != nil {
				return nil, err
			}
			defer cleanup()
			dir, label, untrusted = clone, "github.com/"+t.Repo.String(), true
		}

		stage(webui.StageAnalyse)
		opt := codescan.Options{Timeout: codescan.DefaultTimeout, Untrusted: untrusted}
		rep, err := codescan.RunWith(ctx, dir, version, opt, selectScanners(dir)...)
		if err != nil {
			return nil, err
		}
		rep.Run.Context["cible"] = label
		stampMachine(rep)
		if commit := headCommit(ctx, dir); commit != "" {
			rep.Run.Context["commit"] = commit
		}
		return rep, nil
	}
}
