// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Package proctree arrete un processus et tout ce qu'il a lance.
//
// exec.CommandContext ne tue que le processus lance. Un moteur comme semgrep
// lance ses propres sous-processus, git lance son assistant HTTPS: tues seuls,
// ils laissent derriere eux des enfants qui continuent de tourner, gardent la
// sortie ouverte et, sous Windows, empechent d'effacer le clone qu'ils lisent.
// Prepare regle la commande pour que l'annulation de son contexte arrete tout
// l'arbre.
package proctree

import (
	"os/exec"
	"time"
)

// WaitDelay borne l'attente des sorties d'un processus deja arrete.
const WaitDelay = 5 * time.Second

// Prepare doit etre appele avant Start. L'annulation du contexte de cmd arrete
// alors le processus et tous ses descendants.
func Prepare(cmd *exec.Cmd) {
	cmd.WaitDelay = WaitDelay
	prepare(cmd)
}
