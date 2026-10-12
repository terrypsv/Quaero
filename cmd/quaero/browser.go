// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"os/exec"
	"runtime"
)

// browserCommand rend la commande qui ouvre url dans le navigateur par defaut
// du systeme. Le binaire est fixe pour chaque systeme, l'adresse vient de
// webui.URL, jamais d'une entree exterieure.
func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "windows":
		// rundll32 ouvre l'adresse sans passer par cmd.exe, dont l'analyse
		// des caracteres speciaux (&, ^) couperait une adresse longue.
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		return "open", []string{url}
	default:
		return "xdg-open", []string{url}
	}
}

// openBrowser ouvre url sans attendre: le navigateur vit sa vie, Quaero
// continue de servir. Un echec n'est pas fatal, l'adresse reste affichee dans
// le terminal.
func openBrowser(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	// #nosec G204 -- binaire fixe par systeme, adresse construite par webui.URL
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Recolter le processus quand il se termine, pour ne pas laisser de zombie
	// sous Linux et macOS.
	go func() { _ = cmd.Wait() }()
	return nil
}
