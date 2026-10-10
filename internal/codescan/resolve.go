// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveBin trouve le binaire d'un moteur. Le PATH d'abord, puis les dossiers
// ou les installateurs usuels deposent leurs binaires sans toujours les ajouter
// au PATH: GOBIN, chaque GOPATH\bin, ~/go/bin pour `go install`, et
// ~/.local/bin pour pip et pipx hors Windows.
//
// Un moteur installe mais invisible est le pire des cas: le rapport dirait
// "absent" alors que l'outil est la. Chercher la ou il a ete pose evite de
// faire porter a l'utilisateur la configuration de son PATH.
func resolveBin(name string) (string, error) {
	p, lookErr := exec.LookPath(name)
	if lookErr == nil {
		return p, nil
	}
	// Un chemin explicite designe un fichier precis: on ne cherche pas ailleurs.
	if strings.ContainsAny(name, `/\`) {
		return "", lookErr
	}
	for _, dir := range installDirs() {
		for _, cand := range candidates(name) {
			full := filepath.Join(dir, cand)
			if isExecutable(full) {
				return full, nil
			}
		}
	}
	return "", fmt.Errorf("%s introuvable dans le PATH et dans %s",
		name, strings.Join(installDirs(), ", "))
}

// installDirs liste les dossiers d'installation consultes apres le PATH, sans
// doublon et dans l'ordre de priorite.
func installDirs() []string {
	var dirs []string
	if gb := os.Getenv("GOBIN"); gb != "" {
		dirs = append(dirs, gb)
	}
	for _, gp := range filepath.SplitList(os.Getenv("GOPATH")) {
		if gp != "" {
			dirs = append(dirs, filepath.Join(gp, "bin"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
		if runtime.GOOS != "windows" {
			dirs = append(dirs, filepath.Join(home, ".local", "bin"))
		}
	}

	seen := map[string]bool{}
	out := dirs[:0]
	for _, d := range dirs {
		key := filepath.Clean(d)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}

// candidates rend les noms de fichier a essayer. Sous Windows un binaire porte
// une extension; ailleurs le nom suffit.
func candidates(name string) []string {
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		return []string{name + ".exe", name + ".cmd", name + ".bat"}
	}
	return []string{name}
}

// isExecutable dit si p est un fichier ordinaire executable. Sous Windows,
// l'extension tient lieu de bit d'execution.
func isExecutable(p string) bool {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}
