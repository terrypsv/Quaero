// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Un dossier local se compare a l'analyse precedente faite sur la meme
// machine: le meme chemin ailleurs n'est pas forcement le meme depot. Le nom
// de la machine change avec le reseau sur certains systemes, alors Quaero
// tire un identifiant au hasard la premiere fois et le garde. Il ne dit rien
// de la machine et ne quitte jamais le rapport.

var (
	machineOnce sync.Once
	machine     string
	machineRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// stampMachine pose l'identifiant de cette machine dans le rapport.
func stampMachine(rep *finding.Report) {
	machineOnce.Do(func() { machine = machineID(machineFile()) })
	if machine != "" && rep != nil {
		rep.Run.Context["poste"] = machine
	}
}

func machineFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".quaero", "poste")
}

// machineID lit l'identifiant garde dans path, ou le tire et l'y ecrit. Deux
// Quaero lances ensemble gardent le meme: le second relit celui du premier.
// Il rend "" s'il ne peut ni le lire ni l'ecrire.
func machineID(path string) string {
	if path == "" {
		return ""
	}
	read := func() string {
		b, err := os.ReadFile(path)
		if id := strings.TrimSpace(string(b)); err == nil && machineRe.MatchString(id) {
			return id
		}
		return ""
	}
	if id := read(); id != "" {
		return id
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	id := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ""
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return read()
	}
	if err != nil {
		return ""
	}
	_, werr := f.WriteString(id + "\n")
	if cerr := f.Close(); werr != nil || cerr != nil {
		return ""
	}
	return id
}
