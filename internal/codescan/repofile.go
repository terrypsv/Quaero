// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Lire un fichier du depot analyse, qui peut etre un clone tiers, ne doit
// jamais sortir du depot. os.Root refuse tout chemin qui en sortirait, par
// « .. » comme par un lien symbolique, a n'importe quel niveau du chemin.
// filepath.IsLocal ecarte en plus, sous Windows, les noms reserves (CON, NUL,
// COM1) et les flux de donnees (« fichier.go:flux »). Seul un fichier
// ordinaire est ouvert: un tube ou un peripherique bloquerait la lecture.

// openRepoFile ouvre en lecture le fichier rel du depot root.
func openRepoFile(root, rel string) (*os.File, func(), bool) {
	if root == "" || rel == "" {
		return nil, nil, false
	}
	name := filepath.FromSlash(rel)
	if !filepath.IsLocal(name) {
		return nil, nil, false
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, nil, false
	}
	info, err := r.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		_ = r.Close()
		return nil, nil, false
	}
	f, err := r.Open(name)
	if err != nil {
		_ = r.Close()
		return nil, nil, false
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		_ = r.Close()
		return nil, nil, false
	}
	return f, func() { _ = f.Close(); _ = r.Close() }, true
}

// readRepoHead rend au plus max premiers octets d'un fichier du depot.
func readRepoHead(root, rel string, max int64) ([]byte, bool) {
	f, done, ok := openRepoFile(root, rel)
	if !ok {
		return nil, false
	}
	defer done()
	data, err := io.ReadAll(io.LimitReader(f, max))
	return data, err == nil
}

// Bornes de repoLines: assez pour une construction signalee sur plusieurs
// lignes, pas assez pour qu'un fichier geant ralentisse l'analyse.
const (
	maxSnippetLines = 20
	maxSnippetBytes = 4 << 10
	maxScanBytes    = 8 << 20
)

// repoLines rend les lignes start a end d'un fichier du depot, telles
// qu'ecrites. semgrep ne les donne plus sans compte connecte (« requires
// login »): Quaero les relit lui-meme, sur la machine.
func repoLines(root, rel string, start, end int) string {
	if start <= 0 {
		return ""
	}
	if end < start {
		end = start
	}
	if end-start >= maxSnippetLines {
		end = start + maxSnippetLines - 1
	}
	f, done, ok := openRepoFile(root, rel)
	if !ok {
		return ""
	}
	defer done()
	sc := bufio.NewScanner(io.LimitReader(f, maxScanBytes))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var out []string
	size := 0
	for n := 1; sc.Scan(); n++ {
		if n < start {
			continue
		}
		line := strings.TrimRight(sc.Text(), "\r")
		size += len(line) + 1
		if size > maxSnippetBytes {
			break
		}
		out = append(out, line)
		if n >= end {
			break
		}
	}
	return strings.Join(out, "\n")
}
