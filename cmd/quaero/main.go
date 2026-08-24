// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Command quaero serves a search interface over GitHub that reads phrases
// instead of query syntax, and rates whether a repository can be depended on.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/webui"
)

// version is injected at build time from the git tag via -ldflags. An untagged
// build says so rather than claiming a release number it does not carry.
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "adresse d'ecoute")
	showVersion := flag.Bool("version", false, "afficher la version et quitter")
	saveToken := flag.String("save-token", "", "enregistrer un jeton GitHub et quitter")
	forget := flag.Bool("forget-token", false, "oublier le jeton enregistre et quitter")
	flag.Parse()

	if *showVersion {
		fmt.Printf("quaero %s\n", version)
		return
	}

	if *forget {
		path, err := github.ForgetToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("jeton oublie (%s)\n", path)
		return
	}

	if *saveToken != "" {
		path, err := github.SaveToken(*saveToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("jeton enregistre dans %s\n", path)
		fmt.Println("Il sera utilise automatiquement aux prochains demarrages.")
		return
	}

	client, err := github.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n\n", err)
		fmt.Fprintln(os.Stderr, "Sans jeton, l'API GitHub limite a 60 requetes par heure, ce qu'une")
		fmt.Fprintln(os.Stderr, "seule session de recherche epuise. Creer un jeton personnel sans")
		fmt.Fprintln(os.Stderr, "aucune permission (la recherche publique n'en demande pas), puis:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  quaero -save-token <jeton>     l'enregistrer une fois pour toutes")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "ou, pour une session seulement:")
		fmt.Fprintln(os.Stderr, "  PowerShell : $env:GITHUB_TOKEN=\"...\"")
		fmt.Fprintln(os.Stderr, "  bash       : export GITHUB_TOKEN=...")
		os.Exit(2)
	}

	server := &webui.Server{Client: client, Version: version}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// The default address is loopback on purpose: the process carries a GitHub
	// token, and a tool bound to every interface by default is a tool that
	// leaks that token the first time it runs on an untrusted network.
	fmt.Printf("quaero %s - http://%s\n", version, *addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serveur: %v", err)
	}
}
