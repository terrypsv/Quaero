// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Command quaero serves a search interface over GitHub that reads phrases
// instead of query syntax, and rates whether a repository can be depended on.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/terrypsv/Quaero/internal/codescan"
	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/webui"
)

// version is injected at build time from the git tag via -ldflags. An untagged
// build says so rather than claiming a release number it does not carry.
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "adresse d'ecoute")
	noBrowser := flag.Bool("no-browser", false, "ne pas ouvrir l'interface dans le navigateur au lancement")
	showVersion := flag.Bool("version", false, "afficher la version et quitter")
	saveToken := flag.String("save-token", "", "enregistrer un jeton GitHub et quitter")
	forget := flag.Bool("forget-token", false, "oublier le jeton enregistre et quitter")
	auditQuery := flag.String("audit", "", "auditer la sante des depots correspondant a cette requete, puis quitter")
	auditJSON := flag.String("audit-json", "", "avec -audit: ecrire le rapport au schema partage dans ce fichier")
	auditLimit := flag.Int("audit-limit", 30, "avec -audit: nombre de depots a evaluer")
	scanPath := flag.String("scan", "", "analyser le code d'un depot, puis quitter: un chemin local, ou un depot github (owner/repo ou URL github.com) a cloner")
	scanJSON := flag.String("scan-json", "", "avec -scan: ecrire le rapport au schema partage dans ce fichier")
	scanTimeout := flag.Duration("scan-timeout", codescan.DefaultTimeout, "avec -scan: duree maximale accordee a chaque moteur (ex. 5m, 30m)")
	advisoryReport := flag.String("advisory", "", "lire un rapport ecrit par -scan-json et lister les constats a signaler, puis quitter")
	advisoryFinding := flag.String("finding", "", "avec -advisory: preparer le brouillon de signalement de ce constat")
	advisoryOut := flag.String("advisory-out", "", "avec -advisory et -finding: ecrire le brouillon dans ce fichier")
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
	if *auditQuery != "" {
		code, err := runAudit(*auditQuery, *auditLimit, *auditJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		}
		os.Exit(code)
	}
	if *advisoryReport != "" {
		code, err := runAdvisory(*advisoryReport, *advisoryFinding, *advisoryOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		}
		os.Exit(code)
	}
	if *scanPath != "" {
		code, err := runScan(*scanPath, *scanJSON, *scanTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		}
		os.Exit(code)
	}

	client, err := github.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n\n", err)
		fmt.Fprintln(os.Stderr, "Sans jeton, la recherche GitHub est limitee a 10 requetes par minute,")
		fmt.Fprintln(os.Stderr, "deux recherches approfondies. Creer un jeton personnel sans")
		fmt.Fprintln(os.Stderr, "aucune permission (la recherche publique n'en demande pas), puis:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  quaero -save-token <jeton>     l'enregistrer une fois pour toutes")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "ou, pour une session seulement:")
		fmt.Fprintln(os.Stderr, "  PowerShell : $env:GITHUB_TOKEN=\"...\"")
		fmt.Fprintln(os.Stderr, "  bash       : export GITHUB_TOKEN=...")
		os.Exit(2)
	}
	// Le jeton de session ne vit qu'en memoire, le temps de cette execution.
	session, err := webui.NewToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: jeton de session impossible a tirer: %v\n", err)
		os.Exit(2)
	}
	server := &webui.Server{Client: client, Version: version, Addr: *addr, Token: session}
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// The default address is loopback on purpose: the process carries a GitHub
	// token, and a tool bound to every interface by default is a tool that
	// leaks that token the first time it runs on an untrusted network.
	// L'ecoute est ouverte avant le navigateur: la page doit repondre des que
	// l'onglet s'affiche, et un port deja pris doit se dire avant.
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: ecoute sur %s impossible: %v\n", *addr, err)
		fmt.Fprintln(os.Stderr, "Quaero tourne peut-etre deja. Ouvrir l'adresse dans le navigateur, ou choisir un autre port avec -addr.")
		os.Exit(2)
	}
	// Le navigateur s'ouvre sur le lien de session: le jeton y passe une fois,
	// devient un cookie, puis disparait de la barre d'adresse.
	url := webui.SessionURL(*addr, session)
	fmt.Printf("quaero %s - %s\n", version, webui.URL(*addr))
	if webui.ListensEverywhere(*addr) {
		fmt.Fprintln(os.Stderr, "attention: ecoute sur toutes les interfaces. Le controle de l'hote ne s'applique plus, seul le jeton de session protege l'interface.")
	}
	if *noBrowser {
		fmt.Printf("Ouvrir la session: %s\n", url)
	} else if err := openBrowser(url); err != nil {
		fmt.Fprintf(os.Stderr, "navigateur non ouvert (%v). Ouvrir la session: %s\n", err, url)
	}
	fmt.Println("Ctrl+C pour arreter.")
	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serveur: %v", err)
	}
}
