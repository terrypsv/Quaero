// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

// Command quaero serves a search interface over GitHub that reads phrases
// instead of query syntax, and rates whether a repository can be depended on.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/terrypsv/Quaero/internal/codescan"
	"github.com/terrypsv/Quaero/internal/github"
	"github.com/terrypsv/Quaero/internal/reports"
	"github.com/terrypsv/Quaero/internal/triage"
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
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(2)
	}
	// Sans jeton, Quaero tourne quand meme: chacun peut l'essayer sans rien
	// creer. La recherche est alors limitee par GitHub, l'audit d'un depot
	// public ne change pas.
	if client.Anonymous() {
		fmt.Fprintln(os.Stderr, "sans jeton GitHub: recherche limitee a 10 requetes par minute, audit inchange.")
		fmt.Fprintln(os.Stderr, "Pour 30 par minute, un jeton sans aucune permission suffit: quaero -save-token <jeton>")
	}
	// Le jeton de session est garde entre deux lancements: un onglet ouvert
	// avant une relance le connait et reprend, sans nouvel onglet.
	session, reused, err := sessionToken(*addr)
	if session == "" {
		fmt.Fprintf(os.Stderr, "erreur: jeton de session impossible a tirer: %v\n", err)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "attention: jeton de session non garde (%v), un onglet ouvert ne reprendra pas apres une relance\n", err)
	}
	server := &webui.Server{Client: client, Version: version, Addr: *addr, Token: session, Scan: webScan(client.Token), ScanTimeout: codescan.DefaultTimeout}
	// Les analyses lancees depuis l'interface sont gardees sur la machine, dans
	// le dossier de l'utilisateur, pour les rouvrir sans reseau. Quand Quaero
	// ecoute sur toutes les interfaces, elles ne sont ni gardees ni servies,
	// comme les dossiers locaux: elles peuvent citer du code prive.
	if dir, err := reports.DefaultDir(); err == nil && !webui.ListensEverywhere(*addr) {
		// Un rapport d'avant le guide de correction le recoit en se rouvrant.
		server.Reports = &reports.Store{Dir: dir, Enrich: codescan.Remedies}
		server.OpenDir = openFolder
	}
	// Les decisions de tri suivent la meme regle: elles citent des fichiers et
	// des notes sur des failles non corrigees.
	if path, err := triage.DefaultPath(); err == nil && !webui.ListensEverywhere(*addr) {
		server.Triage = &triage.Store{Path: path}
	}
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
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(listener) }()

	// Ctrl+C arrete d'abord l'analyse en cours, le temps qu'elle efface son
	// clone: quitter sans cela laisserait du code tiers dans le temporaire.
	stop, release := signal.NotifyContext(context.Background(), stopSignals...)
	defer release()
	go func() {
		<-stop.Done()
		// Un second Ctrl+C quitte tout de suite, sans attendre le nettoyage.
		release()
		if stopped, finished := server.StopScan(10 * time.Second); stopped && finished {
			fmt.Println("analyse en cours interrompue")
		} else if stopped {
			fmt.Fprintf(os.Stderr, "analyse interrompue sans avoir fini, un clone quaero-scan-* peut rester dans %s\n", os.TempDir())
		}
		_ = httpServer.Close()
	}()

	// Le navigateur s'ouvre sur le lien de session: le jeton y passe une fois,
	// devient un cookie, puis disparait de la barre d'adresse. Un onglet ouvert
	// avant la relance se manifeste dans les secondes qui suivent: il reprend,
	// et aucun autre ne s'ouvre.
	url := webui.SessionURL(*addr, session)
	fmt.Printf("quaero %s - %s\n", version, webui.URL(*addr))
	if webui.ListensEverywhere(*addr) {
		fmt.Fprintln(os.Stderr, "attention: ecoute sur toutes les interfaces. Le controle de l'hote ne s'applique plus, seul le jeton de session protege l'interface.")
	}
	switch {
	case reused && server.WaitPresence(presenceWait):
		fmt.Println("Onglet deja ouvert, il reprend avec cette execution.")
	case *noBrowser:
		fmt.Printf("Ouvrir la session: %s\n", url)
	default:
		if err := openBrowser(url); err != nil {
			fmt.Fprintf(os.Stderr, "navigateur non ouvert (%v). Ouvrir la session: %s\n", err, url)
		}
	}
	// Un clone reste d'une execution precedente (arret brutal, fichier tenu
	// sous Windows) se signale, sans etre efface: un autre Quaero pourrait
	// etre en train de le lire.
	if stale := staleClones(os.TempDir(), time.Hour); len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "attention: %d clone(s) d'analyses precedentes dans %s (%s*), a supprimer a la main\n",
			len(stale), os.TempDir(), cloneDirPrefix)
	}
	fmt.Println("Ctrl+C pour arreter.")

	if err := <-served; err != nil && err != http.ErrServerClosed {
		log.Fatalf("serveur: %v", err)
	}
}

// presenceWait est le temps laisse a un onglet deja ouvert pour se manifester
// apres une relance. La page retente chaque seconde.
const presenceWait = 2500 * time.Millisecond

// sessionToken rend le jeton de session et dit s'il vient d'un lancement
// precedent. En ecoute sur toutes les interfaces, le jeton est tire a chaque
// lancement et jamais ecrit: il ne doit pas survivre a une exposition reseau.
func sessionToken(addr string) (string, bool, error) {
	if webui.ListensEverywhere(addr) {
		t, err := webui.NewToken()
		return t, false, err
	}
	path, err := webui.SessionPath()
	if err != nil {
		t, terr := webui.NewToken()
		if terr != nil {
			return "", false, terr
		}
		return t, false, err
	}
	return webui.SessionToken(path)
}
