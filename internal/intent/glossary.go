// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package intent

// GitHub indexes repository names, descriptions and READMEs, and those are
// overwhelmingly in English. A phrase typed in French therefore has to cross
// the language barrier before it becomes a query, or it matches nothing.
//
// This file is that crossing. It does two things, and the first matters more
// than the second.

// generic lists the words that describe the *kind* of thing being looked for
// rather than what it does. "une bibliotheque pour parser du yaml" is really a
// search for "yaml parse": nobody writes "library" in the description of their
// library, and every repository is a tool, a client or a module.
//
// Sending these words to GitHub is worse than useless. Search terms are
// combined with AND, so one word that matches nothing empties the entire
// result set. A single "bibliotheque" in the query is enough to return zero
// results for a query that would otherwise have worked.
var generic = map[string]bool{
	"bibliotheque": true, "librairie": true, "lib": true, "library": true,
	"outil": true, "outils": true, "tool": true, "tooling": true,
	"module": true, "paquet": true, "package": true,
	"programme": true, "logiciel": true, "software": true,
	"application": true, "appli": true, "app": true,
	"projet": true, "project": true, "depot": true, "repo": true,
	"repository": true, "solution": true, "systeme": true, "system": true,
	"truc": true, "chose": true, "quelque": true, "something": true,
	"implementation": true, "utilitaire": true, "utility": true,
}

// glossary translates the technical vocabulary people actually type. It is
// deliberately small: a large automatic translation would mistranslate more
// than it fixes, and a wrong term is worse than a missing one because it
// silently excludes the right results.
//
// Only terms whose English form is the one used in repository names and
// descriptions are listed. "parser" stays "parser" because both spellings
// occur; "chiffrement" becomes "encryption" because nobody names a Go package
// "chiffrement".
var glossary = map[string]string{
	// donnees et formats
	"chiffrement":   "encryption",
	"chiffrer":      "encrypt",
	"dechiffrer":    "decrypt",
	"crypto":        "cryptography",
	"cryptographie": "cryptography",
	"compression":   "compression",
	"compresser":    "compress",
	"analyse":       "parser",
	"analyser":      "parse",
	"lecture":       "reader",
	"ecriture":      "writer",
	"conversion":    "converter",
	"convertir":     "convert",
	"validation":    "validation",
	"valider":       "validate",
	"serialisation": "serialization",

	// reseau
	"reseau":    "network",
	"serveur":   "server",
	"client":    "client",
	"requete":   "request",
	"proxy":     "proxy",
	"pare-feu":  "firewall",
	"connexion": "connection",
	"protocole": "protocol",
	"routage":   "routing",
	"routeur":   "router",

	// stockage
	"base":       "database",
	"donnees":    "data",
	"fichier":    "file",
	"fichiers":   "files",
	"stockage":   "storage",
	"sauvegarde": "backup",
	"cache":      "cache",
	"migration":  "migration",
	"requetes":   "query",

	// interface et rendu
	"interface":  "ui",
	"graphique":  "graphics",
	"image":      "image",
	"images":     "image",
	"rendu":      "rendering",
	"terminal":   "terminal",
	"tableau":    "table",
	"formulaire": "form",
	"modele":     "template",

	// exploitation
	"journal":       "log",
	"journaux":      "logs",
	"surveillance":  "monitoring",
	"supervision":   "monitoring",
	"metrique":      "metrics",
	"metriques":     "metrics",
	"deploiement":   "deployment",
	"conteneur":     "container",
	"conteneurs":    "container",
	"orchestrateur": "orchestrator",
	"planificateur": "scheduler",
	"tache":         "task",
	"taches":        "task",
	"file":          "queue",
	"attente":       "queue",

	// securite
	"securite":         "security",
	"authentification": "authentication",
	"autorisation":     "authorization",
	"vulnerabilite":    "vulnerability",
	"vulnerabilites":   "vulnerability",
	"faille":           "vulnerability",
	"scan":             "scanner",
	"scanner":          "scanner",
	"audit":            "audit",
	"secret":           "secrets",
	"secrets":          "secrets",
	"jeton":            "token",
	"mot":              "password",
	"passe":            "password",
	"empreinte":        "hash",
	"signature":        "signature",

	// tests et qualite
	"test":        "testing",
	"tests":       "testing",
	"couverture":  "coverage",
	"performance": "performance",
	"performant":  "fast",
	"rapide":      "fast",
	"leger":       "lightweight",
	"minimaliste": "minimal",
	"embarque":    "embedded",

	// formes d'execution: ce sont les mots qui manquaient le plus, parce
	// qu'une "ligne de commande" ne s'ecrit jamais ainsi dans un depot.
	"ligne":      "cli",
	"commande":   "cli",
	"invite":     "shell",
	"console":    "terminal",
	"demon":      "daemon",
	"service":    "service",
	"greffon":    "plugin",
	"extension":  "extension",
	"navigateur": "browser",
	"bureau":     "desktop",
	"mobile":     "mobile",
	"web":        "web",
	"site":       "website",
	"statique":   "static",

	// divers courants
	"generateur":                "generator",
	"generer":                   "generate",
	"editeur":                   "editor",
	"visualisation":             "visualization",
	"apprentissage":             "machine-learning",
	"traduction":                "translation",
	"documentation":             "documentation",
	"calendrier":                "calendar",
	"courriel":                  "email",
	"messagerie":                "messaging",
	"paiement":                  "payment",
	"facture":                   "invoice",
	"tableur":                   "spreadsheet",
	"feuille":                   "spreadsheet",
	"calcul":                    "spreadsheet",
	"pdf":                       "pdf",
	"markdown":                  "markdown",
	"carte":                     "map",
	"cartographie":              "map",
	"graphe":                    "graph",
	"arbre":                     "tree",
	"recherche":                 "search",
	"rechercher":                "search",
	"indexation":                "index",
	"tri":                       "sort",
	"aleatoire":                 "random",
	"horodatage":                "timestamp",
	"date":                      "date",
	"heure":                     "time",
	"couleur":                   "color",
	"police":                    "font",
	"son":                       "audio",
	"audio":                     "audio",
	"video":                     "video",
	"flux":                      "stream",
	"lecteur":                   "player",
	"jeu":                       "game",
	"moteur":                    "engine",
	"simulation":                "simulation",
	"apprentissage-automatique": "machine-learning",
}

// multiWord handles the expressions that only mean something as a group.
// "ligne de commande" translated word by word gives "cli cli", which is
// harmless, but "base de donnees" would give "database data" and drag in every
// repository mentioning data. Collapsing them first avoids that.
var multiWord = []struct {
	phrase string
	term   string
}{
	{"ligne de commande", "cli"},
	{"base de donnees", "database"},
	{"bases de donnees", "database"},
	{"apprentissage automatique", "machine-learning"},
	{"intelligence artificielle", "ai"},
	{"traitement du langage", "nlp"},
	{"vision par ordinateur", "computer-vision"},
	{"series temporelles", "time-series"},
	{"file d attente", "queue"},
	{"mot de passe", "password"},
	{"gestion de version", "version-control"},
	{"integration continue", "ci"},
	{"reseau de neurones", "neural-network"},
	{"analyse statique", "static-analysis"},
	{"tests unitaires", "unit-testing"},
	{"bout en bout", "end-to-end"},
	{"temps reel", "realtime"},
	{"open source", "open-source"},
}

// translate maps a word through the glossary, leaving it untouched when no
// entry exists. Unknown words pass through because a rare, untranslated term
// is often the most precise thing in the phrase.
func translate(word string) string {
	if to, ok := glossary[word]; ok {
		return to
	}
	return word
}
