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
	"plateforme": true, "platform": true,
	// Les pluriels: "bibliotheques go" ne doit pas plus chercher le mot que
	// "bibliotheque go".
	"bibliotheques": true, "librairies": true, "libs": true, "libraries": true,
	"tools": true, "modules": true, "paquets": true, "packages": true,
	"programmes": true, "logiciels": true, "applications": true, "applis": true,
	"apps": true, "projets": true, "projects": true, "depots": true, "repos": true,
	"repositories": true, "solutions": true, "systemes": true, "systems": true,
	"utilitaires": true, "utilities": true, "plateformes": true, "platforms": true,
	"implementations": true, "trucs": true, "choses": true,
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
	// "analyse" est le nom (analyse de binaires, de journaux), "analyser" le
	// verbe qu'on emploie pour un format (analyser du yaml).
	"analyse":       "analysis",
	"analyser":      "parse",
	"parseur":       "parser",
	"parseurs":      "parser",
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

	// securite: le vocabulaire que Quaero doit lire sans faute, puisque c'est
	// son domaine de travail.
	"securite":         "security",
	"intrusion":        "intrusion",
	"detection":        "detection",
	"rancongiciel":     "ransomware",
	"rancongiciels":    "ransomware",
	"maliciel":         "malware",
	"maliciels":        "malware",
	"hameconnage":      "phishing",
	"forensique":       "forensics",
	"criminalistique":  "forensics",
	"retro-ingenierie": "reverse-engineering",
	"desassembleur":    "disassembler",
	"decompilateur":    "decompiler",
	"debogueur":        "debugger",
	"durcissement":     "hardening",
	"certificat":       "certificate",
	"certificats":      "certificate",
	"cle":              "key",
	"cles":             "key",
	"hachage":          "hash",
	"steganographie":   "steganography",
	"anonymat":         "anonymity",
	"anonymisation":    "anonymization",
	"confidentialite":  "privacy",
	"fuzzeur":          "fuzzer",
	"renifleur":        "sniffer",
	"usurpation":       "spoofing",
	"journalisation":   "logging",
	"conformite":       "compliance",
	"micrologiciel":    "firmware",
	"memoire":          "memory",
	"leurre":           "honeypot",
	"vulnerables":      "vulnerable",
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
	"attaque":          "attack",
	"attaques":         "attack",
	"menace":           "threat",
	"menaces":          "threat",
	"renseignement":    "intelligence",
	"sous-domaine":     "subdomain",
	"sous-domaines":    "subdomain",
	"noyau":            "kernel",
	"binaire":          "binary",
	"binaires":         "binary",
	"dependance":       "dependency",
	"dependances":      "dependency",
	"obfuscation":      "obfuscation",
	"desobfuscation":   "deobfuscation",
	"desobfuscateur":   "deobfuscator",
	"craquage":         "cracking",
	"cassage":          "cracking",
	"emulateur":        "emulator",
	"emulation":        "emulation",
	"contournement":    "bypass",
	"empoisonnement":   "poisoning",
	"controle":         "control",
	"regle":            "rule",
	"regles":           "rules",
	"gestion":          "management",
	"externe":          "external",
	"interne":          "internal",
	"post-quantique":   "post-quantum",
	"chiffre":          "encrypted",
	"chiffres":         "encrypted",

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
	"mobiles":    "mobile",
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
// The longer expressions come first: "gestionnaire de mots de passe" has to be
// read before "mots de passe", or it would be cut in two.
var multiWord = []struct {
	phrase string
	term   string
}{
	// securite
	{"gestionnaire de mots de passe", "password-manager"},
	{"gestionnaire de mot de passe", "password-manager"},
	{"cassage de mots de passe", "password-cracking"},
	{"craquage de mots de passe", "password-cracking"},
	{"chiffrement de bout en bout", "end-to-end-encryption"},
	{"analyse de logiciels malveillants", "malware-analysis"},
	{"analyse de logiciel malveillant", "malware-analysis"},
	{"analyse de malwares", "malware-analysis"},
	{"analyse de malware", "malware-analysis"},
	{"logiciels malveillants", "malware"},
	{"logiciel malveillant", "malware"},
	{"detection d'intrusion", "ids"},
	{"detection d intrusion", "ids"},
	{"detection des intrusions", "ids"},
	{"prevention d'intrusion", "ips"},
	{"prevention d intrusion", "ips"},
	{"tests d'intrusion", "pentest"},
	{"test d'intrusion", "pentest"},
	{"tests d intrusion", "pentest"},
	{"test d intrusion", "pentest"},
	{"detection de secrets", "secrets"},
	{"scanner de ports", "port-scanner"},
	{"scan de ports", "port-scanner"},
	{"balayage de ports", "port-scanner"},
	{"capture de paquets", "pcap"},
	{"capture reseau", "pcap"},
	{"analyse de trafic", "traffic-analysis"},
	{"analyse reseau", "network-analysis"},
	{"pot de miel", "honeypot"},
	{"pots de miel", "honeypot"},
	{"ingenierie inverse", "reverse-engineering"},
	{"investigation numerique", "forensics"},
	{"reponse aux incidents", "incident-response"},
	{"reponse a incident", "incident-response"},
	{"chasse aux menaces", "threat-hunting"},
	{"renseignement sur les menaces", "threat-intelligence"},
	{"sources ouvertes", "osint"},
	{"elevation de privileges", "privilege-escalation"},
	{"escalade de privileges", "privilege-escalation"},
	{"mouvement lateral", "lateral-movement"},
	{"injection sql", "sql-injection"},
	{"deni de service", "denial-of-service"},
	{"double authentification", "2fa"},
	{"authentification multifacteur", "mfa"},
	{"gestion des identites", "iam"},
	{"chaine d'approvisionnement", "supply-chain"},
	{"chaine d approvisionnement", "supply-chain"},
	{"nomenclature logicielle", "sbom"},
	{"reseau prive virtuel", "vpn"},
	{"pare-feu applicatif", "waf"},
	{"pare feu applicatif", "waf"},
	{"pare feu", "firewall"},
	{"bac a sable", "sandbox"},
	{"radio logicielle", "sdr"},
	{"objets connectes", "iot"},
	{"internet des objets", "iot"},
	{"noms de domaine", "domain"},
	{"nom de domaine", "domain"},
	{"equipe rouge", "red-team"},
	{"equipe bleue", "blue-team"},
	{"vie privee", "privacy"},
	{"active directory", "active-directory"},
	{"regles yara", "yara"},
	{"regle yara", "yara"},
	{"regles sigma", "sigma"},
	{"regle sigma", "sigma"},
	{"regles suricata", "suricata"},
	{"regles snort", "snort"},
	{"serveur de commande et controle", "c2"},
	{"commande et controle", "c2"},
	{"reverse shell", "reverse-shell"},
	{"web shell", "webshell"},
	{"authentification a deux facteurs", "2fa"},
	{"double facteur", "2fa"},
	{"deux facteurs", "2fa"},
	{"surface d'attaque", "attack-surface"},
	{"surface d attaque", "attack-surface"},
	{"cartographie reseau", "network-mapping"},
	{"signature de code", "code-signing"},
	{"controle d'acces", "access-control"},
	{"controle d acces", "access-control"},
	{"injection de commandes", "command-injection"},
	{"injection de commande", "command-injection"},
	{"injection de code", "code-injection"},
	{"vidage memoire", "memory-dump"},
	{"dump memoire", "memory-dump"},

	{"ligne de commande", "cli"},
	{"base de donnees", "database"},
	{"bases de donnees", "database"},
	{"apprentissage automatique", "machine-learning"},
	{"intelligence artificielle", "ai"},
	{"traitement du langage", "nlp"},
	{"vision par ordinateur", "computer-vision"},
	{"series temporelles", "time-series"},
	{"file d attente", "queue"},
	{"mots de passe", "password"},
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
