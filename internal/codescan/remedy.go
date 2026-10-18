// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"path"
	"regexp"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Un constat dit ce qui ne va pas. Le remede dit comment corriger, et quand
// c'est un faux positif, comment le dire dans le code pour que la prochaine
// analyse ne le releve plus. Il vient d'un guide ecrit a la main, regle par
// regle, sans modele de langage: le meme constat donne toujours le meme
// conseil, et rien ne quitte la machine.

// EvidenceException porte, pour un constat de code, le cas ou c'est un faux
// positif et l'annotation qui le dit dans le code.
const EvidenceException = "exception"

// genericRemediation est le conseil que gosec et semgrep recoivent avant le
// guide. Un rapport enregistre avant le guide le porte encore.
const genericRemediation = "Revoir le motif signale et corriger ou justifier l'exception."

// unknownRule est le remede d'une regle que le guide ne connait pas: la
// description de la regle dit le motif attendu.
var unknownRule = remedy{
	"Pas de remède écrit pour cette règle. Sa description, dans « détails », dit le motif sûr attendu.",
	"Si le motif est voulu.",
}

// EvidenceSuggestedFix porte la correction que la regle semgrep propose
// elle-meme, a appliquer a la ligne signalee.
const EvidenceSuggestedFix = "correctif"

type remedy struct {
	fix string // comment corriger
	ok  string // quand c'est un faux positif
}

var (
	remSecret = remedy{
		"Lire le secret depuis l'environnement ou un gestionnaire de secrets, jamais depuis le code. Un secret déjà publié se révoque, le retirer de l'historique ne suffit pas.",
		"Si c'est un nom de variable, une clé d'exemple ou une valeur de test sans usage réel.",
	}
	remBindAll = remedy{
		"Écouter sur 127.0.0.1 par défaut, et n'ouvrir toutes les interfaces que sur une demande explicite de l'utilisateur.",
		"Si le service est fait pour être joint depuis le réseau, derrière une authentification.",
	}
	remUnsafe = remedy{
		"Réserver unsafe aux appels système qui l'exigent, ou passer par golang.org/x/sys, qui les encapsule.",
		"Pour un appel d'API système qui demande un pointeur, comme un appel Windows par syscall.",
	}
	remErr = remedy{
		"Tester l'erreur rendue, ou l'ignorer explicitement avec _ = en disant pourquoi.",
		"Si l'erreur ne change rien à la suite, comme la fermeture d'un fichier ouvert en lecture.",
	}
	remHostKey = remedy{
		"Vérifier la clé de l'hôte, avec golang.org/x/crypto/ssh/knownhosts ou une empreinte attendue.",
		"Seulement dans un test local, jamais dans un binaire publié.",
	}
	remURL = remedy{
		"Si l'adresse vient de l'extérieur, la valider avant la requête, schéma https, hôte attendu, et refuser les adresses internes (127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16...).",
		"Si l'adresse est construite par le programme à partir d'une constante.",
	}
	remPprof = remedy{
		"Ne pas importer net/http/pprof dans un binaire publié, ou le servir sur un port local à part.",
		"Dans un outil de développement qui n'est pas livré.",
	}
	remIntConv = remedy{
		"Vérifier les bornes avant la conversion (math.MaxInt32, math.MaxUint16...), ou garder un type assez large.",
		"Si la valeur est bornée par construction, par exemple la longueur d'un tableau fixe.",
	}
	remBomb = remedy{
		"Borner ce qui est décompressé: io.CopyN ou io.LimitReader avec une taille maximale.",
		"Si l'archive est produite par le programme lui-même.",
	}
	remHTTPDir = remedy{
		"Servir un dossier dédié, et refuser les chemins qui sortent de la racine, avec os.Root ou filepath.IsLocal.",
		"Si le dossier ne contient que des fichiers publics.",
	}
	remTimeout = remedy{
		"Passer par un http.Server avec ReadHeaderTimeout, et ReadTimeout et WriteTimeout si possible, plutôt que http.ListenAndServe.",
		"Rarement, même en local un délai ne coûte rien.",
	}
	remSQL = remedy{
		"Passer les valeurs en paramètres de la requête, db.Query(\"SELECT ... WHERE id = ?\", id), jamais par fmt.Sprintf ni par concaténation.",
		"Si seule une partie constante, comme un nom de table fixe, est assemblée.",
	}
	remTemplate = remedy{
		"Laisser html/template échapper, et ne convertir en template.HTML que du contenu déjà nettoyé.",
		"Si le contenu converti est une constante du programme.",
	}
	remExec = remedy{
		"Lancer un binaire fixe, les arguments séparés, exec.Command(\"git\", \"clone\", url), sans passer par un shell (cmd /c, sh -c). Valider ce qui vient de l'utilisateur, et refuser un argument qui commence par un tiret.",
		"Si le binaire et ses arguments viennent du programme, pas d'une entrée extérieure.",
	}
	remDirPerm = remedy{
		"Créer le dossier en 0o750, ou 0o700 s'il contient des données personnelles.",
		"Pour un dossier fait pour être partagé entre comptes.",
	}
	remTemp = remedy{
		"Passer par os.CreateTemp ou os.MkdirTemp plutôt qu'un nom fixe dans le dossier temporaire.",
		"Si le nom est tiré au hasard par le programme.",
	}
	remPath = remedy{
		"Si le chemin peut venir de l'extérieur, le borner à un dossier avec os.OpenRoot (Go 1.24), ou filepath.IsLocal après filepath.Clean. Sinon, rien à changer.",
		"Si le chemin est construit par le programme, ou choisi par l'utilisateur lui-même en ligne de commande.",
	}
	remZip = remedy{
		"Refuser les entrées dont le nom n'est pas local, filepath.IsLocal, avant d'écrire, ou extraire au travers d'os.Root.",
		"Si l'archive est produite par le programme lui-même.",
	}
	remFilePerm = remedy{
		"Écrire en 0o600 un fichier qui contient des données personnelles ou des secrets. 0o644 ne se justifie que pour un fichier fait pour être lu par tous.",
		"Pour un exécutable installé (0o755) ou un fichier public.",
	}
	remClose = remedy{
		"Après une écriture, vérifier l'erreur de Close, c'est elle qui dit si les données sont arrivées sur le disque.",
		"Pour un fichier ouvert en lecture seule.",
	}
	remHash = remedy{
		"Passer à SHA-256 (crypto/sha256) pour tout usage de sécurité (signature, intégrité, jeton). Pour un mot de passe, bcrypt ou argon2.",
		"Si l'empreinte sert à identifier et non à protéger, comme l'empreinte SHA-1 d'un certificat affichée à côté de la SHA-256.",
	}
	remTLS = remedy{
		"Garder la vérification des certificats (pas d'InsecureSkipVerify) et fixer MinVersion à tls.VersionTLS12 au moins.",
		"Seulement dans un test contre un serveur local.",
	}
	remRSA = remedy{
		"Générer des clés RSA de 2048 bits au moins, 3072 de préférence.",
		"Jamais pour une clé réelle.",
	}
	remRand = remedy{
		"Utiliser crypto/rand pour tout jeton, mot de passe ou identifiant qu'il ne faut pas pouvoir deviner.",
		"Pour un tirage sans enjeu de sécurité, comme un jeu ou un échantillonnage.",
	}
	remCipher = remedy{
		"Passer à AES-GCM (crypto/aes puis cipher.NewGCM) ou à ChaCha20-Poly1305.",
		"Pour lire un ancien format qu'on ne choisit pas, sans rien chiffrer de nouveau avec.",
	}
	remCGI = remedy{
		"Ne pas importer net/http/cgi, servir en HTTP direct.",
		"Rarement.",
	}
	remLoopVar = remedy{
		"Depuis Go 1.22, chaque tour de boucle a sa propre variable, passer la directive go du go.mod à 1.22 ou plus suffit.",
		"Si le go.mod est déjà en 1.22 ou plus.",
	}
	remBounds = remedy{
		"Vérifier la longueur avant l'accès.",
		"Si la longueur est garantie juste avant.",
	}
	remRespWriter = remedy{
		"Rendre le HTML avec html/template, qui échappe les données. Pour une page fixe embarquée, fixer Content-Type et le dire sur la ligne.",
		"Si ce qui est écrit est une page embarquée ou du JSON encodé, sans donnée de l'utilisateur.",
	}
	remPinAction = remedy{
		"Épingler chaque action sur le SHA complet de son commit, uses: actions/checkout@<40 caractères> # v4, et laisser Dependabot les mettre à jour.",
		"Pour une action de sa propre organisation, en connaissance de cause.",
	}
	remShellInjection = remedy{
		"Passer l'expression ${{ ... }} par une variable d'environnement (env:) et l'utiliser entre guillemets dans le script, jamais directement dans run:.",
		"Si l'expression ne contient rien qu'un tiers puisse écrire (titre de PR, branche, commentaire).",
	}
	remDockerUser = remedy{
		"Ajouter une instruction USER avec un compte non root avant le lancement du programme.",
		"Pour une image de construction qui ne tourne jamais en service.",
	}
)

// gosecRemedies suit les regles de gosec.
var gosecRemedies = map[string]remedy{
	"G101": remSecret, "G102": remBindAll, "G103": remUnsafe, "G104": remErr,
	"G106": remHostKey, "G107": remURL, "G108": remPprof, "G109": remIntConv,
	"G110": remBomb, "G111": remHTTPDir, "G112": remTimeout, "G114": remTimeout,
	"G115": remIntConv, "G201": remSQL, "G202": remSQL, "G203": remTemplate,
	"G204": remExec, "G301": remDirPerm, "G302": remFilePerm, "G303": remTemp,
	"G304": remPath, "G305": remZip, "G306": remFilePerm, "G307": remClose,
	"G401": remHash, "G402": remTLS, "G403": remRSA, "G404": remRand,
	"G405": remCipher, "G406": remHash, "G501": remHash, "G502": remCipher,
	"G503": remCipher, "G504": remCGI, "G505": remHash, "G506": remHash,
	"G507": remHash, "G601": remLoopVar, "G602": remBounds,
}

// semgrepRemedies suit la fin de l'identifiant des regles semgrep courantes.
var semgrepRemedies = map[string]remedy{
	"dangerous-exec-command":               remExec,
	"dangerous-exec-cmd":                   remExec,
	"dangerous-command-write":              remExec,
	"dangerous-syscall-exec":               remExec,
	"use-of-sha1":                          remHash,
	"use-of-md5":                           remHash,
	"use-of-DES":                           remCipher,
	"use-of-rc4":                           remCipher,
	"use-of-weak-rsa-key":                  remRSA,
	"no-direct-write-to-responsewriter":    remRespWriter,
	"github-actions-mutable-action-tag":    remPinAction,
	"run-shell-injection":                  remShellInjection,
	"missing-ssl-minversion":               remTLS,
	"ssl-v3-is-insecure":                   remTLS,
	"tls-with-insecure-cipher":             remTLS,
	"bad-tmp-file-creation":                remTemp,
	"string-formatted-query":               remSQL,
	"gosql-sqli":                           remSQL,
	"pgx-sqli":                             remSQL,
	"avoid-bind-to-all-interfaces":         remBindAll,
	"math-random-used":                     remRand,
	"use-of-unsafe-block":                  remUnsafe,
	"potential-dos-via-decompression-bomb": remBomb,
	"missing-user":                         remDockerUser,
	"missing-user-entrypoint":              remDockerUser,
	"last-user-is-root":                    remDockerUser,
}

var gosecRuleRe = regexp.MustCompile(`^G[0-9]{3}$`)

// remedyOf rend le remede d'un constat de code et les annotations qui le
// disent faux positif, une par moteur qui l'a releve: un constat fusionne de
// semgrep et gosec n'est tu que si les deux le sont. ok est faux si le guide ne
// connait pas la regle.
func remedyOf(f finding.Finding) (r remedy, notes []string, ok bool) {
	var gosecRules []string
	if rule, _, found := strings.Cut(f.Title, ":"); found && gosecRuleRe.MatchString(rule) {
		gosecRules = append(gosecRules, rule)
	}
	for _, e := range f.Evidence {
		if e.Type == EvidenceMerged {
			if rule, _, found := strings.Cut(e.Data, ":"); found && gosecRuleRe.MatchString(rule) && !containsStr(gosecRules, rule) {
				gosecRules = append(gosecRules, rule)
			}
		}
	}
	for _, rule := range gosecRules {
		if g, known := gosecRemedies[rule]; known && !ok {
			r, ok = g, true
		}
		notes = append(notes, "« // #nosec "+rule+" -- raison » en fin de ligne")
	}
	for _, e := range f.Evidence {
		if e.Type != "rule" {
			continue
		}
		short := shortRule(e.Data)
		g, known := semgrepRemedies[short]
		if !known && strings.HasPrefix(short, "detected-") {
			g, known = remSecret, true
		}
		if known && !ok {
			r, ok = g, true
		}
		notes = append(notes, nosemgrepNote(f, e.Data))
	}
	return r, notes, ok
}

// nosemgrepNote ecrit l'annotation semgrep dans la syntaxe des commentaires du
// fichier signale. Un fichier qui melange deux syntaxes (JSX, gabarit Vue) a
// les deux: dans le balisage, « // » s'afficherait sur la page.
func nosemgrepNote(f finding.Finding, rule string) string {
	ann := func(open, end string) string { return "« " + open + " nosemgrep: " + rule + end + " »" }
	switch ext, base := fileOf(f); {
	case hashComment[ext] || base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == "makefile":
		return ann("#", "") + " sur la ligne d'avant"
	case ext == ".html" || ext == ".htm" || ext == ".xml":
		return ann("<!--", " -->") + " sur la ligne d'avant"
	case ext == ".sql" || ext == ".lua":
		return ann("--", "") + " sur la ligne d'avant"
	case ext == ".jsx" || ext == ".tsx":
		return ann("//", "") + " sur la ligne d'avant, ou " + ann("{/*", " */}") + " dans du JSX"
	case ext == ".vue" || ext == ".svelte":
		return ann("//", "") + " sur la ligne d'avant dans le script, ou " + ann("<!--", " -->") + " dans le gabarit"
	}
	return ann("//", "") + " sur la ligne d'avant"
}

// fileOf rend l'extension et le nom, en minuscules, du fichier d'un constat
// ecrit fichier:ligne ou fichier:ligne:colonne.
func fileOf(f finding.Finding) (ext, base string) {
	file := ""
	if f.Target != nil {
		file = f.Target.Identifier
		for range 2 {
			if i := strings.LastIndexByte(file, ':'); i > 0 && i < len(file)-1 && strings.Trim(file[i+1:], "0123456789") == "" {
				file = file[:i]
			}
		}
	}
	base = strings.ToLower(path.Base(strings.ReplaceAll(file, "\\", "/")))
	return path.Ext(base), base
}

// hashComment sont les extensions dont les commentaires commencent par #.
var hashComment = set(".py", ".rb", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml", ".tf", ".hcl", ".pl", ".r", ".ps1", ".dockerfile", ".cfg", ".ini", ".conf")

// remedies pose sur chaque constat de code le remede du guide a la place du
// conseil general. Une regle que le guide ne connait pas renvoie a sa
// description, et garde l'annotation qui la tait. Un constat qui a deja son
// remede n'est pas touche: l'appel peut se repeter.
func remedies(fs []finding.Finding) {
	for i := range fs {
		f := &fs[i]
		if published(*f) || isMeta(*f) || len(evidenceValues(*f, EvidenceException)) > 0 {
			continue
		}
		if f.Remediation != "" && f.Remediation != genericRemediation {
			continue
		}
		r, notes, ok := remedyOf(*f)
		if !ok {
			r = unknownRule
		}
		f.Remediation = r.fix
		if len(notes) > 0 {
			f.Evidence = append(f.Evidence, finding.Evidence{Type: EvidenceException,
				Data: r.ok + " Le dire dans le code avec " + strings.Join(notes, ", et ") + "."})
		}
	}
}

// Remedies pose le guide sur un rapport enregistre avant lui: rouvert, il dit
// comment corriger comme une analyse du jour. Les dependances gardent le
// conseil qu'elles portent, leur version corrigee demande la base OSV du jour
// de l'analyse.
func Remedies(rep *finding.Report) {
	if rep != nil {
		remedies(rep.Findings)
	}
}
