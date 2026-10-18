// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/terrypsv/Quaero/internal/finding"
)

// Pour une dependance, corriger veut dire passer a une version qui ne porte
// plus la faille. La base OSV la donne pour chaque vulnerabilite (evenement
// « fixed »), govulncheck aussi. Quaero retient, pour chaque copie de la
// dependance (son manifeste et sa version en place), la plus haute de ces
// versions, celle qui les corrige toutes, et ecrit la commande qui y passe.
// Deux copies d'un meme paquet sur deux branches (semver 5.7.1 et 6.3.0) ont
// chacune leur version cible: monter 5.7.1 en 6.x changerait d'API.

// Preuves posees sur les constats de dependance.
const (
	// EvidenceFixedIn porte la premiere version qui corrige la vulnerabilite.
	EvidenceFixedIn = "corrige_en"
	// EvidenceNoFix dit que la base connait le paquet et ne publie aucune
	// version corrigee. Sans elle ni corrige_en, la version est inconnue.
	EvidenceNoFix = "sans_correctif"
	// EvidenceEcosystem porte l'ecosysteme de la dependance (Go, npm, PyPI...).
	EvidenceEcosystem = "ecosysteme"
	// EvidenceTargetVersion porte la plus haute des versions corrigees des
	// vulnerabilites d'une copie de la dependance: celle qui les corrige
	// toutes.
	EvidenceTargetVersion = "version_cible"
	// EvidenceCommand porte une commande qui passe la dependance a cette
	// version. Il peut y en avoir plusieurs, a lancer dans l'ordre.
	EvidenceCommand = "commande"
)

// fixTypes sont les preuves qui decrivent une dependance precise. Une fusion
// ne les passe d'un constat a l'autre que pour le meme paquet: une meme CVE
// peut toucher x/net, stdlib et un paquet Maven.
var fixTypes = set("manifest", EvidenceFixedIn, EvidenceNoFix, EvidenceEcosystem, EvidenceTargetVersion, EvidenceCommand)

// cmpVersion compare deux versions, avec ou sans « v »: a la semver pour
// l'essentiel, les metadonnees de build (+...) ignorees, les identifiants de
// pre-version numeriques compares en nombres. Une version sans pre-version
// passe devant la meme avec (-rc1). Un suffixe a la Python (1.2rc1, 1.2.dev1,
// 1.2.post1) se range avant le nombre seul, dev avant a, b et rc, sauf post
// qui vient apres. Les qualificatifs Maven de version publiee (.Final,
// .RELEASE, -GA) valent la version seule.
func cmpVersion(a, b string) int {
	a, b = releaseOnly(a), releaseOnly(b)
	ma, pa, _ := strings.Cut(a, "-")
	mb, pb, _ := strings.Cut(b, "-")
	sa, sb := versionParts(ma), versionParts(mb)
	for i := 0; i < max(len(sa), len(sb)); i++ {
		var x, y string
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		if c := cmpPart(x, y); c != 0 {
			return c
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return cmpPre(pa, pb)
}

// versionCmp rend la comparaison qui convient a un ecosysteme: PEP 440 pour
// PyPI, cmpVersion sinon.
func versionCmp(eco string) func(a, b string) int {
	if strings.EqualFold(eco, "pypi") {
		return cmpPEP440
	}
	return cmpVersion
}

// pep440Re lit une version Python: epoque, nombres, pre-version (a, b, rc),
// post-version, version de developpement. Les ecritures admises par PEP 440
// (alpha, beta, c, pre, preview, rev, r, separateurs . _ -) y sont comprises.
var pep440Re = regexp.MustCompile(`^(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?$`)

// pep440Key est la cle de tri de PEP 440. Une version de developpement sans
// pre ni post-version passe avant toute pre-version, une version sans
// pre-version apres toutes, sans post-version avant toutes, sans dev apres.
type pep440Key struct {
	epoch   int
	release []int
	pre     [2]int // phase (-1 dev seule, 0 a, 1 b, 2 rc, 3 aucune), numero
	post    int    // -1 aucune
	dev     int    // 1<<30 aucune
}

func parsePEP440(v string) (pep440Key, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "+")
	m := pep440Re.FindStringSubmatch(v)
	if m == nil {
		return pep440Key{}, false
	}
	num := func(s string) int { n, _ := strconv.Atoi(s); return n }
	k := pep440Key{epoch: num(m[1]), pre: [2]int{3, 0}, post: -1, dev: 1 << 30}
	for _, p := range strings.Split(m[2], ".") {
		k.release = append(k.release, num(p))
	}
	switch m[3] {
	case "a", "alpha":
		k.pre = [2]int{0, num(m[4])}
	case "b", "beta":
		k.pre = [2]int{1, num(m[4])}
	case "c", "rc", "pre", "preview":
		k.pre = [2]int{2, num(m[4])}
	}
	switch {
	case m[5] != "":
		k.post = num(m[5])
	case m[6] != "":
		k.post = num(m[7])
	}
	if m[8] != "" {
		k.dev = num(m[9])
		if m[3] == "" && k.post < 0 {
			k.pre = [2]int{-1, 0}
		}
	}
	return k, true
}

// cmpPEP440 compare deux versions Python selon PEP 440, ou comme cmpVersion
// si l'une ne s'y lit pas.
func cmpPEP440(a, b string) int {
	ka, oka := parsePEP440(a)
	kb, okb := parsePEP440(b)
	if !oka || !okb {
		return cmpVersion(a, b)
	}
	cmp := func(x, y int) int {
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
	if c := cmp(ka.epoch, kb.epoch); c != 0 {
		return c
	}
	for i := 0; i < max(len(ka.release), len(kb.release)); i++ {
		var x, y int
		if i < len(ka.release) {
			x = ka.release[i]
		}
		if i < len(kb.release) {
			y = kb.release[i]
		}
		if c := cmp(x, y); c != 0 {
			return c
		}
	}
	for _, c := range []int{cmp(ka.pre[0], kb.pre[0]), cmp(ka.pre[1], kb.pre[1]), cmp(ka.post, kb.post), cmp(ka.dev, kb.dev)} {
		if c != 0 {
			return c
		}
	}
	return 0
}

// releaseOnly retire le « v », les metadonnees de build et un qualificatif
// Maven de version publiee.
func releaseOnly(v string) string {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "+")
	return mavenRelease.ReplaceAllString(v, "")
}

var mavenRelease = regexp.MustCompile(`(?i)[.-](final|release|ga)$`)

// versionParts coupe une version en nombres. Un element qui commence par une
// lettre (1.2.dev1, 1.0.Beta1) se rattache au nombre d'avant: c'est son
// suffixe, pas un nombre de plus.
func versionParts(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ".") {
		if len(out) > 0 && p != "" && (p[0] < '0' || p[0] > '9') {
			out[len(out)-1] += p
			continue
		}
		out = append(out, p)
	}
	return out
}

// cmpPart compare un element de version: le nombre de tete, puis un suffixe
// eventuel (rc1, post1).
func cmpPart(x, y string) int {
	nx, rx := leadingNumber(x)
	ny, ry := leadingNumber(y)
	if nx != ny {
		if nx < ny {
			return -1
		}
		return 1
	}
	rank := func(r string) int {
		r = strings.ToLower(strings.TrimLeft(r, "._-"))
		switch {
		case r == "":
			return 2
		case strings.HasPrefix(r, "post"):
			return 3
		case strings.HasPrefix(r, "dev"):
			return 0
		}
		return 1
	}
	if kx, ky := rank(rx), rank(ry); kx != ky {
		if kx < ky {
			return -1
		}
		return 1
	}
	return cmpPre(rx, ry)
}

// cmpPre compare deux pre-versions identifiant par identifiant: un nombre
// contre un nombre en valeur, un nombre passe avant un mot, le plus court
// avant le plus long a egalite.
func cmpPre(a, b string) int {
	if a == b {
		return 0
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < min(len(pa), len(pb)); i++ {
		x, errx := strconv.Atoi(pa[i])
		y, erry := strconv.Atoi(pb[i])
		switch {
		case errx == nil && erry == nil:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		case errx == nil:
			return -1
		case erry == nil:
			return 1
		default:
			nx, rx := leadingNumber(strings.TrimLeft(pa[i], "abcdefghijklmnopqrstuvwxyz"))
			ny, ry := leadingNumber(strings.TrimLeft(pb[i], "abcdefghijklmnopqrstuvwxyz"))
			if wx, wy := strings.TrimRight(pa[i], "0123456789"), strings.TrimRight(pb[i], "0123456789"); wx != wy {
				if wx < wy {
					return -1
				}
				return 1
			}
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
			if rx != ry {
				if rx < ry {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// leadingNumber rend le nombre en tete de s et le reste.
func leadingNumber(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n, _ := strconv.Atoi(s[:i])
	return n, s[i:]
}

// depKey designe une copie d'une dependance: son ecosysteme, son nom, le
// manifeste qui la declare et sa version en place. Un go.mod n'a qu'une
// version de chaque module, la plus haute demandee (MVS): pour Go, la version
// n'en fait pas partie. osv-scanner lit celle ecrite dans go.mod, govulncheck
// celle retenue au build, et deux go get dans le meme go.mod se
// contrediraient.
type depKey struct{ eco, name, manifest, version string }

// depKeys rend les copies d'une dependance que porte un constat, une par
// manifeste.
func depKeys(f finding.Finding) []depKey {
	eco := depEcosystem(f)
	name, version := depModule(f), depVersion(f)
	if eco == "go" {
		version = ""
	}
	var ks []depKey
	for _, m := range evidenceValues(f, "manifest") {
		ks = append(ks, depKey{eco, normName(eco, name), m, version})
	}
	return ks
}

// fixCommands pose sur chaque constat de dependance, avant la fusion, tant
// que chacun ne parle que d'un paquet, la version cible de chacune de ses
// copies et les commandes qui y passent. Une vulnerabilite sans version
// corrigee ne compte pas: la page le dit a part.
func fixCommands(fs []finding.Finding) {
	target := map[depKey]string{}
	for _, f := range fs {
		if !published(f) {
			continue
		}
		for _, k := range depKeys(f) {
			cmp := versionCmp(k.eco)
			for _, v := range evidenceValues(f, EvidenceFixedIn) {
				if target[k] == "" || cmp(v, target[k]) > 0 {
					target[k] = v
				}
			}
		}
	}
	for i := range fs {
		f := &fs[i]
		if !published(*f) {
			continue
		}
		for _, k := range depKeys(*f) {
			v := target[k]
			if v == "" || k.name == "" {
				continue
			}
			addEvidence(f, EvidenceTargetVersion, strings.TrimPrefix(v, "v"))
			for _, cmd := range upgradeCommands(k.eco, k.manifest, depModule(*f), k.version, v) {
				addEvidence(f, EvidenceCommand, cmd)
			}
		}
	}
}

// unusedFixes remplace, pour une dependance que rien n'importe, la mise a
// jour par go mod tidy dans chacun de ses modules: elle se retire.
func unusedFixes(fs []finding.Finding) {
	for i := range fs {
		f := &fs[i]
		if !published(*f) || !hasContext(*f, ContextUnused) {
			continue
		}
		kept := f.Evidence[:0:0]
		for _, e := range f.Evidence {
			if e.Type != EvidenceTargetVersion && e.Type != EvidenceCommand {
				kept = append(kept, e)
			}
		}
		f.Evidence = kept
		for _, m := range evidenceValues(*f, "manifest") {
			if path.Base(m) == "go.mod" {
				if c := goCommand(m, "mod tidy"); c != "" {
					addEvidence(f, EvidenceCommand, c)
				}
			}
		}
	}
}

// upgradeCommands ecrit les commandes qui passent name, en version current
// dans manifest, a version. Elles ne sont jamais executees par Quaero: elles
// s'affichent, a relire. Une commande n'est ecrite que si elle change le
// depot lui-meme, pour un manifeste qu'elle sait lire:
//   - go.mod: go get, puis go mod tidy, dans le dossier du module;
//   - package-lock.json: npm update, qui reste dans les versions que permet
//     package.json, et monte aussi une dependance indirecte sans l'ajouter
//     aux directes;
//   - Cargo.lock: cargo update de cette copie seulement.
//
// pip, yarn, pnpm ou poetry n'en ont pas: la version cible suffit, la
// commande depend de l'outil du projet. stdlib n'en a pas non plus, elle
// depend de la version de Go qui compile.
func upgradeCommands(ecosystem, manifest, name, current, version string) []string {
	version = strings.TrimPrefix(version, "v")
	dir := manifestDir(manifest)
	// Le nom, les versions et le dossier viennent du depot analyse: une
	// commande n'est ecrite que s'ils ne peuvent rien glisser dans un shell.
	if !shellSafe(name) || !shellSafe(version) || !shellSafe(current) || !shellSafe(dir) {
		return nil
	}
	base := path.Base(path.Clean(manifest))
	switch strings.ToLower(ecosystem) {
	case "go":
		if name == "stdlib" || name == "toolchain" || base != "go.mod" {
			return nil
		}
		return []string{goCommand(manifest, "get "+name+"@v"+version), goCommand(manifest, "mod tidy")}
	case "npm":
		if base != "package-lock.json" && base != "npm-shrinkwrap.json" {
			return nil
		}
		c := "npm update"
		if dir != "" {
			c += " --prefix " + dir
		}
		return []string{c + " " + name}
	case "crates.io":
		if (base != "Cargo.lock" && base != "Cargo.toml") || current == "" {
			return nil
		}
		c := "cargo update -p " + name + "@" + current + " --precise " + version
		if dir != "" {
			c += " --manifest-path " + dir + "/Cargo.toml"
		}
		return []string{c}
	}
	return nil
}

// goCommand ecrit une commande go lancee dans le dossier du go.mod: go -C s'y
// place, sans changer de dossier a la main.
func goCommand(manifest, args string) string {
	dir := manifestDir(manifest)
	if !shellSafe(dir) {
		return ""
	}
	if dir != "" {
		return "go -C " + dir + " " + args
	}
	return "go " + args
}

// shellSafeRe borne ce qu'une commande affichee peut porter: lettres, chiffres
// et les signes des noms de modules et de paquets, sans espace ni guillemet.
var shellSafeRe = regexp.MustCompile(`^[A-Za-z0-9._@/+-]*$`)

func shellSafe(s string) bool {
	return shellSafeRe.MatchString(s) && !strings.HasPrefix(s, "-")
}

// manifestDir rend le dossier d'un manifeste relatif au depot, ou "" pour la
// racine.
func manifestDir(manifest string) string {
	if manifest == "" {
		return ""
	}
	dir := path.Dir(path.Clean(manifest))
	if dir == "." || dir == "/" {
		return ""
	}
	return dir
}

// normName ramene un nom de paquet a la forme sous laquelle deux ecritures
// designent le meme: PyPI ne distingue ni la casse ni - _ . (PEP 503).
func normName(eco, name string) string {
	if strings.EqualFold(eco, "pypi") {
		return strings.ToLower(pypiSep.ReplaceAllString(name, "-"))
	}
	return name
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// depEcosystem rend l'ecosysteme d'un constat de dependance, en minuscules.
func depEcosystem(f finding.Finding) string {
	if e := evidenceValues(f, EvidenceEcosystem); len(e) > 0 {
		return strings.ToLower(e[0])
	}
	return ""
}

// depIdentity nomme le paquet d'un constat de dependance, ou "" pour un
// constat de code: deux constats ne se fusionnent que pour le meme paquet.
func depIdentity(f finding.Finding) string {
	if f.Target == nil || (f.Target.Type != "dependency" && !strings.HasPrefix(f.ID, "QRO-VULN-")) {
		return ""
	}
	eco := depEcosystem(f)
	return eco + ":" + normName(eco, depModule(f))
}

// sameDependency dit si deux constats parlent du meme paquet: meme nom, et
// meme ecosysteme quand les deux le disent.
func sameDependency(a, b finding.Finding) bool {
	ea, eb := evidenceValues(a, EvidenceEcosystem), evidenceValues(b, EvidenceEcosystem)
	eco := ""
	if len(ea) > 0 {
		eco = ea[0]
	}
	if len(ea) > 0 && len(eb) > 0 && !strings.EqualFold(ea[0], eb[0]) {
		return false
	}
	return normName(eco, depModule(a)) == normName(eco, depModule(b))
}

// depModule rend le nom d'une dependance, sans sa version.
func depModule(f finding.Finding) string {
	if f.Target == nil {
		return ""
	}
	id := f.Target.Identifier
	if i := strings.LastIndexByte(id, '@'); i > 0 {
		id = id[:i]
	}
	return id
}

// depVersion rend la version en place d'une dependance, sans « v » ni « go ».
func depVersion(f finding.Finding) string {
	if f.Target == nil {
		return ""
	}
	id := f.Target.Identifier
	i := strings.LastIndexByte(id, '@')
	if i <= 0 {
		return ""
	}
	v := id[i+1:]
	for _, p := range []string{"go", "v"} {
		if strings.HasPrefix(v, p) && len(v) > len(p) && v[len(p)] >= '0' && v[len(p)] <= '9' {
			v = v[len(p):]
		}
	}
	return v
}

func addEvidence(f *finding.Finding, kind, data string) {
	if !hasEvidence(*f, kind, data) {
		f.Evidence = append(f.Evidence, finding.Evidence{Type: kind, Data: data})
	}
}

func evidenceValues(f finding.Finding, kind string) []string {
	var out []string
	for _, e := range f.Evidence {
		if e.Type == kind && e.Data != "" {
			out = append(out, e.Data)
		}
	}
	return out
}

func hasEvidence(f finding.Finding, kind, data string) bool {
	for _, e := range f.Evidence {
		if e.Type == kind && e.Data == data {
			return true
		}
	}
	return false
}
