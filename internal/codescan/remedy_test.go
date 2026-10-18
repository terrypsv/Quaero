// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/terrypsv/Quaero/internal/finding"
)

func evidenceOf(f finding.Finding, kind string) []string { return evidenceValues(f, kind) }

// Le guide remplace le conseil general, et l'annotation suit chaque moteur qui
// a releve la ligne: une seule ne tairait pas l'autre.
func TestRemedeDuGuide(t *testing.T) {
	sg := codeAt("QRO-SEMGREP-exec", "util.go:27", "semgrep", finding.SeverityHigh, "CWE-94")
	sg.Title = "dangerous-exec-command: Detected non-static command"
	sg.Evidence = append(sg.Evidence, finding.Evidence{Type: "rule", Data: "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command"})
	gs := codeAt("QRO-GOSEC-G204", "util.go:27", "gosec", finding.SeverityMedium, "CWE-78")
	gs.Title = "G204: Subprocess launched with variable"
	path := codeAt("QRO-GOSEC-G304", "a.go:3", "gosec", finding.SeverityMedium, "CWE-22")
	path.Title = "G304: Potential file inclusion via variable"
	other := codeAt("QRO-SEMGREP-x", "b.py:1", "semgrep", finding.SeverityLow, "")
	other.Title = "regle-inconnue: x"
	other.Remediation = "conseil general"
	other.Evidence = append(other.Evidence, finding.Evidence{Type: "rule", Data: "python.x.regle-inconnue"})

	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{},
		fakeScanner{name: "semgrep", available: true, findings: []finding.Finding{sg, other}},
		fakeScanner{name: "gosec", available: true, findings: []finding.Finding{gs, path}})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]finding.Finding{}
	for _, f := range rep.Findings {
		by[f.Target.Identifier] = f
	}
	exec := by["util.go:27"]
	if !strings.Contains(exec.Remediation, "sans passer par un shell") {
		t.Errorf("remede exec: %q", exec.Remediation)
	}
	if exc := strings.Join(evidenceOf(exec, EvidenceException), ""); !strings.Contains(exc, "#nosec G204") ||
		!strings.Contains(exc, "nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command") {
		t.Errorf("annotations du constat fusionne: %q", exc)
	}
	if !strings.Contains(by["a.go:3"].Remediation, "os.OpenRoot") {
		t.Errorf("remede G304: %q", by["a.go:3"].Remediation)
	}
	if f := by["b.py:1"]; f.Remediation != "conseil general" || len(evidenceOf(f, EvidenceException)) != 0 {
		t.Errorf("regle inconnue touchee: %+v", f)
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.35.0", "v0.35.0", 0}, {"0.9.0", "0.10.0", -1}, {"1.25.4", "1.25", 1},
		{"1.0.0-rc1", "1.0.0", -1}, {"2.0.0", "1.99.99", 1}, {"0.0.0-2024", "0.0.0-2023", 1},
		{"1.0.0-rc.10", "1.0.0-rc.9", 1}, {"1.0.0-rc10", "1.0.0-rc9", 1}, {"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, {"1.2rc1", "1.1", 1}, {"1.2rc1", "1.2", -1},
		{"1.2.post1", "1.2", 1}, {"1.2.3+build-7", "1.2.3", 0}, {"4.1.100.Final", "4.1.99.Final", 1},
		{"0.0.0-20240102000000-abc", "0.0.0-20240101000000-def", 1},
		{"1.2.dev1", "1.2a1", -1}, {"1.2a1", "1.2b1", -1}, {"1.2.3.Final", "1.2.3", 0},
		{"1.0.Beta1", "1.0", -1}, {"5.3.0.RELEASE", "5.2.9.RELEASE", 1}, {"1.2.post1", "1.3.dev1", -1},
	} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmpVersion(%q, %q) = %d, attendu %d", c.a, c.b, got, c.want)
		}
	}
}

// La version corrigee vient de la base OSV, la plus haute des failles d'une
// dependance donne la commande, lancee dans le dossier de son go.mod.
func TestCommandeDeMiseAJour(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"cmd/x/go.mod"},"packages":[
 {"package":{"name":"golang.org/x/net","version":"0.35.0","ecosystem":"Go"},"vulnerabilities":[
  {"id":"GO-1","affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.33.0"},{"introduced":"0.34.0"},{"fixed":"0.36.0"}]}]}]},
  {"id":"GO-2","affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.38.0"}]}]}]},
  {"id":"GO-3","affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}]},
 {"package":{"name":"stdlib","version":"1.25","ecosystem":"Go"},"vulnerabilities":[
  {"id":"GO-4","affected":[{"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.25.4"}]}]}]}]}]},
 {"source":{"path":"web/package-lock.json"},"packages":[
 {"package":{"name":"lodash","version":"4.17.4","ecosystem":"npm"},"vulnerabilities":[
  {"id":"GHSA-1","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}]}]}]}`)
	fs, err := parseOSV(raw)
	if err != nil {
		t.Fatal(err)
	}
	fixCommands(fs)
	by := map[string]finding.Finding{}
	for _, f := range fs {
		by[f.References[0].ID] = f
	}
	if got := evidenceOf(by["GO-1"], EvidenceFixedIn); !reflect.DeepEqual(got, []string{"0.36.0"}) {
		t.Errorf("GO-1 corrige en %v", got)
	}
	if !strings.Contains(by["GO-3"].Remediation, "Aucune version corrigee") {
		t.Errorf("GO-3: %q", by["GO-3"].Remediation)
	}
	want := []string{"go -C cmd/x get golang.org/x/net@v0.38.0", "go -C cmd/x mod tidy"}
	for _, id := range []string{"GO-1", "GO-2", "GO-3"} {
		if got := evidenceOf(by[id], EvidenceCommand); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: commandes %v", id, got)
		}
		if got := evidenceOf(by[id], EvidenceTargetVersion); !reflect.DeepEqual(got, []string{"0.38.0"}) {
			t.Errorf("%s: version cible %v", id, got)
		}
	}
	if got := evidenceOf(by["GO-4"], EvidenceCommand); len(got) != 0 || !reflect.DeepEqual(evidenceOf(by["GO-4"], EvidenceTargetVersion), []string{"1.25.4"}) {
		t.Errorf("stdlib: %v %v", got, evidenceOf(by["GO-4"], EvidenceTargetVersion))
	}
	if got := evidenceOf(by["GHSA-1"], EvidenceCommand); !reflect.DeepEqual(got, []string{"npm update --prefix web lodash"}) {
		t.Errorf("npm: %v", got)
	}
	if !hasEvidence(by["GO-3"], EvidenceNoFix, "oui") || hasEvidence(by["GO-1"], EvidenceNoFix, "oui") {
		t.Errorf("sans correctif mal pose")
	}
}

// La correction proposee par une regle semgrep est gardee.
func TestCorrectionSemgrep(t *testing.T) {
	raw := []byte(`{"results":[{"check_id":"go.x.y","path":"a.go","start":{"line":2},"end":{"line":2},"extra":{"message":"m","severity":"WARNING","lines":"md5.New()","fix":"sha256.New()"}}]}`)
	fs, err := parseSemgrep(raw)
	if err != nil || len(fs) != 1 || !reflect.DeepEqual(evidenceOf(fs[0], EvidenceSuggestedFix), []string{"sha256.New()"}) {
		t.Errorf("%v %+v", err, fs)
	}
}

// L'annotation suit la syntaxe des commentaires du fichier signale.
func TestAnnotationSelonLeLangage(t *testing.T) {
	for file, want := range map[string]string{
		"a.go:3":                     "« // nosemgrep: r.x » sur la ligne d'avant",
		"tools/b.py:12:4":            "« # nosemgrep: r.x » sur la ligne d'avant",
		".github/workflows/ci.yml:8": "« # nosemgrep: r.x » sur la ligne d'avant",
		"docker/Dockerfile:1":        "« # nosemgrep: r.x » sur la ligne d'avant",
		"web/index.html:40":          "« <!-- nosemgrep: r.x --> » sur la ligne d'avant",
		"db/schema.sql:3":            "« -- nosemgrep: r.x » sur la ligne d'avant",
		"ui/App.tsx:9":               "« // nosemgrep: r.x » sur la ligne d'avant, ou « {/* nosemgrep: r.x */} » dans du JSX",
		"ui/Page.vue:4":              "« // nosemgrep: r.x » sur la ligne d'avant dans le script, ou « <!-- nosemgrep: r.x --> » dans le gabarit",
		`C:\depot\src\main.rs:2`:     "« // nosemgrep: r.x » sur la ligne d'avant",
	} {
		f := codeAt("QRO-SEMGREP-x", file, "semgrep", finding.SeverityLow, "")
		f.Evidence = append(f.Evidence, finding.Evidence{Type: "rule", Data: "r.x"})
		if _, notes, _ := remedyOf(f); len(notes) != 1 || notes[0] != want {
			t.Errorf("%s: %v", file, notes)
		}
	}
}

// Une dependance que rien n'importe se retire: go mod tidy dans son module, pas
// de mise a jour.
func TestCommandeDependanceInutilisee(t *testing.T) {
	f := finding.Finding{ID: "QRO-VULN-GO-1", Target: &finding.Target{Type: "dependency", Identifier: "golang.org/x/net@0.35.0"},
		References: []finding.Reference{{Framework: "OSV", ID: "GO-1"}},
		Evidence:   []finding.Evidence{{Type: "manifest", Data: "cmd/x/go.mod"}, {Type: EvidenceEcosystem, Data: "Go"}, {Type: EvidenceFixedIn, Data: "0.38.0"}}}
	fs := []finding.Finding{f}
	fixCommands(fs)
	if got := evidenceOf(fs[0], EvidenceCommand); len(got) != 2 {
		t.Fatalf("avant le tri: %v", got)
	}
	addContext(&fs[0], ContextUnused)
	unusedFixes(fs)
	if got := evidenceOf(fs[0], EvidenceCommand); !reflect.DeepEqual(got, []string{"go -C cmd/x mod tidy"}) {
		t.Errorf("commandes %v", got)
	}
	if got := evidenceOf(fs[0], EvidenceTargetVersion); len(got) != 0 {
		t.Errorf("version cible %v", got)
	}
}

// Le nom, la version et le dossier viennent du depot: rien qui puisse glisser
// une commande dans un shell n'est ecrit. Une commande n'est ecrite que pour un
// manifeste qu'elle sait mettre a jour.
func TestCommandeSansCaractereDeShell(t *testing.T) {
	for _, c := range [][5]string{
		{"npm", "web/package-lock.json", "lodash; rm -rf ~", "4.17.4", "4.17.21"},
		{"npm", "web/package-lock.json", "lodash", "4.17.4", "4.17.21$(id)"},
		{"npm", "we b/$(id)/package-lock.json", "lodash", "4.17.4", "4.17.21"},
		{"npm", "package-lock.json", "--registry=http://x", "1.0.0", "1.0.1"},
		{"npm", "web/yarn.lock", "lodash", "4.17.4", "4.17.21"},
		{"Go", "web/pom.xml", "golang.org/x/net", "0.35.0", "0.38.0"},
		{"Go", "go.mod", "stdlib", "1.25", "1.25.4"},
		{"PyPI", "requirements.txt", "django", "4.2.0", "4.2.16"},
		{"crates.io", "Cargo.lock", "serde", "", "1.0.200"},
	} {
		if got := upgradeCommands(c[0], c[1], c[2], c[3], c[4]); got != nil {
			t.Errorf("%v: %v", c, got)
		}
	}
	if got := upgradeCommands("Go", "go.mod", "golang.org/x/net", "0.35.0", "v0.38.0"); !reflect.DeepEqual(got, []string{"go get golang.org/x/net@v0.38.0", "go mod tidy"}) {
		t.Errorf("racine: %v", got)
	}
	if got := upgradeCommands("crates.io", "rust/Cargo.lock", "serde", "1.0.100", "1.0.200"); !reflect.DeepEqual(got, []string{"cargo update -p serde@1.0.100 --precise 1.0.200 --manifest-path rust/Cargo.toml"}) {
		t.Errorf("cargo: %v", got)
	}
}

// Deux copies d'un paquet sur deux branches ont chacune leur version cible:
// 5.7.1 ne monte pas en 6.x.
func TestVersionCibleParBranche(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"package-lock.json"},"packages":[
 {"package":{"name":"semver","version":"5.7.1","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-c2qf","affected":[{"package":{"name":"semver","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.7.2"},{"introduced":"6.0.0"},{"fixed":"6.3.1"},{"introduced":"7.0.0"},{"fixed":"7.5.2"}]}]}]}]},
 {"package":{"name":"semver","version":"6.3.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-c2qf","affected":[{"package":{"name":"semver","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.7.2"},{"introduced":"6.0.0"},{"fixed":"6.3.1"},{"introduced":"7.0.0"},{"fixed":"7.5.2"}]}]}]}]}]}]}`)
	fs, err := parseOSV(raw)
	if err != nil || len(fs) != 2 {
		t.Fatal(err, len(fs))
	}
	fixCommands(fs)
	for i, want := range []string{"5.7.2", "6.3.1"} {
		if got := evidenceOf(fs[i], EvidenceTargetVersion); !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("%s: version cible %v, attendu %s", fs[i].Target.Identifier, got, want)
		}
	}
}

// Une meme CVE touche x/net, stdlib et un paquet Maven: la fusion ne melange
// pas leurs versions ni leurs commandes.
func TestFusionSansMelangeDePaquets(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[
 {"package":{"name":"golang.org/x/net","version":"0.10.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2023-2102","aliases":["CVE-2023-44487"],"affected":[
   {"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]},
   {"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.21.3"}]}]}]}]},
 {"package":{"name":"stdlib","version":"1.21.0","ecosystem":"Go"},"vulnerabilities":[{"id":"GO-2023-2102","aliases":["CVE-2023-44487"],"affected":[
   {"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]},
   {"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.21.3"}]}]}]}]}]},
 {"source":{"path":"web/pom.xml"},"packages":[
 {"package":{"name":"io.netty:netty-codec-http2","version":"4.1.99.Final","ecosystem":"Maven"},"vulnerabilities":[{"id":"GHSA-xpw8-rcwv-8f8p","aliases":["CVE-2023-44487"],"affected":[
   {"package":{"name":"io.netty:netty-codec-http2","ecosystem":"Maven"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.1.100.Final"}]}]}]}]}]}]}`)
	fs, err := parseOSV(raw)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunWith(context.Background(), t.TempDir(), "test", Options{},
		fakeScanner{name: "osv-scanner", available: true, findings: fs})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]finding.Finding{}
	for _, f := range rep.Findings {
		if published(f) {
			by[depModule(f)] = f
		}
	}
	if len(by) != 3 {
		t.Fatalf("un constat par paquet attendu: %v", by)
	}
	for name, want := range map[string]struct {
		target   string
		commands []string
		manifest string
	}{
		"golang.org/x/net":           {"0.17.0", []string{"go get golang.org/x/net@v0.17.0", "go mod tidy"}, "go.mod"},
		"stdlib":                     {"1.21.3", nil, "go.mod"},
		"io.netty:netty-codec-http2": {"4.1.100.Final", nil, "web/pom.xml"},
	} {
		f := by[name]
		if got := evidenceOf(f, EvidenceTargetVersion); !reflect.DeepEqual(got, []string{want.target}) {
			t.Errorf("%s: version cible %v", name, got)
		}
		if got := evidenceOf(f, EvidenceCommand); !reflect.DeepEqual(got, want.commands) {
			t.Errorf("%s: commandes %v", name, got)
		}
		if got := evidenceOf(f, "manifest"); !reflect.DeepEqual(got, []string{want.manifest}) {
			t.Errorf("%s: manifestes %v", name, got)
		}
	}
}

// govulncheck releve une meme entree dans deux modules: chacun garde son
// constat. Sans version corrigee, l'entree dit s'il n'y en a pas de publiee;
// un fork qu'elle ne decrit pas n'en dit rien.
func TestGovulncheckUnConstatParModule(t *testing.T) {
	raw := []byte(`{"osv":{"id":"GO-1","summary":"s","affected":[
 {"package":{"name":"golang.org/x/sys","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.31.0"}]}]},
 {"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},
 {"package":{"name":"github.com/foo/bar","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]}]}}
{"finding":{"osv":"GO-1","fixed_version":"v0.31.0","trace":[{"module":"golang.org/x/sys","version":"v0.30.0"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"stdlib","version":"v1.25.0","package":"net/http","function":"Get","position":{"filename":"main.go","line":3}}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"github.com/acme/bar","version":"v1.2.3"}]}}
`)
	fs, err := interpretGovulncheck(toolResult{stdout: raw})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]finding.Finding{}
	for _, f := range fs {
		by[depModule(f)] = f
	}
	if len(fs) != 3 {
		t.Fatalf("%d constats: %+v", len(fs), fs)
	}
	if got := evidenceOf(by["golang.org/x/sys"], EvidenceFixedIn); !reflect.DeepEqual(got, []string{"0.31.0"}) {
		t.Errorf("x/sys: %v", got)
	}
	if !hasEvidence(by["stdlib"], EvidenceNoFix, "oui") || !hasContext(by["stdlib"], ContextCalled) {
		t.Errorf("stdlib: %+v", by["stdlib"].Evidence)
	}
	if f := by["github.com/acme/bar"]; hasEvidence(f, EvidenceNoFix, "oui") || !strings.Contains(f.Remediation, "inconnue") {
		t.Errorf("fork dit sans correctif: %q", f.Remediation)
	}
}

// Dans un go.mod, osv-scanner lit la version ecrite et govulncheck celle du
// build: une seule commande, a la plus haute des versions cibles.
func TestUnGoGetParGoMod(t *testing.T) {
	dep := func(id, ident, fixed string) finding.Finding {
		return finding.Finding{ID: id, Target: &finding.Target{Type: "dependency", Identifier: ident},
			References: []finding.Reference{{Framework: "OSV", ID: id}},
			Evidence:   []finding.Evidence{{Type: "manifest", Data: "a/go.mod"}, {Type: EvidenceEcosystem, Data: "Go"}, {Type: EvidenceFixedIn, Data: fixed}}}
	}
	fs := []finding.Finding{dep("GO-1", "golang.org/x/net@0.15.0", "0.17.0"), dep("GO-2", "golang.org/x/net@v0.18.0", "0.19.0")}
	fixCommands(fs)
	for _, f := range fs {
		if got := evidenceOf(f, EvidenceCommand); !reflect.DeepEqual(got, []string{"go -C a get golang.org/x/net@v0.19.0", "go -C a mod tidy"}) {
			t.Errorf("%s: %v", f.ID, got)
		}
	}
}

// PyPI ne distingue ni la casse ni - _ . dans un nom: Django et django sont le
// meme paquet. Un paquet absent de la base ne se dit pas sans correctif.
func TestNomPyPINormalise(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"requirements.txt"},"packages":[
 {"package":{"name":"django","version":"4.2.0","ecosystem":"PyPI"},"vulnerabilities":[{"id":"PYSEC-1","affected":[{"package":{"name":"Django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.16"}]}]}]}]},
 {"package":{"name":"zope.interface","version":"5.0","ecosystem":"PyPI"},"vulnerabilities":[{"id":"PYSEC-2","affected":[{"package":{"name":"autre","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.0"}]}]}]}]}]}]}`)
	fs, err := parseOSV(raw)
	if err != nil || len(fs) != 2 {
		t.Fatal(err)
	}
	if got := evidenceOf(fs[0], EvidenceFixedIn); !reflect.DeepEqual(got, []string{"4.2.16"}) {
		t.Errorf("django corrige en %v", got)
	}
	if hasEvidence(fs[1], EvidenceNoFix, "oui") || len(evidenceOf(fs[1], EvidenceFixedIn)) != 0 || strings.Contains(fs[1].Remediation, "Aucune") {
		t.Errorf("paquet absent de la base: %+v", fs[1])
	}
}

// PyPI se range selon PEP 440: l'ordre de l'exemple de la norme.
func TestOrdrePEP440(t *testing.T) {
	order := []string{"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
		"1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0.post456.dev34", "1.0.post456",
		"1.0.15", "1.1.dev1", "1!0.5"}
	for i := range order {
		for j := range order {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := cmpPEP440(order[i], order[j]); got != want {
				t.Errorf("cmpPEP440(%q, %q) = %d, attendu %d", order[i], order[j], got, want)
			}
		}
	}
	if cmpPEP440("1.0+abc.5", "1.0") != 0 || cmpPEP440("1.0-1", "1.0.post1") != 0 || cmpPEP440("1.0.0", "1.0") != 0 {
		t.Error("ecritures equivalentes")
	}
}
