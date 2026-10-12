// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package codescan

import "context"

// Analyser du code tiers n'est pas sans risque: govulncheck charge le graphe
// des paquets, ce qui compile le code source analyse. La compilation elle-meme
// n'execute rien, mais deux chemins detournes le peuvent, et un depot hostile
// peut les armer. Ce fichier les ferme pour un scan marque non fiable.
//
// Ce n'est pas une isolation complete. Le bac a sable d'execution (conteneur ou
// VM) reste a faire, et pour du code vraiment douteux il faut scanner dans une
// machine jetable. Ce durcissement retire les armes les plus simples, il ne
// remplace pas une cloison.

// hardenedEnv rend les variables d'environnement a imposer aux moteurs pour un
// depot non fiable. Elles s'ajoutent a l'environnement du processus, en der-
// niere position, donc elles gagnent.
func hardenedEnv() []string {
	return []string{
		// Un go.mod hostile peut demander une autre chaine d'outils Go, que
		// `go` telechargerait puis executerait. local l'en empeche: seule la
		// chaine deja installee tourne.
		"GOTOOLCHAIN=local",
		// cgo invoque le compilateur C sur du code C du depot. Coupe, aucun
		// compilateur C n'est lance sur la cible.
		"CGO_ENABLED=0",
		// Pas d'invite de mot de passe qui bloquerait un scan sans surveillance.
		"GIT_TERMINAL_PROMPT=0",
		// Tolere un go.sum incomplet plutot que d'echouer avant d'analyser.
		"GOFLAGS=-mod=mod",
	}
}

type envKey struct{}

// withScanEnv attache a ctx les variables a imposer aux moteurs. runTool les
// lit et les applique au sous-processus.
func withScanEnv(ctx context.Context, env []string) context.Context {
	if len(env) == 0 {
		return ctx
	}
	return context.WithValue(ctx, envKey{}, env)
}

// scanEnv rend les variables attachees a ctx, ou nil.
func scanEnv(ctx context.Context) []string {
	env, _ := ctx.Value(envKey{}).([]string)
	return env
}
