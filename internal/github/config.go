// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package github

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// configName is the file the token is remembered in, under the user's home.
const configDir = ".quaero"
const configFile = "config.json"

type storedConfig struct {
	Token string `json:"token"`
}

// ConfigPath returns where the token is kept.
func ConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("repertoire personnel introuvable: %w", err)
	}
	return filepath.Join(home, configDir, configFile), nil
}

// SaveToken writes the token to the config file with owner-only permissions.
//
// A credential written world-readable is a credential shared with every
// process on the machine. On Unix the mode is enforced; on Windows the file
// inherits the profile directory's protection, which is user-scoped by
// default, and the difference is stated rather than glossed over.
func SaveToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("jeton vide")
	}

	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("creation du repertoire de configuration: %w", err)
	}

	payload, err := json.MarshalIndent(storedConfig{Token: token}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("ecriture de la configuration: %w", err)
	}

	// The write above sets the mode at creation, but an existing file keeps
	// its own; forcing it closes that gap.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return path, fmt.Errorf("le jeton est enregistre mais les permissions n'ont pas pu etre restreintes: %w", err)
		}
	}
	return path, nil
}

// LoadToken reads the stored token, returning an empty string when none is
// stored. A missing file is not an error: it is the normal first run.
func LoadToken() string {
	path, err := ConfigPath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg storedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Token)
}

// ForgetToken removes the stored credential.
func ForgetToken() (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return path, err
	}
	return path, nil
}
