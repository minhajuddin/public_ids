package publicid

import (
	"fmt"
	"os"
)

// LoadKeyManifestFile reads and parses a JSON key manifest from a file. The
// key material is validated later, when NewRegistry builds the keystore.
func LoadKeyManifestFile(path string) (*KeyManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key manifest %q: %w", path, err)
	}
	return ParseKeyManifest(data)
}

// LoadKeyManifest resolves the manifest file path from the environment
// variable named by envVar, falling back to defaultPath when the variable is
// unset or empty.
//
// The env var holds a path, not the manifest itself: storing key material as a
// file (e.g. a mounted secret) and pointing to it by path keeps secrets out of
// the process environment, where they can leak via /proc, crash dumps, and
// inherited child processes.
func LoadKeyManifest(envVar, defaultPath string) (*KeyManifest, error) {
	path := os.Getenv(envVar)
	if path == "" {
		path = defaultPath
	}
	if path == "" {
		return nil, fmt.Errorf("no key manifest path: set %s or provide a default path", envVar)
	}
	return LoadKeyManifestFile(path)
}
