package publicid

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadKeyManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	require.NoError(t, os.WriteFile(path, []byte(manifestJSON(2)), 0o600))

	// Direct file load.
	m, err := LoadKeyManifestFile(path)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), m.ActiveKeyID)
	assert.Len(t, m.Keys, 2)

	// Loaded manifest builds a working registry.
	r, err := NewRegistry([]PrefixInfo{{UserID, "user"}}, ".", m)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// Via env var holding the path.
	t.Setenv("PID_MANIFEST", path)
	m, err = LoadKeyManifest("PID_MANIFEST", "")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), m.ActiveKeyID)

	// Falls back to defaultPath when the env var is empty.
	t.Setenv("PID_MANIFEST", "")
	m, err = LoadKeyManifest("PID_MANIFEST", path)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), m.ActiveKeyID)

	// Missing file errors.
	_, err = LoadKeyManifestFile(filepath.Join(dir, "does-not-exist.json"))
	assert.Error(t, err)

	// No path from env or default errors.
	_, err = LoadKeyManifest("PID_MANIFEST_UNSET", "")
	assert.Error(t, err)
}
