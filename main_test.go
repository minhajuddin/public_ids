package publicid

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	UserID Entity = 1
	PostID Entity = 2
)

// Two distinct 32-byte keys, std-base64 encoded for the manifest.
var (
	key1B64 = base64.StdEncoding.EncodeToString([]byte("key-one-key-one-key-one-key-one!"))
	key2B64 = base64.StdEncoding.EncodeToString([]byte("key-two-key-two-key-two-key-two!"))
)

func manifestJSON(activeKeyID uint32) string {
	return fmt.Sprintf(`{
		"active_key_id": %d,
		"keys": [
			{"id": 1, "secret": %q},
			{"id": 2, "secret": %q}
		]
	}`, activeKeyID, key1B64, key2B64)
}

func newTestRegistry(t *testing.T, activeKeyID uint32) *Registry {
	t.Helper()
	m, err := ParseKeyManifest([]byte(manifestJSON(activeKeyID)))
	require.NoError(t, err)
	r, err := NewRegistry([]PrefixInfo{
		{UserID, "user"},
		{PostID, "post"},
	}, ".", m)
	require.NoError(t, err)
	return r
}

func TestRoundTrip(t *testing.T) {
	u := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")
	r := newTestRegistry(t, 2)

	for _, tc := range []struct {
		entity Entity
		prefix string
	}{
		{UserID, "user."},
		{PostID, "post."},
	} {
		token, err := r.Serialize(&PublicID{tc.entity, u})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(token, tc.prefix), "token %q should start with %q", token, tc.prefix)

		pid, err := r.Deserialize(token)
		require.NoError(t, err)
		assert.Equal(t, tc.entity, pid.Entity)
		assert.Equal(t, u, pid.UUID)
	}
}

func TestKeyRotation(t *testing.T) {
	u := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")

	// Mint a token while key 1 is active.
	old := newTestRegistry(t, 1)
	token, err := old.Serialize(&PublicID{UserID, u})
	require.NoError(t, err)

	// After rotating to key 2 (key 1 still present) the old token still verifies.
	rotated := newTestRegistry(t, 2)
	pid, err := rotated.Deserialize(token)
	require.NoError(t, err)
	assert.Equal(t, u, pid.UUID)

	// New tokens are signed with the active key and also verify.
	newToken, err := rotated.Serialize(&PublicID{UserID, u})
	require.NoError(t, err)
	assert.NotEqual(t, token, newToken, "rotated token should be signed by a different key")
	_, err = rotated.Deserialize(newToken)
	require.NoError(t, err)
}

func TestRetiredKeyRejected(t *testing.T) {
	u := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")

	// Token minted under key 1.
	old := newTestRegistry(t, 1)
	token, err := old.Serialize(&PublicID{UserID, u})
	require.NoError(t, err)

	// A registry that only knows key 2 must reject it (key 1 retired).
	onlyKey2, err := ParseKeyManifest([]byte(fmt.Sprintf(
		`{"active_key_id":2,"keys":[{"id":2,"secret":%q}]}`, key2B64)))
	require.NoError(t, err)
	r, err := NewRegistry([]PrefixInfo{{UserID, "user"}}, ".", onlyKey2)
	require.NoError(t, err)

	_, err = r.Deserialize(token)
	assert.Error(t, err)
}

func TestTamperRejected(t *testing.T) {
	u := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")
	r := newTestRegistry(t, 2)
	token, err := r.Serialize(&PublicID{UserID, u})
	require.NoError(t, err)

	// Flip the last character of the payload: signature no longer matches.
	bad := []byte(token)
	last := len(bad) - 1
	if bad[last] == 'A' {
		bad[last] = 'B'
	} else {
		bad[last] = 'A'
	}
	_, err = r.Deserialize(string(bad))
	assert.Error(t, err)

	// A registry holding a different secret under the same key id rejects a
	// validly-signed token (exercises the signature check, not just key lookup).
	wrong, err := ParseKeyManifest([]byte(fmt.Sprintf(
		`{"active_key_id":1,"keys":[{"id":1,"secret":%q}]}`,
		base64.StdEncoding.EncodeToString([]byte("different-key-different-key-diff!")))))
	require.NoError(t, err)
	wr, err := NewRegistry([]PrefixInfo{{UserID, "user"}}, ".", wrong)
	require.NoError(t, err)

	def1 := newTestRegistry(t, 1)
	tok1, err := def1.Serialize(&PublicID{UserID, u})
	require.NoError(t, err)
	_, err = wr.Deserialize(tok1)
	assert.Error(t, err)
}

func TestManifestValidation(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("key-one-key-one-key-one-key-one!"))
	cases := map[string]string{
		"empty keys":     `{"active_key_id":1,"keys":[]}`,
		"missing active": fmt.Sprintf(`{"active_key_id":9,"keys":[{"id":1,"secret":%q}]}`, good),
		"duplicate id":   fmt.Sprintf(`{"active_key_id":1,"keys":[{"id":1,"secret":%q},{"id":1,"secret":%q}]}`, good, good),
		"key id zero":    fmt.Sprintf(`{"active_key_id":0,"keys":[{"id":0,"secret":%q}]}`, good),
		"short secret":   `{"active_key_id":1,"keys":[{"id":1,"secret":"c2hvcnQ="}]}`, // "short"
		"bad base64":     `{"active_key_id":1,"keys":[{"id":1,"secret":"not!base64!"}]}`,
		"malformed json": `{"active_key_id":1,`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := ParseKeyManifest([]byte(js))
			if err != nil {
				return // parse-level failure is an acceptable rejection
			}
			_, err = NewRegistry([]PrefixInfo{{UserID, "user"}}, ".", m)
			assert.Error(t, err)
		})
	}
}

func TestRegistryValidation(t *testing.T) {
	m, err := ParseKeyManifest([]byte(manifestJSON(1)))
	require.NoError(t, err)

	// Empty separator.
	_, err = NewRegistry([]PrefixInfo{{UserID, "user"}}, "", m)
	assert.Error(t, err)

	// Prefix containing the separator would break parsing.
	_, err = NewRegistry([]PrefixInfo{{UserID, "us.er"}}, ".", m)
	assert.Error(t, err)

	// Duplicate prefix.
	_, err = NewRegistry([]PrefixInfo{{UserID, "user"}, {PostID, "user"}}, ".", m)
	assert.Error(t, err)
}

// TestConcurrentUse locks in the fix for the shared-hash data race: run with
// -race to catch regressions.
func TestConcurrentUse(t *testing.T) {
	u := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")
	r := newTestRegistry(t, 2)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				token, err := r.Serialize(&PublicID{UserID, u})
				if err != nil {
					t.Errorf("serialize: %v", err)
					return
				}
				pid, err := r.Deserialize(token)
				if err != nil {
					t.Errorf("deserialize valid token: %v", err)
					return
				}
				if pid.UUID != u {
					t.Errorf("round-trip mismatch: got %v want %v", pid.UUID, u)
					return
				}
			}
		}()
	}
	wg.Wait()
}
