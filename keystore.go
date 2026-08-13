package publicid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"sync"
)

const (
	// signatureLength is how many bytes of the HMAC-SHA256 tag we retain.
	// 12 bytes (96 bits) is a tamper-evidence tag, not a full-strength MAC.
	signatureLength = 12
	// minKeyLength rejects obviously-weak secrets. 32+ bytes is recommended.
	minKeyLength = 16
)

// keyStore holds decoded, validated keys indexed by key id, plus the id used
// to sign new tokens. It is immutable after construction and therefore safe
// for concurrent use.
type keyStore struct {
	keys        map[uint32]*keyPool
	activeKeyID uint32
}

// keyPool owns one key's secret and a pool of ready-to-use HMAC hashers.
// Pooling avoids re-deriving the HMAC ipad/opad state on every call while
// keeping each hasher owned by a single goroutine at a time.
type keyPool struct {
	secret []byte
	pool   sync.Pool
}

func (kp *keyPool) sign(prefix string, id []byte) []byte {
	h := kp.pool.Get().(hash.Hash)
	h.Reset()
	// hash.Hash.Write never returns an error.
	h.Write([]byte(prefix))
	h.Write(id)
	sum := h.Sum(nil)
	kp.pool.Put(h)
	return sum[:signatureLength]
}

func (m *KeyManifest) buildKeyStore() (*keyStore, error) {
	if m == nil {
		return nil, errors.New("key manifest is nil")
	}
	if len(m.Keys) == 0 {
		return nil, errors.New("key manifest has no keys")
	}

	ks := &keyStore{
		keys:        make(map[uint32]*keyPool, len(m.Keys)),
		activeKeyID: m.ActiveKeyID,
	}
	for _, mk := range m.Keys {
		if mk.ID == 0 {
			// 0 is the proto3 default for an unset key_id; disallow it so a
			// crafted message with no key_id can never select a real key.
			return nil, errors.New("key id 0 is reserved")
		}
		if _, dup := ks.keys[mk.ID]; dup {
			return nil, fmt.Errorf("duplicate key id %d", mk.ID)
		}
		secret, err := base64.StdEncoding.DecodeString(mk.Secret)
		if err != nil {
			return nil, fmt.Errorf("key id %d: invalid base64 secret: %w", mk.ID, err)
		}
		if len(secret) < minKeyLength {
			return nil, fmt.Errorf("key id %d: secret too short (%d bytes, need >= %d)", mk.ID, len(secret), minKeyLength)
		}

		kp := &keyPool{secret: secret}
		kp.pool.New = func() any { return hmac.New(sha256.New, kp.secret) }
		ks.keys[mk.ID] = kp
	}

	if _, ok := ks.keys[ks.activeKeyID]; !ok {
		return nil, fmt.Errorf("active_key_id %d not present in keys", ks.activeKeyID)
	}
	return ks, nil
}
