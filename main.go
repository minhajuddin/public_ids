package publicid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"

	"github.com/google/uuid"
	pb "github.com/minhajuddin/public_ids/pb"
	"google.golang.org/protobuf/proto"
)

var b64 = base64.RawURLEncoding.WithPadding(base64.NoPadding)

const (
	// signatureLength is how many bytes of the HMAC-SHA256 tag we retain.
	// 12 bytes (96 bits) is a tamper-evidence tag, not a full-strength MAC.
	signatureLength = 12
	// minKeyLength rejects obviously-weak secrets. 32+ bytes is recommended.
	minKeyLength = 16
	// maxTokenLength bounds attacker-controlled input before we allocate/parse.
	maxTokenLength = 4096
)

type Entity int

type PublicID struct {
	Entity Entity
	UUID   uuid.UUID
}

type PrefixInfo struct {
	Entity Entity
	Prefix string
}

// KeyManifest is the JSON document describing the HMAC signing keys.
// It supports rotation: newly issued IDs are signed with ActiveKeyID, while
// any key still listed in Keys can verify previously-issued IDs.
//
//	{
//	  "active_key_id": 2,
//	  "keys": [
//	    {"id": 1, "secret": "<base64 std-encoded bytes>"},
//	    {"id": 2, "secret": "<base64 std-encoded bytes>"}
//	  ]
//	}
type KeyManifest struct {
	ActiveKeyID uint32        `json:"active_key_id"`
	Keys        []ManifestKey `json:"keys"`
}

// ManifestKey is a single signing key. Secret is standard-base64-encoded raw
// key bytes; key material must never be committed in plaintext.
type ManifestKey struct {
	ID     uint32 `json:"id"`
	Secret string `json:"secret"`
}

// ParseKeyManifest decodes a JSON key manifest. It does not validate the key
// material; NewRegistry does that when it builds the keystore.
func ParseKeyManifest(data []byte) (*KeyManifest, error) {
	var m KeyManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse key manifest: %w", err)
	}
	return &m, nil
}

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

type Registry struct {
	prefixes  map[Entity]string
	entities  map[string]Entity
	separator string
	codec     codec
}

func (r *Registry) Deserialize(s string) (*PublicID, error) {
	id, prefix, err := r.codec.Decode(s, r.separator)
	if err != nil {
		return nil, err
	}

	entity, ok := r.entities[prefix]
	if !ok {
		return nil, errors.New("unknown prefix")
	}

	return &PublicID{
		Entity: entity,
		UUID:   id,
	}, nil
}

func (r *Registry) Serialize(p *PublicID) (string, error) {
	prefix, ok := r.prefixes[p.Entity]
	if !ok {
		return "", errors.New("prefix not found")
	}
	return r.codec.Encode(p.UUID, prefix, r.separator)
}

type codec interface {
	Encode(id uuid.UUID, prefix string, separator string) (string, error)
	Decode(s string, separator string) (id uuid.UUID, prefix string, err error)
}

type pbSignatureEncoder struct {
	keys *keyStore
}

func newPbSignatureEncoder(ks *keyStore) *pbSignatureEncoder {
	return &pbSignatureEncoder{keys: ks}
}

func (e *pbSignatureEncoder) Encode(id uuid.UUID, prefix string, separator string) (string, error) {
	kp, ok := e.keys.keys[e.keys.activeKeyID]
	if !ok {
		return "", errors.New("active signing key not found")
	}

	signature := kp.sign(prefix, id[:])
	finalPidBytes, err := proto.Marshal(&pb.SignedPublicID{
		Prefix:    prefix,
		Id:        id[:],
		Signature: signature,
		KeyId:     e.keys.activeKeyID,
	}) // serialize
	if err != nil {
		return "", err
	}

	return prefix + separator + b64.EncodeToString(finalPidBytes), nil
}

func (e *pbSignatureEncoder) Decode(s string, separator string) (uuid.UUID, string, error) {
	if len(s) > maxTokenLength {
		return uuid.UUID{}, "", errors.New("input too long")
	}

	// 1. Split off the out-of-band prefix and check the format.
	parts := strings.Split(s, separator)
	if len(parts) != 2 {
		return uuid.UUID{}, "", errors.New("bad format")
	}

	// 2. Decode and parse the protobuf payload.
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return uuid.UUID{}, "", err
	}

	var out pb.SignedPublicID
	if err := proto.Unmarshal(payload, &out); err != nil { // deserialize
		return uuid.UUID{}, "", err
	}

	// The prefix travels both out-of-band and inside the payload; they must agree.
	if parts[0] != out.Prefix {
		return uuid.UUID{}, "", errors.New("prefix mismatch")
	}

	// 3. Select the verification key by the id embedded in the token. This is
	// what makes rotation work: a token signed by a now-inactive key still
	// verifies as long as that key remains in the manifest.
	kp, ok := e.keys.keys[out.KeyId]
	if !ok {
		return uuid.UUID{}, "", errors.New("unknown key id")
	}

	// 4. Verify the signature in constant time.
	expected := kp.sign(out.Prefix, out.Id)
	if !hmac.Equal(expected, out.Signature) {
		return uuid.UUID{}, "", errors.New("invalid signature")
	}

	id, err := uuid.FromBytes(out.Id)
	if err != nil {
		return uuid.UUID{}, "", err
	}

	return id, out.Prefix, nil
}

// NewRegistry builds a Registry from prefix mappings and a validated key
// manifest. The returned Registry is immutable and safe for concurrent use.
func NewRegistry(pis []PrefixInfo, separator string, manifest *KeyManifest) (*Registry, error) {
	if separator == "" {
		return nil, errors.New("separator must not be empty")
	}

	ks, err := manifest.buildKeyStore()
	if err != nil {
		return nil, err
	}

	prefixes := make(map[Entity]string, len(pis))
	entities := make(map[string]Entity, len(pis))
	for _, p := range pis {
		if p.Prefix == "" {
			return nil, errors.New("prefix must not be empty")
		}
		if strings.Contains(p.Prefix, separator) {
			return nil, fmt.Errorf("prefix %q contains separator %q", p.Prefix, separator)
		}
		if _, dup := entities[p.Prefix]; dup {
			return nil, fmt.Errorf("duplicate prefix %q", p.Prefix)
		}
		if _, dup := prefixes[p.Entity]; dup {
			return nil, fmt.Errorf("duplicate entity %d", p.Entity)
		}
		prefixes[p.Entity] = p.Prefix
		entities[p.Prefix] = p.Entity
	}

	return &Registry{
		prefixes:  prefixes,
		entities:  entities,
		separator: separator,
		codec:     newPbSignatureEncoder(ks),
	}, nil
}
