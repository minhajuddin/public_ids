package publicid

import (
	"errors"
	"fmt"
	"strings"
)

// Registry maps entities to prefixes and delegates the wire format to a codec.
// It is immutable after construction and safe for concurrent use.
type Registry struct {
	prefixes map[Entity]string
	entities map[string]Entity
	codec    codec
}

func (r *Registry) Deserialize(s string) (*PublicID, error) {
	id, prefix, err := r.codec.Decode(s)
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
	return r.codec.Encode(p.UUID, prefix)
}

// NewRegistry builds a Registry from prefix mappings and a validated key
// manifest. The separator joins the prefix to the payload in a token and is
// handed to the codec; it must not be empty or appear in any prefix. The
// returned Registry is immutable and safe for concurrent use.
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
		prefixes: prefixes,
		entities: entities,
		codec:    newPbSignatureEncoder(ks, separator),
	}, nil
}
