package publicid

import (
	"encoding/json"
	"fmt"
)

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
