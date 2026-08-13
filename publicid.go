// Package publicid encodes and decodes signed, prefixed public identifiers.
//
// A public ID pairs an application entity with a UUID and serializes to a
// tamper-evident token of the form "<prefix><separator><payload>", where the
// payload is a protobuf message carrying the UUID and an HMAC signature. Tokens
// are minted and verified through a Registry; see NewRegistry.
package publicid

import "github.com/google/uuid"

// Entity identifies the kind of object a PublicID refers to (e.g. a user or a
// post). Callers define their own Entity constants and map them to prefixes.
type Entity int

// PublicID is the decoded form of a token: an entity paired with its UUID.
type PublicID struct {
	Entity Entity
	UUID   uuid.UUID
}

// PrefixInfo maps an Entity to the string prefix used in its tokens.
type PrefixInfo struct {
	Entity Entity
	Prefix string
}
