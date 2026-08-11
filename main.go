package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	signatureByteLen = 12
	separator        = "."
)

var b64 = base64.RawURLEncoding.WithPadding(base64.NoPadding)

type Entity int

type PublicID struct {
	Entity Entity
	UUID   uuid.UUID
}
type PrefixInfo struct {
	Entity Entity
	Prefix string
}

// This will be the proto
type PublicIDWithSignature struct {
	Entity    Entity
	UUID      uuid.UUID
	Signature string
}

type (
	encoder func(prefix string, separator string, uuid uuid.UUID, signer signer) string
	signer  func(msg []byte) []byte
)

type Registry struct {
	prefixes  map[Entity]string
	separator string
	signer    signer
	encoder   encoder
}

func (r *Registry) Serialize(p *PublicID) (string, error) {
	// TODO: Change this to protobuf or msgpack
	prefix, ok := r.prefixes[p.Entity]
	if !ok {
		return "", errors.New("prefix not found")
	}
	return r.encoder(prefix, separator, p.UUID, r.signer), nil
}

func (r *Registry) Parse(s string) (PublicID, error) {
	return PublicID{}, nil
}

func stdSigner(msg []byte) []byte {
	h := hmac.New(sha256.New, []byte("magical-and-secret-key"))
	return h.Sum(msg)
}

func stdEncoder(prefix string, separator string, uuid uuid.UUID, signer signer) string {
	msg := fmt.Sprintf("%s%s%s", prefix, separator, b64.EncodeToString(uuid[:]))
	signature := signer([]byte(msg))

	return fmt.Sprintf("%s%s%s", msg, separator, b64.EncodeToString(signature[:12]))
}

func NewRegistry(pis []PrefixInfo, separator string) Registry {
	prefixes := make(map[Entity]string)
	for _, p := range pis {
		prefixes[p.Entity] = p.Prefix
	}
	return Registry{
		prefixes:  prefixes,
		separator: separator,
		encoder:   stdEncoder,
		signer:    stdSigner,
	}
}
