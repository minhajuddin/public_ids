package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/google/uuid"
	pb "github.com/minhajuddin/public_ids/pb"
	"google.golang.org/protobuf/proto"
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
	// TODO: Change this to protobuf or msgpack
	prefix, ok := r.prefixes[p.Entity]
	if !ok {
		return "", errors.New("prefix not found")
	}
	return r.codec.Encode(p.UUID, prefix, r.separator)
}

func (r *Registry) Parse(s string) (PublicID, error) {
	return PublicID{}, nil
}

type codec interface {
	Encode(uuid uuid.UUID, prefix string, separator string) (string, error)
	Decode(s string, separator string) (uuid uuid.UUID, prefix string, err error)
}

type pbSignatureEncoder struct {
	hash hash.Hash
}

func (e *pbSignatureEncoder) Encode(uuid uuid.UUID, prefix string, separator string) (string, error) {
	b, err := e.sign(prefix, uuid[:])
	if err != nil {
		return "", err
	}
	finalPidBytes, err := proto.Marshal(&pb.SignedPublicID{
		Prefix:    prefix,
		Id:        uuid[:],
		Signature: b,
		KeyId:     1,
	}) // serialize
	if err != nil {
		return "", err
	}

	msg := fmt.Sprintf("%s%s%s", prefix, separator, b64.EncodeToString(finalPidBytes))

	return msg, nil
}

func (e *pbSignatureEncoder) Decode(s string, separator string) (uuid.UUID, string, error) {
	// 1 cut the prefix and check format
	parts := strings.Split(s, separator)

	if len(parts) != 2 {
		return uuid.UUID{}, "", errors.New("bad format")
	}

	// 2 parse protobuf
	outBytes := make([]byte, b64.DecodedLen(len(parts[1])))
	n, err := b64.Decode(outBytes, []byte(parts[1]))
	if err != nil {
		return uuid.UUID{}, "", err
	}
	outBytes = outBytes[:n]

	var out pb.SignedPublicID
	err = proto.Unmarshal(outBytes, &out) // deserialize
	if err != nil {
		return uuid.UUID{}, "", err
	}

	// compare id prefix and proto prefix
	if parts[0] != out.Prefix {
		return uuid.UUID{}, "", errors.New("prefix mismatch")
	}

	// 3 check signature
	signature, err := e.sign(out.Prefix, out.Id)
	if err != nil {
		return uuid.UUID{}, "", err
	}
	if !bytes.Equal(signature, out.Signature) {
		return uuid.UUID{}, "", errors.New("invalid signature")
	}

	id, err := uuid.FromBytes(out.Id)
	if err != nil {
		return uuid.UUID{}, "", err
	}

	return id, out.Prefix, nil
}

func (e *pbSignatureEncoder) sign(prefix string, id []byte) ([]byte, error) {
	e.hash.Reset()
	if _, err := e.hash.Write([]byte(prefix)); err != nil {
		return nil, err
	}
	if _, err := e.hash.Write(id); err != nil {
		return nil, err
	}

	signature := e.hash.Sum(nil)
	shortSignature := signature[:12]

	return shortSignature, nil
}

func newPbSignatureEncoder(hash hash.Hash) *pbSignatureEncoder {
	return &pbSignatureEncoder{
		hash: hash,
	}
}

func NewRegistry(pis []PrefixInfo, separator string) *Registry {
	prefixes := make(map[Entity]string)
	entities := make(map[string]Entity)
	for _, p := range pis {
		prefixes[p.Entity] = p.Prefix
		entities[p.Prefix] = p.Entity
	}
	return &Registry{
		prefixes:  prefixes,
		entities:  entities,
		separator: separator,
		codec:     newPbSignatureEncoder(hmac.New(sha256.New, []byte("a-single-key"))),
	}
}
