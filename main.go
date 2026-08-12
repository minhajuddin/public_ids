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
	separator string
	codec     codec
}

func (r *Registry) Deserialize(s string) (*PublicID, error) {
	return r.codec.Decode(s, r.separator)
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
	Decode(s string, separator string) (PublicID, error)
}

type pbSignatureEncoder struct {
	hash     hash.Hash
	entities map[string]Entity
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

func (e *pbSignatureEncoder) Decode(s string, separator string) (*PublicID, error) {
	// 1 cut the prefix and check format
	parts := strings.Split(s, separator)

	if len(parts) != 2 {
		return nil, errors.New("bad format")
	}

	// 2 parse protobuf
	outBytes := make([]byte, b64.DecodedLen(len(parts[1])))
	n, err := b64.Decode(outBytes, []byte(parts[1]))
	if err != nil {
		return nil, err
	}
	outBytes = outBytes[:n]

	var out pb.SignedPublicID
	err = proto.Unmarshal(outBytes, &out) // deserialize
	if err != nil {
		return nil, err
	}

	// compare id prefix and proto prefix
	if parts[0] != out.Prefix {
		return nil, errors.New("prefix mismatch")
	}

	// 3 check signature
	signature, err := e.sign(out.Prefix, out.Id)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signature, out.Signature) {
		return nil, errors.New("invalid signature")
	}

	uuid, err := uuid.FromBytes(out.Id)
	if err != nil {
		return nil, err
	}

	return &PublicID{
		Entity: e.entities[out.Prefix],
		UUID:   uuid,
	}, nil
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

func newPbSignatureEncoder(hash hash.Hash, entities map[string]Entity) *pbSignatureEncoder {
	return &pbSignatureEncoder{
		hash:     hash,
		entities: entities,
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
		separator: separator,
		codec:     newPbSignatureEncoder(hmac.New(sha256.New, []byte("a-single-key")), entities),
	}
}
