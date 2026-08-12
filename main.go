package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

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
	Decode(s string) (*PublicID, error)
}

type pbSignatureEncoder struct {
	hash hash.Hash
}

func (e *pbSignatureEncoder) Encode(uuid uuid.UUID, prefix string, separator string) (string, error) {
	id := &pb.PublicID{
		Uuid:      uuid[:],
		Signature: []byte("test"),
		KeyId:     1,
	}
	data, err := proto.Marshal(id) // serialize
	if err != nil {
		return "", err
	}
	// // ...
	// var out pb.PublicID
	// err = proto.Unmarshal(data, &out)   // deserialize

	msg := fmt.Sprintf("%s%s%s", prefix, separator, b64.EncodeToString(data))
	signature := e.hash.Sum([]byte(msg))

	return fmt.Sprintf("%s%s%s", msg, separator, b64.EncodeToString(signature)), nil
}

func (e *pbSignatureEncoder) Decode(s string) (*PublicID, error) {
	return nil, nil
}

func newPbSignatureEncoder(hash hash.Hash) *pbSignatureEncoder {
	return &pbSignatureEncoder{
		hash: hash,
	}
}

func NewRegistry(pis []PrefixInfo, separator string) *Registry {
	prefixes := make(map[Entity]string)
	for _, p := range pis {
		prefixes[p.Entity] = p.Prefix
	}
	return &Registry{
		prefixes:  prefixes,
		separator: separator,
		codec: &pbSignatureEncoder{
			hmac.New(sha256.New, []byte("a-single-key")),
		},
	}
}
