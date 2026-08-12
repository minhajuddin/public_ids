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
	Decode(s string, separator string) (*PublicID, error)
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

	fmt.Println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
	fmt.Println(b64.EncodeToString(finalPidBytes))
	fmt.Println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
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
	outBytes := make([]byte, 0, len(s))
	_, err := b64.Decode(outBytes, []byte(parts[1]))
	if err != nil {
		return nil, err
	}

	fmt.Println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
	fmt.Println(b64.EncodeToString(outBytes))
	fmt.Println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")

	var out pb.SignedPublicID
	err = proto.Unmarshal(outBytes, &out) // deserialize
	if err != nil {
		fmt.Println("------------------------------------------------------------")
		fmt.Println(s, separator, parts)
		fmt.Println("------------------------------------------------------------")
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
	if bytes.Compare(signature, out.Signature) != 0 {
		return nil, errors.New("invalid signature")
	}

	uuid, err := uuid.ParseBytes(out.Id)
	if err != nil {
		return nil, err
	}

	return &PublicID{
		Entity: 0,
		UUID:   uuid,
	}, nil
}

func (e *pbSignatureEncoder) sign(prefix string, id []byte) ([]byte, error) {
	buf := bytes.NewBuffer([]byte(prefix))
	_, err := buf.Write(id)
	if err != nil {
		return []byte{}, err
	}

	signature := e.hash.Sum(buf.Bytes())
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
