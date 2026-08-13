package publicid

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/uuid"
	pb "github.com/minhajuddin/public_ids/pb"
	"google.golang.org/protobuf/proto"
)

var b64 = base64.RawURLEncoding.WithPadding(base64.NoPadding)

// maxTokenLength bounds attacker-controlled input before we allocate/parse.
const maxTokenLength = 4096

// codec turns a (UUID, prefix) pair into a token and back. Implementations own
// the wire format, including the separator that joins the out-of-band prefix to
// the encoded payload.
type codec interface {
	Encode(id uuid.UUID, prefix string) (string, error)
	Decode(s string) (id uuid.UUID, prefix string, err error)
}

// pbSignatureEncoder is a codec that serializes a protobuf payload carrying the
// UUID and an HMAC signature, prefixed with the out-of-band prefix. The
// separator that joins the prefix and payload is fixed at construction.
type pbSignatureEncoder struct {
	keys      *keyStore
	separator string
}

func newPbSignatureEncoder(ks *keyStore, separator string) *pbSignatureEncoder {
	return &pbSignatureEncoder{keys: ks, separator: separator}
}

func (e *pbSignatureEncoder) Encode(id uuid.UUID, prefix string) (string, error) {
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

	return prefix + e.separator + b64.EncodeToString(finalPidBytes), nil
}

func (e *pbSignatureEncoder) Decode(s string) (uuid.UUID, string, error) {
	if len(s) > maxTokenLength {
		return uuid.UUID{}, "", errors.New("input too long")
	}

	// 1. Split off the out-of-band prefix and check the format.
	parts := strings.Split(s, e.separator)
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
