package main

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"
)

const (
	UserID Entity = 1
	PostID Entity = 2
)

func TestFull(t *testing.T) {
	uuid := uuid.MustParse("019ff1f1-8c07-7329-a100-c1316bbda1d1")
	r := NewRegistry([]PrefixInfo{
		{UserID, "user"},
		{PostID, "post"},
	}, ".")
	id, err := r.Serialize(&PublicID{UserID, uuid})
	assert.Nil(t, err)
	// assert.Equal(t, id, "user.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3")
	// id, err = r.Serialize(&PublicID{PostID, uuid})
	// assert.Equal(t, id, "post.AZ_x8YwHcymhAMExa72h0Q.cG9zdC5BWl94OFl3")

	pid, err := r.Deserialize(id)
	assert.Nil(t, err)
	assert.Equal(t, pid.Entity, 3)
	assert.Equal(t, pid.UUID, uuid)
}

// 019ff1f1-8c07-7329-a100-c1316bbda1d1_123456
// usr.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3
// pst.AZ_x8YwHcymhAMExa72h0Q.cG9zdC5BWl94OFl3

// Old vs Proto with prefix in message
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYASIEdXNlcg
// usr.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3

// With prefix nil
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYASIEdXNlcg <- Without null prefix
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYAQ
// usr.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3

// With prefix removed from protobuf
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYASIEdXNlcg <- Without null prefix
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYAQ
// usr.ChABn_HxjAdzKaEAwTFrvaHREgx1c2VyAZ_x8YwHcykYAQ
// usr.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3
// usr.ChABn_HxjAdzKaEAwTFrvaHREgx1c2VyAZ_x8YwHcykYAQ
// usr.ChABn_HxjAdzKaEAwTFrvaHREgzpSLJni7kp-FlhMZYYAQ
// usr.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3
