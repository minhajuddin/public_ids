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
	assert.Equal(t, id, "user.AZ_x8YwHcymhAMExa72h0Q.dXNlci5BWl94OFl3")
	id, err = r.Serialize(&PublicID{PostID, uuid})
	assert.Equal(t, id, "post.AZ_x8YwHcymhAMExa72h0Q.cG9zdC5BWl94OFl3")
}
