// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testJWT struct {
	jwt.Token
}

func (j testJWT) Principal() string {
	return j.Subject()
}

func TestRequirePartnerIDs(t *testing.T) {
	var tests = []struct {
		name       string
		attrMap    map[string]any
		shouldPass bool
	}{
		{
			name: "partnerIDs",
			attrMap: map[string]any{
				// nolint: goconst
				allowedPartners: []string{"partner0", "partner1"},
			},
			shouldPass: true,
		},

		{
			name: "missing partnerIDs key",
			attrMap: map[string]any{
				allowedResources: map[string]any{},
			},
		},
		{
			name: "no partnerIDs",
			attrMap: map[string]any{
				allowedPartners: []string{},
			},
		},
		{
			name: "malformed partnerIDs field",
			attrMap: map[string]any{
				allowedPartners: map[string]any{"partner0": true},
			},
		},
	}

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			token, err := jwt.NewBuilder().
				Claim(allowedResources, test.attrMap).
				Subject("client0").
				Issuer("https://example.com").
				Build()
			require.NoError(err, "failed to build test JWT")
			err = jwtClaimPartnerIDsValidator(ctx, nil, testJWT{token})
			if test.shouldPass {
				assert.NoError(err)
			} else {
				assert.Error(err)
			}
		})
	}
}
