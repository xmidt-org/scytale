// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehash"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculejwt"
)

type testJWT struct {
	jwt.Token
}

func (t testJWT) Principal() string {
	p, _ := t.Token.Subject()
	return p
}

func (t testJWT) Get(k string) (any, bool) {
	return t.Field(k)
}

func (t testJWT) Audience() []string {
	v, _ := t.Token.Audience()

	return v
}

func (t testJWT) Expiration() time.Time {
	v, _ := t.Token.Expiration()

	return v
}

func (t testJWT) IssuedAt() time.Time {
	v, _ := t.Token.IssuedAt()

	return v
}

func (t testJWT) Issuer() string {
	v, _ := t.Token.Issuer()

	return v
}

func (t testJWT) JwtID() string {
	v, _ := t.Token.JwtID()

	return v
}

func (t testJWT) NotBefore() time.Time {
	v, _ := t.Token.NotBefore()

	return v
}

func (t testJWT) Subject() string {
	v, _ := t.Token.Subject()

	return v
}

func (t testJWT) Capabilities() (caps []string) {
	if v, ok := t.Field(basculejwt.CapabilitiesKey); ok {
		caps, _ = bascule.GetCapabilities(v)
	}

	return
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

func TestBasicCredentials(t *testing.T) {
	const (
		testUser     = "user"
		testPassword = "pass"
	)

	var tests = []struct {
		name       string
		user       string
		password   string
		shouldPass bool
	}{
		{
			name:       "valid credentials",
			user:       testUser,
			password:   testPassword,
			shouldPass: true,
		},
		{
			name:     "wrong password",
			user:     testUser,
			password: "wrong",
		},
		{
			name:     "unknown user",
			user:     "nobody",
			password: testPassword,
		},
	}

	creds, cmp, err := newBasicCredentials(map[string]string{testUser: testPassword})
	require.NoError(t, err)
	v := basculehash.NewValidator[*http.Request](cmp, creds)
	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			token, err := basculehttp.BasicTokenParser{}.Parse(ctx,
				base64.StdEncoding.EncodeToString([]byte(test.user+":"+test.password)))
			require.NoError(err)

			_, err = v.Validate(ctx, nil, token)
			if test.shouldPass {
				assert.NoError(err)
			} else {
				assert.ErrorIs(err, bascule.ErrBadCredentials)
			}
		})
	}
}

func TestAuthPrincipalValidator(t *testing.T) {
	ctx := context.Background()
	assert.NoError(t, authPrincipalValidator(ctx, bascule.StubToken("client0")))

	err := authPrincipalValidator(ctx, bascule.StubToken(""))
	assert.ErrorIs(t, err, bascule.ErrBadCredentials)
	assert.ErrorIs(t, err, errAuthEmptyPrincipal)
	assert.Equal(t, AuthEmptyPrincipal, authenticateReason(err))
}

func TestValidatorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorIs(t, jwtClaimPartnerIDsValidator(ctx, nil, bascule.StubToken("client0")), context.Canceled)
	assert.ErrorIs(t, authPrincipalValidator(ctx, bascule.StubToken("client0")), context.Canceled)
}

func TestGetPartnerIDsWithoutAttributes(t *testing.T) {
	_, err := getPartnerIDs(bascule.StubToken("client0"))
	assert.ErrorIs(t, err, errAuthMissingClaims)
}
