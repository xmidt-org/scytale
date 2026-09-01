// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-kit/kit/metrics"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/wrp-go/v3"
)

func TestAuthorizeWRP(t *testing.T) {
	testCases := []struct {
		Name                string
		PartnerIDs          []string
		AllowedPartners     []string
		IsBearer            bool
		InjectSecurityToken bool
		ExpectAutocorrect   bool
		Error               error
		BaseLabelPairs      map[string]string
		ExpectedPartnerIDs  []string
	}{
		{
			Name:  "Bascule token Missing",
			Error: ErrTokenMissing,

			IsBearer: true,
			BaseLabelPairs: map[string]string{
				ReasonLabel: TokenMissing,

				ClientIDLabel: "none",
			},
		},
		{
			Name:                "Bad bascule token type",
			Error:               ErrTokenTypeMismatch,
			InjectSecurityToken: true,
			// nolint: goconst
			AllowedPartners: []string{"partner0"},
			BaseLabelPairs: map[string]string{
				ReasonLabel:   TokenTypeMismatch,
				ClientIDLabel: "none",
			},
		},

		{
			Name:                "Invalid AllowedPartners",
			Error:               ErrInvalidAllowedPartners,
			InjectSecurityToken: true,
			IsBearer:            true,
			AllowedPartners:     []string{},
			BaseLabelPairs: map[string]string{
				ReasonLabel: JWTPIDInvalid,
				// nolint: goconst
				ClientIDLabel: "tester",
			},
		},

		{
			Name:                "No AllowedPartners",
			Error:               ErrInvalidAllowedPartners,
			InjectSecurityToken: true,
			IsBearer:            true,
			AllowedPartners:     nil,
			BaseLabelPairs: map[string]string{
				ReasonLabel:   JWTPIDInvalid,
				ClientIDLabel: "tester",
			},
		},

		{
			Name:                "PartnerIDs missing from WRP",
			Error:               ErrPIDMissing,
			InjectSecurityToken: true,
			IsBearer:            true,
			AllowedPartners:     []string{"p0", "p1"},
			ExpectAutocorrect:   true,
			BaseLabelPairs: map[string]string{
				ReasonLabel:   WRPPIDMissing,
				ClientIDLabel: "tester",
			},
			ExpectedPartnerIDs: []string{"p0", "p1"},
		},

		{
			Name:                "PartnerIDs is not subset of allowerPartners",
			InjectSecurityToken: true,
			IsBearer:            true,
			PartnerIDs:          []string{"p2"},
			AllowedPartners:     []string{"p0", "p1"},
			Error:               ErrPIDMismatch,
			BaseLabelPairs: map[string]string{
				ReasonLabel:   WRPPIDMismatch,
				ClientIDLabel: "tester",
			},
			ExpectedPartnerIDs: []string{"p0", "p1"},
			ExpectAutocorrect:  true,
		},

		{
			Name:                "Wildcard in allowedPartners",
			InjectSecurityToken: true,
			IsBearer:            true,
			PartnerIDs:          []string{"p2"}, //TODO: is this the behavior we actually want? '*' giving user superpowers!
			AllowedPartners:     []string{"p0", "p1", "*"},
			BaseLabelPairs: map[string]string{
				ReasonLabel:   JWTPIDWildcard,
				ClientIDLabel: "tester",
			},
			ExpectedPartnerIDs: []string{"p2"},
		},

		{
			Name:                "Non-empty partnerIDs is subset of allowerPartners",
			InjectSecurityToken: true,
			IsBearer:            true,
			PartnerIDs:          []string{"p0"},
			AllowedPartners:     []string{"p0", "p1"},
			BaseLabelPairs: map[string]string{
				ReasonLabel:   WRPPIDMatch,
				ClientIDLabel: "tester",
			},
			ExpectedPartnerIDs: []string{"p0"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			assert := assert.New(t)

			ctx := context.Background()
			if testCase.InjectSecurityToken {
				ctx = enrichWithBasculeToken(context.Background(), testCase.IsBearer, testCase.AllowedPartners)
			}

			wrpMsg := &wrp.Message{
				PartnerIDs: testCase.PartnerIDs,
			}

			var (
				wrpAccessAuthority wrpAccessAuthority
				counter            = newTestCounter()
			)

			expectedStrictLabels, expectedLenientLabels := createLabelMaps(testCase.Error != nil, testCase.BaseLabelPairs)

			//strict mode
			wrpAccessAuthority = &wrpPartnersAccess{
				strict:                  true,
				receivedWRPMessageCount: counter,
			}
			modified, err := wrpAccessAuthority.authorizeWRP(ctx, wrpMsg)
			assert.False(modified)
			assert.Equal(testCase.Error, err)
			assert.Equal(float64(1), counter.count)
			assert.Equal(expectedStrictLabels, counter.labelPairs)

			//lenient mode
			counter = newTestCounter()
			wrpAccessAuthority = &wrpPartnersAccess{
				strict:                  false,
				receivedWRPMessageCount: counter,
			}

			modified, err = wrpAccessAuthority.authorizeWRP(ctx, wrpMsg)
			assert.Equal(testCase.ExpectAutocorrect, modified)
			assert.Nil(err)
			assert.Equal(float64(1), counter.count)
			assert.Equal(expectedLenientLabels, counter.labelPairs)
		})
	}
}

func createLabelMaps(rejected bool, baseLabelPairs map[string]string) (strict map[string]string, lenient map[string]string) {
	strict = make(map[string]string)
	lenient = make(map[string]string)

	for k, v := range baseLabelPairs {
		strict[k] = v
		lenient[k] = v
	}

	if rejected {
		strict[OutcomeLabel] = Rejected
	} else {
		strict[OutcomeLabel] = Accepted
	}
	lenient[OutcomeLabel] = Accepted

	return
}

func enrichWithBasculeToken(ctx context.Context, isBearer bool, partners []string) context.Context {
	if isBearer {
		token, err := jwt.NewBuilder().
			Claim(allowedResources, map[string]any{allowedPartners: partners}).
			Subject("tester").
			Issuer("https://example.com").
			Build()
		if err != nil {
			panic(fmt.Errorf("failed to build test JWT: %v", err))
		}

		return bascule.WithToken(ctx, &testJWT{token})
	}

	return bascule.WithToken(ctx, bascule.StubToken("tester"))
}

type testCounter struct {
	count      float64
	labelPairs map[string]string
}

func (c *testCounter) Add(delta float64) {
	c.count += delta
}

func (c *testCounter) With(labelValues ...string) metrics.Counter {
	for i := 0; i < len(labelValues)-1; i += 2 {
		c.labelPairs[labelValues[i]] = labelValues[i+1]
	}
	return c
}

func newTestCounter() *testCounter {
	return &testCounter{
		labelPairs: make(map[string]string),
	}
}
