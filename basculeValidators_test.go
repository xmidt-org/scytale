// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
)

func TestRequirePartnerIDs(t *testing.T) {
	type badType []struct{}
	var tests = []struct {
		name       string
		attrMap    map[string]interface{}
		shouldPass bool
	}{
		{
			name: "partnerIDs",
			attrMap: map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{"partner0", "partner1"},
				}},
			shouldPass: true,
		},

		{
			name: "missing partnerIDs key",
			attrMap: map[string]interface{}{
				"allowedResources": map[string]interface{}{},
			},
		},
		{
			name: "no partnerIDs",
			attrMap: map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{},
				},
			},
		},
		{
			name: "malformed partnerIDs field",
			attrMap: map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []badType{{}, {}, {}},
				}},
		},
	}

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			attrs := bascule.NewAttributes(test.attrMap)
			token := bascule.NewToken("bearer", "client0", attrs)

			err := requirePartnersJWTClaim(ctx, token)
			if test.shouldPass {
				assert.Nil(err)
			} else {
				assert.NotNil(err)
			}
		})
	}
}
