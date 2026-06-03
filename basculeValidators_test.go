// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequirePartnerIDs(t *testing.T) {
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
					"allowedPartners": map[string]interface{}{"partner0": true},
				}},
		},
	}

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			token := &jwtToken{principal: "client0", claims: test.attrMap}

			err := requirePartnersJWTClaim(ctx, token)
			if test.shouldPass {
				assert.Nil(err)
			} else {
				assert.NotNil(err)
			}
		})
	}
}
