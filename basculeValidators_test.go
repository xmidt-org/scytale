package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
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
				}}),
			shouldPass: true,
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
					"allowedPartners": []int{0, 1, 2},
				}},
		},
	}

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			attrs := bascule.NewAttributesFromMap(test.attrMap)
			token := bascule.NewToken("bearer", "client0", attrs)

			err := requirePartnerIDs(ctx, token)
			if test.shouldPass {
				assert.Nil(err)
			} else {
				assert.NotNil(err)
			}
		})
	}
}
