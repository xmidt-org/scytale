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
		attributes bascule.Attributes
		shouldPass bool
	}{
		{
			name: "partnerIDs",
			attributes: bascule.NewAttributesFromMap(map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{"partner0", "partner1"},
				}}),
			shouldPass: true,
		},

		{
			name:       "no partnerIDs",
			attributes: bascule.NewAttributes(),
		},
		{
			name: "malformed partnerIDs field",
			attributes: bascule.NewAttributesFromMap(map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []bool{true},
				}}),
		},
	}

	ctx := context.Background()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			token := bascule.NewToken("bearer", "client0", test.attributes)

			err := requirePartnerIDs(ctx, token)
			if test.shouldPass {
				assert.Nil(err)
			} else {
				assert.NotNil(err)
			}
		})
	}
}
