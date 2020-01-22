package main

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/webpa-common/logging"
	"github.com/xmidt-org/wrp-go/wrp"
	"testing"
)

func TestPopulateMessagePartners(t *testing.T) {
	var tests = []struct {
		name               string
		attributes         bascule.Attributes
		expectedPartnerIDs []string
	}{
		{
			name: "partnerIDs",
			attributes: map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{"partner0", "partner1"},
				}},
			expectedPartnerIDs: []string{"partner0", "partner1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			auth := bascule.Authentication{
				Token: bascule.NewToken("bearer", "client0", test.attributes),
			}

			ctx := bascule.WithAuthentication(context.Background(), auth)

			wrpMsg := new(wrp.Message)
			populateMessage(ctx, wrpMsg, logging.DefaultLogger())
			assert.Equal(test.expectedPartnerIDs, wrpMsg.PartnerIDs)
		})
	}
}
