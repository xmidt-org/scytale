package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/webpa-common/xmetrics"
	"github.com/xmidt-org/wrp-go/wrp"
)

func TestEnsureWRPMessageIntegrity(t *testing.T) {
	var tests = []struct {
		name               string
		wrpMsg             *wrp.Message
		attributes         bascule.Attributes
		expectedPartnerIDs []string
	}{
		{
			name: "partnerIDsPresent",
			wrpMsg: &wrp.Message{
				PartnerIDs: []string{"partner0"},
			},
			attributes: bascule.NewAttributesFromMap(map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{"partner0", "partner1"},
				}}),
			expectedPartnerIDs: []string{"partner0"},
		},

		{
			name:   "partnerIDsAbsent",
			wrpMsg: new(wrp.Message),
			attributes: bascule.NewAttributesFromMap(map[string]interface{}{
				"allowedResources": map[string]interface{}{
					"allowedPartners": []string{"partner0", "partner1"},
				}}),
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

			r, err := xmetrics.NewRegistry(&xmetrics.Options{}, Metrics)
			assert.Nil(err)
			ensureWRPMessageIntegrity(ctx, test.wrpMsg, NewEmptyWRPPartnerIDsCounter(r))
			assert.Equal(test.expectedPartnerIDs, test.wrpMsg.PartnerIDs)
		})
	}
}
