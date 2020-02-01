package main

import (
	"context"
	"fmt"

	"github.com/xmidt-org/bascule"
)

//PartnerIDClaimsKey is the key path to the partnerID key in the JWT claims
const PartnerIDClaimsKey = "allowedResources.allowedPartners"

var requirePartnerIDs bascule.ValidatorFunc = func(_ context.Context, token bascule.Token) error {
	if partnerIDs, ok := token.Attributes().GetStringSlice(PartnerIDClaimsKey); !ok || len(partnerIDs) < 1 {
		return fmt.Errorf("value of JWT claim '%v' was not a non-empty list of strings", PartnerIDClaimsKey)
	}
	return nil
}
