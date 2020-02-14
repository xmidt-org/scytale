package main

import (
	"context"
	"fmt"

	"github.com/xmidt-org/webpa-common/basculechecks"

	"github.com/xmidt-org/bascule"
)

var requirePartnersJWTClaim bascule.ValidatorFunc = func(_ context.Context, token bascule.Token) error {
	ids, ok := token.Attributes().GetStringSlice(basculechecks.PartnerKey)
	if !ok || len(ids) < 1 {
		return fmt.Errorf("'%s' JWT claim should be a non-empty list of strings", basculechecks.PartnerKey)
	}
	return nil
}
