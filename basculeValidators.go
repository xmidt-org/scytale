package main

import (
	"context"
	"fmt"

	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/webpa-common/v2/basculechecks"
)

var requirePartnersJWTClaim bascule.ValidatorFunc = func(_ context.Context, token bascule.Token) error {
	partnerVal, ok := bascule.GetNestedAttribute(token.Attributes(), basculechecks.PartnerKeys()...)
	if !ok {
		return fmt.Errorf("partner IDs not found at keys %v", basculechecks.PartnerKeys())
	}
	ids, err := cast.ToStringSliceE(partnerVal)
	if err != nil {
		// nolint:errorlint
		return fmt.Errorf("failed to cast partner IDs to []string: %v", err)
	}
	if len(ids) < 1 {
		return fmt.Errorf("partner ID JWT claim should be a non-empty list of strings")
	}
	return nil
}
