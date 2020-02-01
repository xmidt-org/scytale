package main

import (
	"context"
	"fmt"

	"github.com/xmidt-org/webpa-common/basculechecks"

	"github.com/xmidt-org/bascule"
)

var requirePartnerIDs bascule.ValidatorFunc = func(_ context.Context, token bascule.Token) error {
	ids, ok := token.Attributes().GetStringSlice(basculechecks.PartnerKey)
	if !ok {
		return fmt.Errorf("Couldn't get the partner IDs")
	}

	if len(ids) < 1 {
		return errors.New("JWT must provide claims for partnerIDs")
	}
	return nil
}
