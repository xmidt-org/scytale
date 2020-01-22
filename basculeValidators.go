package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/xmidt-org/bascule"
)

type allowedResources struct {
	AllowedPartners []string
}

type claims struct {
	AllowedResources allowedResources
}

var requirePartnerIDs bascule.ValidatorFunc = func(_ context.Context, token bascule.Token) error {
	var claims claims

	err := mapstructure.Decode(token.Attributes(), &claims)

	if err != nil {
		return fmt.Errorf("Unexpected JWT claim format for partnerIDs: %v", err)
	}

	if len(claims.AllowedResources.AllowedPartners) < 1 {
		return errors.New("JWT must provide claims for partnerIDs")
	}

	return nil
}
