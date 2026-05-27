// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
)

var partnerKeys = []string{"allowedResources", "allowedPartners"}

var requirePartnersJWTClaim = func(_ context.Context, token bascule.Token) error {
	tt, ok := token.(tokenType)
	if !ok || tt.TokenType() != jwtTokenType {
		return nil
	}

	accessor, ok := token.(bascule.AttributesAccessor)
	if !ok {
		return fmt.Errorf("partner IDs not found at keys %v", partnerKeys)
	}

	partnerVal, ok := bascule.GetAttribute[any](accessor, partnerKeys...)
	if !ok {
		return fmt.Errorf("partner IDs not found at keys %v", partnerKeys)
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
