// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehash"
	"golang.org/x/crypto/bcrypt"
)

const (
	allowedPartners  = "allowedPartners"
	allowedResources = "allowedResources"
)

var (
	errAuthMissingClaims  = fmt.Errorf("%w: missing partner related keys", bascule.ErrBadCredentials)
	errAuthInvalidClaims  = fmt.Errorf("%w: invalid `%s` claim(s)", bascule.ErrBadCredentials, partnerKeys)
	errAuthEmptyPrincipal = errors.New("empty principal")
)

var partnerKeys = []string{allowedResources, allowedPartners}

// newBasicCredentials hashes the configured basic auth passwords so they can be
// checked with a constant time comparison.  The plaintext is already present in
// the configuration, so a high bcrypt cost would only add per-request latency.
func newBasicCredentials(allowed map[string]string) (basculehash.Credentials, basculehash.Comparer, error) {
	hasher := basculehash.Bcrypt{Cost: bcrypt.MinCost}
	creds := make(basculehash.Principals, len(allowed))
	for user, password := range allowed {
		digest, err := hasher.Hash([]byte(password))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hash password for basic auth user `%s`: %w", user, err)
		}

		creds[user] = digest
	}

	return creds, hasher, nil
}

// getPartnerIDs returns the partner ids claimed by the token.
func getPartnerIDs(token bascule.Token) ([]string, error) {
	accessor, ok := token.(bascule.AttributesAccessor)
	if !ok {
		return nil, errAuthMissingClaims
	}

	partnerVal, ok := bascule.GetAttribute[any](accessor, partnerKeys...)
	if !ok {
		return nil, errAuthMissingClaims
	}

	ids, err := cast.ToStringSliceE(partnerVal)
	if err != nil {
		return nil, errors.Join(errAuthInvalidClaims, err)
	}

	return ids, nil
}

func jwtClaimPartnerIDsValidator(ctx context.Context, req *http.Request, token bascule.Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	ids, err := getPartnerIDs(token)
	if err != nil {
		return err
	}

	if len(ids) == 0 {
		return fmt.Errorf("%w: should not be empty", errAuthInvalidClaims)
	}

	return nil
}

func authPrincipalValidator(ctx context.Context, token bascule.Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if token.Principal() == "" {
		return fmt.Errorf("%w: %w", bascule.ErrBadCredentials, errAuthEmptyPrincipal)
	}

	return nil
}
