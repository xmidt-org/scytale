// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"net/http"
	"slices"

	"github.com/go-kit/kit/metrics"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculejwt"
	"github.com/xmidt-org/webpa-common/v2/xhttp"
	"github.com/xmidt-org/wrp-go/v3"
)

// partnerAuthority errors
var (
	ErrTokenMissing           = &xhttp.Error{Code: http.StatusInternalServerError, Text: "No JWT Token was found in context"}
	ErrTokenTypeMismatch      = &xhttp.Error{Code: http.StatusInternalServerError, Text: "Token must be a JWT"}
	ErrPIDMissing             = &xhttp.Error{Code: http.StatusBadRequest, Text: "WRP PartnerIDs field must not be empty"}
	ErrInvalidAllowedPartners = &xhttp.Error{Code: http.StatusForbidden, Text: "AllowedPartners JWT claim was either not found or an empty list"}
	ErrPIDMismatch            = &xhttp.Error{Code: http.StatusForbidden, Text: "Unauthorized partners credentials in WRP message"}
)

// WRPCheckConfig drives the WRP Access control configuration when enabled
type WRPCheckConfig struct {
	Type string
}

// wrpAccessAuthority describes behavior for authorizing WRP messages
// against defined access policies.
type wrpAccessAuthority interface {
	authorizeWRP(context.Context, *wrp.Message) (bool, error)
}

// wrpPartnersAuthority defines the access policy for which WRP messages
// are authorized against the partners credentials of the message creator
type wrpPartnersAccess struct {
	strict                  bool
	receivedWRPMessageCount metrics.Counter
}

func (p *wrpPartnersAccess) withSuccess(labelValues ...string) metrics.Counter {
	return p.receivedWRPMessageCount.With(append(labelValues, OutcomeLabel, Accepted)...)
}

// reject records a failed check and returns err when the policy is strictly
// enforced, or nil when it is not.
func (p *wrpPartnersAccess) reject(clientID, reason string, err error) error {
	if !p.strict {
		p.withSuccess(ClientIDLabel, clientID, ReasonLabel, reason).Add(1)
		return nil
	}

	p.receivedWRPMessageCount.With(ClientIDLabel, clientID, ReasonLabel, reason, OutcomeLabel, Rejected).Add(1)
	return err
}

// correct rejects the WRP's partner ids, replacing them with the allowed ones
// when the policy is not strictly enforced.
func (p *wrpPartnersAccess) correct(message *wrp.Message, allowedPartners []string, clientID, reason string, err error) (bool, error) {
	if err := p.reject(clientID, reason, err); err != nil {
		return false, err
	}

	message.PartnerIDs = allowedPartners
	return true, nil
}

// authorizeWRP runs the partners access policy against the WRP and returns an error if the check fails.
// When the policy is not strictly enforced, failures are counted but not returned, and true is returned
// when the WRP's partner ids were corrected to those allowed by the token.
func (p *wrpPartnersAccess) authorizeWRP(ctx context.Context, message *wrp.Message) (bool, error) {
	satClientID := "none"
	token, ok := bascule.Get(ctx)
	if !ok {
		return false, p.reject(satClientID, TokenMissing, ErrTokenMissing)
	}

	switch token.(type) {
	case basculejwt.Claims, basculehttp.BasicToken:
	default:
		return false, p.reject(satClientID, TokenTypeMismatch, ErrTokenTypeMismatch)
	}

	if principal := token.Principal(); len(principal) > 0 {
		satClientID = principal
	}

	allowedPartners, err := getPartnerIDs(token)
	if err != nil || len(allowedPartners) < 1 {
		return false, p.reject(satClientID, JWTPIDInvalid, ErrInvalidAllowedPartners)
	}

	if len(message.PartnerIDs) < 1 {
		return p.correct(message, allowedPartners, satClientID, WRPPIDMissing, ErrPIDMissing)
	}

	if slices.Contains(allowedPartners, Wildcard) {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, JWTPIDWildcard).Add(1)
		return false, nil
	}

	if isSubset(message.PartnerIDs, allowedPartners) {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMatch).Add(1)
		return false, nil
	}

	return p.correct(message, allowedPartners, satClientID, WRPPIDMismatch, ErrPIDMismatch)
}

// returns true if a is a subset of b
func isSubset(a, b []string) bool {
	m := make(map[string]bool)

	for _, e := range b {
		m[e] = true
	}

	for _, e := range a {
		if !m[e] {
			return false
		}
	}
	return true
}
