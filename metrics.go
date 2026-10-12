// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculejwt"
	"github.com/xmidt-org/clortho"

	// nolint: staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
	"go.uber.org/zap"
)

const Wildcard = "*"

// Names for our metrics
const (
	ReceivedWRPMessageCount  = "received_wrp_message_total"
	AuthCapabilityCheckCount = "auth_capability_check"
)

// labels
const (
	ClientIDLabel  = "clientid"
	OutcomeLabel   = "outcome"
	ReasonLabel    = "reason"
	PartnerIDLabel = "partnerid"
	EndpointLabel  = "endpoint"
	MethodLabel    = "method"
)

// label values
const (
	Accepted = "accepted"
	Rejected = "rejected"

	TokenMissing = "token_not_found"
	// nolint: gosec
	TokenTypeMismatch = "token_type_mismatch"

	WRPPIDMissing  = "wrp_pid_missing"
	WRPPIDMismatch = "wrp_pid_mismatch"
	WRPPIDMatch    = "wrp_pid_match"

	JWTPIDWildcard = "jwt_pid_wildcard"
	JWTPIDInvalid  = "jwt_pid_invalid"
)

// Auth related label values
const (
	// reasons
	UnknownReason       = "unknown"
	AuthMissingClaims   = "missing_expected_claims"
	AuthInvalidClaims   = "invalid_claim_values"
	AuthInvalidCreds    = "invalid_creds"
	AuthCannotVerify    = "could_not_verify_message"
	AuthInvalidScheme   = "invalid_scheme"
	AuthUnknownScheme   = "unknown_scheme"
	AuthEmptyPrincipal  = "empty_principal"
	AuthUnsatifiedExp   = "exp_not_satisfied"
	AuthUnsatifiedIAT   = "iat_not_satisfied"
	AuthUnsatifiedNBF   = "nbf_not_satisfied"
	AuthKeyNotFind      = "jwk_key_not_found"
	AuthBadCreds        = "bad_creds"
	AuthMissingCreds    = "missing_creds"
	NoCapabilitiesMatch = "no_capabilities_match"
	// partners
	NonePartner     = "none"
	WildcardPartner = "wildcard"
	ManyPartner     = "many"
	// endpoints
	NoneEndpoint          = "no_endpoints"
	NotRecognizedEndpoint = "not_recognized"
)

// Metrics returns the metrics relevant to this package
func Metrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		{
			Name:       ReceivedWRPMessageCount,
			Type:       xmetrics.CounterType,
			Help:       "Number of WRP Messages successfully decoded and ready for fanout.",
			LabelNames: []string{OutcomeLabel, ClientIDLabel, ReasonLabel},
		},
		{
			Name:       AuthCapabilityCheckCount,
			Type:       xmetrics.CounterType,
			Help:       "Counter for the capability checker, providing outcome information by client, partner, and endpoint",
			LabelNames: []string{OutcomeLabel, ReasonLabel, ClientIDLabel, PartnerIDLabel, EndpointLabel, MethodLabel},
		},
	}
}

type authenticatorEvent struct {
	l         *zap.Logger
	counter   *prometheus.CounterVec
	endpoints []*regexp.Regexp
}

func (ae authenticatorEvent) OnEvent(e bascule.AuthenticateEvent[*http.Request]) {
	if e.Err == nil {
		ae.l.Debug("authenticator event: creds authenticated")

		return
	} else if e.Source == nil {
		panic(fmt.Errorf("authenticator event handling failure: expected event source to be a non-nil: %v", e.Err))
	}

	ls := newAuthLabels(ae.endpoints, e.Source, e.Token, Rejected, authenticateReason(e.Err))
	logRejection(ae.l, "authenticator", ls, e.Err)
	ae.counter.With(ls).Add(1)
}

// authenticateReason maps an authentication error to a metric reason.  Errors
// that wrap bascule.ErrBadCredentials must be matched before it.
func authenticateReason(err error) string {
	switch {
	case errors.Is(err, basculejwt.ErrExpired):
		return AuthUnsatifiedExp
	case errors.Is(err, basculejwt.ErrInvalidIssuedAt):
		return AuthUnsatifiedIAT
	case errors.Is(err, basculejwt.ErrNotYetValid):
		return AuthUnsatifiedNBF
	case errors.Is(err, clortho.ErrKeyNotFound):
		return AuthKeyNotFind
	case errors.Is(err, basculejwt.ErrInvalidSignature):
		return AuthCannotVerify
	case errors.Is(err, bascule.ErrMissingCredentials):
		return AuthMissingCreds
	case errors.Is(err, bascule.ErrInvalidCredentials):
		return AuthInvalidCreds
	case errors.Is(err, errAuthEmptyPrincipal):
		return AuthEmptyPrincipal
	case errors.Is(err, bascule.ErrBadCredentials):
		return AuthBadCreds
	case errors.As(err, new(*basculehttp.UnsupportedSchemeError)):
		return AuthInvalidScheme
	default:
		return UnknownReason
	}
}

type authorizerEvent struct {
	l         *zap.Logger
	counter   *prometheus.CounterVec
	endpoints []*regexp.Regexp
}

func (ae authorizerEvent) OnEvent(e bascule.AuthorizeEvent[*http.Request]) {
	if e.Err == nil {
		ae.counter.With(newAuthLabels(ae.endpoints, e.Resource, e.Token, Accepted, "")).Add(1)

		return
	} else if e.Token == nil {
		panic(fmt.Errorf("authorizer event handling failure: expected event token to be a non-nil since it passed the `authenticator` middleware without issue: %v", e.Err))
	} else if e.Resource == nil {
		panic(fmt.Errorf("authorizer event handling failure: expected event resource to be a non-nil: %v", e.Err))
	}

	ls := newAuthLabels(ae.endpoints, e.Resource, e.Token, Rejected, authorizeReason(e.Err))
	logRejection(ae.l, "authorizer", ls, e.Err)
	ae.counter.With(ls).Add(1)
}

// authorizeReason maps an authorization error to a metric reason.  Errors that
// wrap bascule.ErrBadCredentials must be matched before it.
func authorizeReason(err error) string {
	switch {
	case errors.Is(err, errAuthMissingClaims):
		return AuthMissingClaims
	case errors.Is(err, errAuthInvalidClaims):
		return AuthInvalidClaims
	case errors.Is(err, bascule.ErrBadCredentials):
		return AuthBadCreds
	case errors.Is(err, bascule.ErrUnauthorized):
		return NoCapabilitiesMatch
	default:
		return UnknownReason
	}
}

// newAuthLabels builds the AuthCapabilityCheckCount labels for an auth event.
func newAuthLabels(endpoints []*regexp.Regexp, req *http.Request, token bascule.Token, outcome, reason string) prometheus.Labels {
	var client string
	if token != nil {
		client = token.Principal()
	}

	return prometheus.Labels{
		ClientIDLabel:  client,
		PartnerIDLabel: determinePartnerID(token),
		EndpointLabel:  determineEndpoint(endpoints, req),
		MethodLabel:    req.Method,
		OutcomeLabel:   outcome,
		ReasonLabel:    reason,
	}
}

// logRejection logs a rejected auth event, as an error when the reason is unknown.
func logRejection(l *zap.Logger, stage string, ls prometheus.Labels, err error) {
	fs := []zap.Field{
		zap.String("sat_client_id", ls[ClientIDLabel]),
		zap.String("sat_partner_id", ls[PartnerIDLabel]),
		zap.String("sat_rejection_reason", ls[ReasonLabel]),
	}
	if ls[ReasonLabel] == UnknownReason {
		l.Error(stage+" event failure", append(fs, zap.Error(fmt.Errorf("unexpected event error: %v", err)))...)
	} else {
		l.Info(stage+" event: creds rejected", fs...)
	}
}

func determineEndpoint(endpoints []*regexp.Regexp, req *http.Request) string {
	if len(endpoints) == 0 || req == nil {
		return NoneEndpoint
	}

	url := req.URL.EscapedPath()
	for _, r := range endpoints {
		idxs := r.FindStringIndex(url)
		if len(idxs) == 0 {
			continue
		} else if idxs[0] != 0 {
			continue
		}

		return strings.ReplaceAll(r.String(), " ", "_")
	}

	return NotRecognizedEndpoint
}

func determinePartnerID(token bascule.Token) string {
	switch token.(type) {
	case basculehttp.BasicToken, nil:
		return ""
	case bascule.AttributesAccessor:
	default:
		return AuthUnknownScheme
	}

	ids, err := getPartnerIDs(token)
	if errors.Is(err, errAuthInvalidClaims) {
		return AuthInvalidClaims
	} else if err != nil {
		return AuthMissingClaims
	}

	if len(ids) == 0 {
		return NonePartner
	}

	if len(ids) == 1 {
		if ids[0] == Wildcard {
			return WildcardPartner
		}

		return ids[0]
	}

	if slices.Contains(ids, Wildcard) {
		return WildcardPartner
	}

	return ManyPartner
}
