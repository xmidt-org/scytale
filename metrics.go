// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculejwt"

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
	AuthMissingClaims   = "auth_is_missing_expected_claims"
	AuthInvalidClaims   = "auth_invalid_claim_values"
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

var (
	errEventMetricMetadata = errors.New("could not parse jwt for additional metric metdata")
)

var (
	keyProviderFailureRegex = regexp.MustCompile(`.*key provider \d failed:.*failed to find key with key ID.*`)
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
	l          *zap.Logger
	counter    *prometheus.CounterVec
	endpoints  []*regexp.Regexp
	parserOpts []jwt.ParseOption
}

func (ae authenticatorEvent) OnEvent(e bascule.AuthenticateEvent[*http.Request]) {
	if e.Err == nil {
		ae.l.Debug("authenticator event: creds authenticated")

		return
	}

	if e.Token == nil && e.Err == nil {
		panic(errors.New("authenticator event handling failure: expected event token to be a non-nil"))
	} else if e.Source == nil {
		panic(fmt.Errorf("authenticator event handling failure: expected event source to be a non-nil: %v", e.Err))
	}

	ae.counter.With(ae.getLabels(e)).Add(1)
}

func (ae authenticatorEvent) getLabels(e bascule.AuthenticateEvent[*http.Request]) prometheus.Labels {
	ls := prometheus.Labels{
		ClientIDLabel:  "",
		PartnerIDLabel: "",
		EndpointLabel:  determineEndpoint(ae.endpoints, e.Source),
		MethodLabel:    e.Source.Method,
		OutcomeLabel:   Rejected,
		ReasonLabel:    "",
	}
	if e.Token != nil {
		ls[ClientIDLabel] = e.Token.Principal()
		ls[PartnerIDLabel] = determinePartnerID(e.Token)
	} else {
		reparseFailureMsg := "authenticator event: failed to reparse the request auth"
		opts := append([]jwt.ParseOption{jwt.WithResetValidators(true),
			jwt.WithValidator(jwt.IsIssuedAtValid()),
			jwt.WithValidator(jwt.IsNbfValid())},
			ae.parserOpts...)
		if parser, err := basculejwt.NewTokenParser(opts...); err != nil {
			ae.l.Error(reparseFailureMsg, zap.Error(errors.Join(errEventMetricMetadata, err)))
		} else if authValue := e.Source.Header.Get(basculehttp.DefaultAuthorizationHeader); len(authValue) == 0 {
			ae.l.Error(reparseFailureMsg, zap.Error(errors.Join(errEventMetricMetadata, bascule.ErrMissingCredentials)))
		} else if _, value, err := basculehttp.ParseAuthorization(authValue); err != nil {
			ae.l.Error(reparseFailureMsg, zap.Error(errors.Join(errEventMetricMetadata, err)))
		} else if t, err := parser.Parse(context.Background(), value); err == nil {
			ls[ClientIDLabel] = t.Principal()
			ls[PartnerIDLabel] = determinePartnerID(t)
		} else {
			ae.l.Debug(reparseFailureMsg, zap.Error(errors.Join(errEventMetricMetadata, err)))
		}
	}

	ae.l.Info("authenticator event: creds rejected")
	if errors.Is(e.Err, jwt.ErrTokenExpired()) {
		ls[ReasonLabel] = AuthUnsatifiedExp
	} else if errors.Is(e.Err, jwt.ErrInvalidIssuedAt()) {
		ls[ReasonLabel] = AuthUnsatifiedIAT
	} else if errors.Is(e.Err, jwt.ErrTokenNotYetValid()) {
		ls[ReasonLabel] = AuthUnsatifiedNBF
	} else if jws.IsVerificationError(e.Err) {
		ls[ReasonLabel] = AuthCannotVerify
	} else if errors.Is(e.Err, bascule.ErrInvalidCredentials) {
		ls[ReasonLabel] = AuthInvalidCreds
	} else if errors.Is(e.Err, bascule.ErrBadCredentials) {
		ls[ReasonLabel] = AuthBadCreds
	} else if _, ok := errors.AsType[*basculehttp.UnsupportedSchemeError](e.Err); ok {
		ls[ReasonLabel] = AuthInvalidScheme
	} else if errors.Is(e.Err, errAuthEmptyPrincipal) {
		ls[ReasonLabel] = AuthEmptyPrincipal
	} else if errors.Is(e.Err, errAuthUnknownScheme) {
		ls[ReasonLabel] = AuthUnknownScheme
	} else if keyProviderFailureRegex.MatchString(e.Err.Error()) {
		ls[ReasonLabel] = AuthKeyNotFind
	} else {
		ls[ReasonLabel] = UnknownReason
		ae.l.Error("authenticator event failure", zap.Error(fmt.Errorf("unexpected event error: %v", e.Err)))
	}

	return ls
}

type authorizerEvent struct {
	l         *zap.Logger
	counter   *prometheus.CounterVec
	endpoints []*regexp.Regexp
}

func (ae authorizerEvent) OnEvent(e bascule.AuthorizeEvent[*http.Request]) {
	if e.Token == nil {
		panic(fmt.Errorf("authorizer event handling failure: expected event token to be a non-nil since it passed the `authenticator` middleware without issue: %v", e.Err))
	} else if e.Resource == nil {
		panic(fmt.Errorf("authorizer event handling failure: expected event resource to be a non-nil: %v", e.Err))
	}

	ae.counter.With(ae.getLabels(e)).Add(1)
}

func (ae authorizerEvent) getLabels(e bascule.AuthorizeEvent[*http.Request]) prometheus.Labels {
	ls := prometheus.Labels{
		ClientIDLabel:  e.Token.Principal(),
		PartnerIDLabel: determinePartnerID(e.Token),
		EndpointLabel:  determineEndpoint(ae.endpoints, e.Resource),
		MethodLabel:    e.Resource.Method,
		OutcomeLabel:   Accepted,
		ReasonLabel:    "",
	}
	if e.Err == nil {
		ae.l.Debug("authorizer event: creds accepted")

		return ls
	}

	ae.l.Info("authorizer event: creds rejected")
	ls[OutcomeLabel] = Rejected
	if errors.Is(e.Err, bascule.ErrBadCredentials) {
		ls[ReasonLabel] = AuthBadCreds
	} else if errors.Is(e.Err, bascule.ErrUnauthorized) {
		ls[ReasonLabel] = NoCapabilitiesMatch
	} else if errors.Is(e.Err, errAuthMissingClaims) {
		ls[ReasonLabel] = AuthMissingClaims
	} else if errors.Is(e.Err, errAuthInvalidClaims) {
		ls[ReasonLabel] = AuthInvalidClaims
	} else {
		ls[ReasonLabel] = UnknownReason
		ae.l.Error("authorizer event failure", zap.Error(fmt.Errorf("unexpected event error: %v", e.Err)))
	}

	return ls
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
		}
		if idxs[0] == 0 {
			return strings.ReplaceAll(r.String(), " ", "_")
		}
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

	partnerIDsVal, ok := bascule.GetAttribute[any](token.(bascule.AttributesAccessor), partnerKeys...)
	if !ok {
		return AuthMissingClaims
	}

	ids, err := cast.ToStringSliceE(partnerIDsVal)
	if err != nil {
		return AuthInvalidClaims
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
