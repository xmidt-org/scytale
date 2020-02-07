package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/metrics"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/wrp-go/wrp"
)

//Perhaps this should live in bascule as a utility struct
type codedError struct {
	error
	code int
}

func (e *codedError) StatusCode() int {
	return e.code
}

type partnersValidator struct {
	Strict                  bool
	receivedWRPMessageCount metrics.Counter
}

func (p *partnersValidator) withFailure(labelValues ...string) metrics.Counter {
	if !p.Strict {
		return p.withSuccess(labelValues...)
	}
	return p.receivedWRPMessageCount.With(append(labelValues, OutcomeLabel, Rejected)...)
}

func (p *partnersValidator) withSuccess(labelValues ...string) metrics.Counter {
	return p.receivedWRPMessageCount.With(append(labelValues, OutcomeLabel, Accepted)...)
}

//ensure the JWT token has a non-empty value for the allowedPartners claim
func (p *partnersValidator) ensureJWTPartners(_ context.Context, token bascule.Token) error {
	if partnerIDs, ok := token.Attributes().GetStringSlice(PartnerIDClaimsKey); !ok || len(partnerIDs) < 1 {
		p.withFailure(ClientIDLabel, token.Principal(), ReasonLabel, JWTPIDMissing).Add(1)
		return fmt.Errorf("value of JWT claim '%s' was not a non-empty list of strings", PartnerIDClaimsKey)
	}
	return nil
}

func (p *partnersValidator) check(ctx context.Context, token bascule.Token) error {
	entity, ok := FromContext(ctx)
	if !ok {
		return errors.New("Could not fetch WRP entity from context")
	}

	var (
		message     = entity.Message
		satClientID = "none"
		attributes  = token.Attributes()
	)

	if principal := token.Principal(); len(principal) > 0 {
		satClientID = principal
	}

	var JWTPartnerIDs []string

	if len(message.PartnerIDs) < 1 {
		p.withFailure(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMissing).Add(1)

		if p.Strict {
			return &codedError{code: http.StatusBadRequest, error: errors.New("WRP PartnerIDs field must not be empty")}
		}

		if partnerIDs, ok := attributes.GetStringSlice(PartnerIDClaimsKey); ok && len(partnerIDs) > 0 {
			message.PartnerIDs = partnerIDs
			JWTPartnerIDs = partnerIDs
		} else {
			return errors.New("JWT allowedPartners could not be used to compensate for missing PID in WRP")
		}
	}

	if contains(JWTPartnerIDs, "*") {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, JWTPIDWildcard).Add(1)
		return nil
	}

	if isSubset(message.PartnerIDs, JWTPartnerIDs) {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMatch).Add(1)
		return nil
	}

	p.withFailure(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMismatch).Add(1)
	if p.Strict {
		return errors.New("The JWT allowedPartners claim is not a superset of the non-empty WRP PartnerIDs field")
	}

	return nil
}

func contains(list []string, str string) bool {
	for _, e := range list {
		if e == str {
			return true
		}
	}
	return false
}

//returns true if a is a subset of b
func isSubset(a, b []string) bool {
	m := make(map[string]struct{})

	for _, e := range b {
		m[e] = struct{}{}
	}

	for _, e := range a {
		if _, ok := m[e]; !ok {
			return false
		}

	}
	return true
}

//AuthorizeWRP runs the scytale partnerID checks against the incoming WRP message
//It takes a pointer to the wrp message as it needs to perform changes to it in
//some cases.
//TODO:
func (p *partnersValidator) authorizeWRP(ctx context.Context, message *wrp.Message) (error, bool) {
	return nil, false
}
