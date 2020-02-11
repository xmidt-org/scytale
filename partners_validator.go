package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/metrics"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/webpa-common/basculechecks"
	"github.com/xmidt-org/webpa-common/xhttp"
	"github.com/xmidt-org/wrp-go/wrp"
)

//partnerAuthority errors
var (
	ErrTokenMissing           = &xhttp.Error{Code: http.StatusInternalServerError, Text: "No JWT Token was found in context"}
	ErrTokenTypeMismatch      = &xhttp.Error{Code: http.StatusInternalServerError, Text: "Token must be a JWT"}
	ErrPIDMissing             = &xhttp.Error{Code: http.StatusBadRequest, Text: "WRP PartnerIDs field must not be empty"}
	ErrInvalidAllowedPartners = &xhttp.Error{Code: http.StatusForbidden, Text: "AllowedPartners JWT claim must be a non-empty list of strings"}
	ErrPIDMismatch            = &xhttp.Error{Code: http.StatusForbidden, Text: "Unauthorized partners credentials in WRP message"}
)

type WRPCheckConfig struct {
	Type string
}

type partnersAuthority interface {
	//authorizeWRP should run the scytale partnerID checks against incoming WRP messages
	//It takes a pointer to the wrp message as it may modify it in some cases. It returns
	//true if such modification was made. An error is returned in cases the validator
	//check failed and they are go-kit HTTP response error encoder friendly
	authorizeWRP(context.Context, *wrp.Message) (bool, error)
}

type partnersValidator struct {
	strict                  bool
	receivedWRPMessageCount metrics.Counter
}

func (p *partnersValidator) withFailure(labelValues ...string) metrics.Counter {
	if !p.strict {
		return p.withSuccess(labelValues...)
	}
	return p.receivedWRPMessageCount.With(append(labelValues, OutcomeLabel, Rejected)...)
}

func (p *partnersValidator) withSuccess(labelValues ...string) metrics.Counter {
	return p.receivedWRPMessageCount.With(append(labelValues, OutcomeLabel, Accepted)...)
}

func (p *partnersValidator) authorizeWRP(ctx context.Context, message *wrp.Message) (bool, error) {
	var (
		auth, ok    = bascule.FromContext(ctx)
		satClientID = "none"
	)

	if !ok {
		p.withFailure(ClientIDLabel, satClientID, ReasonLabel, TokenMissing).Add(1)

		if p.strict {
			return false, ErrTokenMissing
		}
		return false, nil
	}

	token := auth.Token

	if token.Type() != "jwt" {
		p.withFailure(ClientIDLabel, satClientID, ReasonLabel, TokenTypeMismatch).Add(1)

		if p.strict {
			return false, ErrTokenTypeMismatch
		}
		return false, nil
	}

	attributes := token.Attributes()

	if principal := token.Principal(); len(principal) > 0 {
		satClientID = principal
	}

	allowedPartners, ok := attributes.GetStringSlice(basculechecks.PartnerKey)

	if !ok || len(allowedPartners) < 1 {
		p.withFailure(ClientIDLabel, satClientID, ReasonLabel, JWTPIDInvalid).Add(1)

		if p.strict {
			return false, ErrInvalidAllowedPartners
		}

		return false, nil
	}

	if len(message.PartnerIDs) < 1 {
		p.withFailure(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMissing).Add(1)

		if p.strict {
			return false, ErrPIDMissing
		}

		message.PartnerIDs = allowedPartners
		return true, nil
	}

	if contains(allowedPartners, "*") {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, JWTPIDWildcard).Add(1)
		return false, nil
	}

	if isSubset(message.PartnerIDs, allowedPartners) {
		p.withSuccess(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMatch).Add(1)
		return false, nil
	}

	p.withFailure(ClientIDLabel, satClientID, ReasonLabel, WRPPIDMismatch).Add(1)
	if p.strict {
		return false, ErrPIDMismatch
	}

	message.PartnerIDs = allowedPartners
	return true, nil
}

//returns true if list contains str
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
