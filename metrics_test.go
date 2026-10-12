// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculejwt"
	"github.com/xmidt-org/clortho"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const (
	testClient     = "client0"
	testPartner    = "partner0"
	testEndpoint   = "/api/v3/device"
	testUnexpected = "unexpected error"
)

// newPartnerToken returns a JWT for client0 whose allowedResources claim holds
// the given value, or no allowedResources claim when resources is nil.
func newPartnerToken(t *testing.T, resources map[string]any) bascule.Token {
	b := jwt.NewBuilder().Subject(testClient)
	if resources != nil {
		b = b.Claim(allowedResources, resources)
	}

	token, err := b.Build()
	require.NoError(t, err)

	return testJWT{token}
}

func newBasicToken(t *testing.T) bascule.Token {
	token, err := basculehttp.BasicTokenParser{}.Parse(context.Background(),
		base64.StdEncoding.EncodeToString([]byte(testClient+":secret")))
	require.NoError(t, err)

	return token
}

func newAuthCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: AuthCapabilityCheckCount},
		[]string{OutcomeLabel, ReasonLabel, ClientIDLabel, PartnerIDLabel, EndpointLabel, MethodLabel},
	)
}

func TestDeterminePartnerID(t *testing.T) {
	var tests = []struct {
		name     string
		token    func(*testing.T) bascule.Token
		expected string
	}{
		{
			name:     "nil token",
			token:    func(*testing.T) bascule.Token { return nil },
			expected: "",
		},
		{
			name:     "basic token",
			token:    newBasicToken,
			expected: "",
		},
		{
			name:     "token without attributes",
			token:    func(*testing.T) bascule.Token { return bascule.StubToken(testClient) },
			expected: AuthUnknownScheme,
		},
		{
			name:     "missing claim",
			token:    func(t *testing.T) bascule.Token { return newPartnerToken(t, nil) },
			expected: AuthMissingClaims,
		},
		{
			name: "invalid claim",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: map[string]any{testPartner: true}})
			},
			expected: AuthInvalidClaims,
		},
		{
			name: "no partners",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: []string{}})
			},
			expected: NonePartner,
		},
		{
			name: "one partner",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: []string{testPartner}})
			},
			expected: testPartner,
		},
		{
			name: "wildcard partner",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: []string{Wildcard}})
			},
			expected: WildcardPartner,
		},
		{
			name: "many partners",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: []string{testPartner, "partner1"}})
			},
			expected: ManyPartner,
		},
		{
			name: "many partners with wildcard",
			token: func(t *testing.T) bascule.Token {
				return newPartnerToken(t, map[string]any{allowedPartners: []string{testPartner, Wildcard}})
			},
			expected: WildcardPartner,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, determinePartnerID(test.token(t)))
		})
	}
}

func TestDetermineEndpoint(t *testing.T) {
	endpoints := []*regexp.Regexp{
		regexp.MustCompile(`/api/v3/device`),
		regexp.MustCompile(`/api/v3/device/[^/]+/stat`),
	}

	var tests = []struct {
		name      string
		endpoints []*regexp.Regexp
		path      string
		nilReq    bool
		expected  string
	}{
		{name: "no endpoints", path: testEndpoint, expected: NoneEndpoint},
		{name: "nil request", endpoints: endpoints, nilReq: true, expected: NoneEndpoint},
		{name: "match", endpoints: endpoints, path: testEndpoint, expected: testEndpoint},
		{name: "first match wins", endpoints: endpoints, path: "/api/v3/device/mac:112233445566/stat", expected: testEndpoint},
		{name: "match must be a prefix", endpoints: endpoints, path: "/other/api/v3/device", expected: NotRecognizedEndpoint},
		{name: "no match", endpoints: endpoints, path: "/api/v3/hooks", expected: NotRecognizedEndpoint},
		{
			name:      "spaces replaced",
			endpoints: []*regexp.Regexp{regexp.MustCompile(`/api/v3/device ?`)},
			path:      testEndpoint,
			expected:  "/api/v3/device_?",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var req *http.Request
			if !test.nilReq {
				req = httptest.NewRequest(http.MethodGet, test.path, nil)
			}

			assert.Equal(t, test.expected, determineEndpoint(test.endpoints, req))
		})
	}
}

func TestAuthenticatorEvent(t *testing.T) {
	endpoints := []*regexp.Regexp{regexp.MustCompile(`/api/v3/device`)}
	partnerToken := func(t *testing.T) bascule.Token {
		return newPartnerToken(t, map[string]any{allowedPartners: []string{testPartner}})
	}

	var tests = []struct {
		name          string
		token         func(*testing.T) bascule.Token
		err           error
		expectCount   bool
		expectedLabel prometheus.Labels
		expectedLevel zapcore.Level
	}{
		{
			name:          "authenticated",
			token:         partnerToken,
			expectedLevel: zapcore.DebugLevel,
		},
		{
			name:        "rejected with token",
			token:       partnerToken,
			err:         errors.Join(bascule.ErrBadCredentials, basculejwt.ErrExpired),
			expectCount: true,
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  testClient,
				PartnerIDLabel: testPartner,
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Rejected,
				ReasonLabel:    AuthUnsatifiedExp,
			},
			expectedLevel: zapcore.InfoLevel,
		},
		{
			name:        "rejected without token",
			token:       func(*testing.T) bascule.Token { return nil },
			err:         bascule.ErrMissingCredentials,
			expectCount: true,
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  "",
				PartnerIDLabel: "",
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Rejected,
				ReasonLabel:    AuthMissingCreds,
			},
			expectedLevel: zapcore.InfoLevel,
		},
		{
			name:        testUnexpected,
			token:       func(*testing.T) bascule.Token { return nil },
			err:         errors.New("unexpected"),
			expectCount: true,
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  "",
				PartnerIDLabel: "",
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Rejected,
				ReasonLabel:    UnknownReason,
			},
			expectedLevel: zapcore.ErrorLevel,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			core, logs := observer.New(zapcore.DebugLevel)
			counter := newAuthCounter()
			ae := authenticatorEvent{l: zap.New(core), counter: counter, endpoints: endpoints}

			ae.OnEvent(bascule.AuthenticateEvent[*http.Request]{
				Source: httptest.NewRequest(http.MethodPost, testEndpoint, nil),
				Token:  test.token(t),
				Err:    test.err,
			})

			if test.expectCount {
				assert.Equal(1, testutil.CollectAndCount(counter))
				assert.Equal(float64(1), testutil.ToFloat64(counter.With(test.expectedLabel)))
			} else {
				assert.Zero(testutil.CollectAndCount(counter))
			}

			entries := logs.All()
			if assert.Len(entries, 1) {
				assert.Equal(test.expectedLevel, entries[0].Level)
			}
		})
	}
}

func TestAuthenticatorEventNilSource(t *testing.T) {
	ae := authenticatorEvent{l: zap.NewNop(), counter: newAuthCounter()}
	assert.Panics(t, func() {
		ae.OnEvent(bascule.AuthenticateEvent[*http.Request]{Err: bascule.ErrBadCredentials})
	})
}

func TestAuthorizerEvent(t *testing.T) {
	endpoints := []*regexp.Regexp{regexp.MustCompile(`/api/v3/device`)}

	var tests = []struct {
		name          string
		err           error
		expectedLabel prometheus.Labels
		expectLog     bool
		expectedLevel zapcore.Level
	}{
		{
			name: "authorized",
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  testClient,
				PartnerIDLabel: testPartner,
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Accepted,
				ReasonLabel:    "",
			},
		},
		{
			name: "unauthorized",
			err:  bascule.ErrUnauthorized,
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  testClient,
				PartnerIDLabel: testPartner,
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Rejected,
				ReasonLabel:    NoCapabilitiesMatch,
			},
			expectLog:     true,
			expectedLevel: zapcore.InfoLevel,
		},
		{
			name: testUnexpected,
			err:  errors.New("unexpected"),
			expectedLabel: prometheus.Labels{
				ClientIDLabel:  testClient,
				PartnerIDLabel: testPartner,
				EndpointLabel:  testEndpoint,
				MethodLabel:    http.MethodPost,
				OutcomeLabel:   Rejected,
				ReasonLabel:    UnknownReason,
			},
			expectLog:     true,
			expectedLevel: zapcore.ErrorLevel,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)
			core, logs := observer.New(zapcore.DebugLevel)
			counter := newAuthCounter()
			ae := authorizerEvent{l: zap.New(core), counter: counter, endpoints: endpoints}

			ae.OnEvent(bascule.AuthorizeEvent[*http.Request]{
				Resource: httptest.NewRequest(http.MethodPost, testEndpoint, nil),
				Token:    newPartnerToken(t, map[string]any{allowedPartners: []string{testPartner}}),
				Err:      test.err,
			})

			assert.Equal(1, testutil.CollectAndCount(counter))
			assert.Equal(float64(1), testutil.ToFloat64(counter.With(test.expectedLabel)))

			entries := logs.All()
			if !test.expectLog {
				assert.Empty(entries)
			} else if assert.Len(entries, 1) {
				assert.Equal(test.expectedLevel, entries[0].Level)
			}
		})
	}
}

func TestAuthorizerEventPanics(t *testing.T) {
	ae := authorizerEvent{l: zap.NewNop(), counter: newAuthCounter()}
	req := httptest.NewRequest(http.MethodPost, testEndpoint, nil)

	assert.Panics(t, func() {
		ae.OnEvent(bascule.AuthorizeEvent[*http.Request]{Resource: req, Err: bascule.ErrUnauthorized})
	}, "nil token")
	assert.Panics(t, func() {
		ae.OnEvent(bascule.AuthorizeEvent[*http.Request]{Token: bascule.StubToken(testClient), Err: bascule.ErrUnauthorized})
	}, "nil resource")
}

func TestAuthenticateReason(t *testing.T) {
	var tests = []struct {
		name     string
		err      error
		expected string
	}{
		{name: "expired", err: errors.Join(bascule.ErrBadCredentials, basculejwt.ErrExpired), expected: AuthUnsatifiedExp},
		{name: "iat", err: errors.Join(bascule.ErrBadCredentials, basculejwt.ErrInvalidIssuedAt), expected: AuthUnsatifiedIAT},
		{name: "nbf", err: errors.Join(bascule.ErrBadCredentials, basculejwt.ErrNotYetValid), expected: AuthUnsatifiedNBF},
		{name: "key not found", err: errors.Join(basculejwt.ErrInvalidSignature, clortho.ErrKeyNotFound), expected: AuthKeyNotFind},
		{name: "invalid signature", err: errors.Join(bascule.ErrBadCredentials, basculejwt.ErrInvalidSignature), expected: AuthCannotVerify},
		{name: "missing creds", err: bascule.ErrMissingCredentials, expected: AuthMissingCreds},
		{name: "invalid creds", err: bascule.ErrInvalidCredentials, expected: AuthInvalidCreds},
		{name: "empty principal", err: fmt.Errorf("%w: %w", bascule.ErrBadCredentials, errAuthEmptyPrincipal), expected: AuthEmptyPrincipal},
		{name: "bad creds", err: bascule.ErrBadCredentials, expected: AuthBadCreds},
		{name: "unsupported scheme", err: &basculehttp.UnsupportedSchemeError{}, expected: AuthInvalidScheme},
		{name: testUnexpected, err: errors.New("unexpected"), expected: UnknownReason},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, authenticateReason(test.err))
		})
	}
}

func TestAuthorizeReason(t *testing.T) {
	var tests = []struct {
		name     string
		err      error
		expected string
	}{
		{name: "missing claims", err: errAuthMissingClaims, expected: AuthMissingClaims},
		{name: "invalid claims", err: fmt.Errorf("%w: should not be empty", errAuthInvalidClaims), expected: AuthInvalidClaims},
		{name: "bad creds", err: bascule.ErrBadCredentials, expected: AuthBadCreds},
		{name: "unauthorized", err: bascule.ErrUnauthorized, expected: NoCapabilitiesMatch},
		{name: testUnexpected, err: errors.New("unexpected"), expected: UnknownReason},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, authorizeReason(test.err))
		})
	}
}
