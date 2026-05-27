// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
)

func TestJWTTokenMethods(t *testing.T) {
	tests := []struct {
		name          string
		token         *jwtToken
		key           string
		expectedValue any
		expectedFound bool
	}{
		{
			name: "get existing key",
			token: &jwtToken{
				principal: "clientA",
				claims: map[string]any{
					"partner": "p0",
				},
			},
			key:           "partner",
			expectedValue: "p0",
			expectedFound: true,
		},
		{
			name: "get missing key",
			token: &jwtToken{
				principal: "clientA",
				claims:    map[string]any{},
			},
			key:           "partner",
			expectedValue: nil,
			expectedFound: false,
		},
		{
			name:          "nil token",
			token:         nil,
			key:           "partner",
			expectedValue: nil,
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.token != nil {
				assert.Equal(t, tt.token.principal, tt.token.Principal())
				assert.Equal(t, jwtTokenType, tt.token.TokenType())
			}

			value, found := tt.token.Get(tt.key)
			assert.Equal(t, tt.expectedFound, found)
			assert.Equal(t, tt.expectedValue, value)
		})
	}
}

func TestValidateTimeClaimsWithLeeway(t *testing.T) {
	const now int64 = 1_000
	origTimeFunc := jwtv4.TimeFunc
	jwtv4.TimeFunc = func() time.Time {
		return time.Unix(now, 0)
	}
	defer func() {
		jwtv4.TimeFunc = origTimeFunc
	}()

	tests := []struct {
		name      string
		claims    jwtv4.MapClaims
		leeway    Leeway
		shouldErr bool
	}{
		{
			name:      "no temporal claims",
			claims:    jwtv4.MapClaims{"sub": "client0"},
			leeway:    Leeway{},
			shouldErr: false,
		},
		{
			name:      "expired token without leeway",
			claims:    jwtv4.MapClaims{"exp": float64(now - 1)},
			leeway:    Leeway{},
			shouldErr: true,
		},
		{
			name:      "expired token with negative exp leeway",
			claims:    jwtv4.MapClaims{"exp": float64(now - 5)},
			leeway:    Leeway{EXP: -10},
			shouldErr: false,
		},
		{
			name:      "future nbf without leeway",
			claims:    jwtv4.MapClaims{"nbf": float64(now + 1)},
			leeway:    Leeway{},
			shouldErr: true,
		},
		{
			name:      "future nbf with negative leeway",
			claims:    jwtv4.MapClaims{"nbf": float64(now + 5)},
			leeway:    Leeway{NBF: -10},
			shouldErr: false,
		},
		{
			name:      "future iat without leeway",
			claims:    jwtv4.MapClaims{"iat": float64(now + 2)},
			leeway:    Leeway{},
			shouldErr: true,
		},
		{
			name:      "future iat with negative leeway",
			claims:    jwtv4.MapClaims{"iat": float64(now + 2)},
			leeway:    Leeway{IAT: -5},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTimeClaimsWithLeeway(tt.claims, tt.leeway)
			if tt.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestBasicAllowedTokenParserParse(t *testing.T) {
	tests := []struct {
		name        string
		allowed     map[string]string
		raw         string
		expectedErr error
		expectedPrn string
	}{
		{
			name: "valid credentials",
			allowed: map[string]string{
				"user": "pass",
			},
			raw:         basculehttp.BasicAuth("user", "pass"),
			expectedErr: nil,
			expectedPrn: "user",
		},
		{
			name: "unknown user",
			allowed: map[string]string{
				"other": "pass",
			},
			raw:         basculehttp.BasicAuth("user", "pass"),
			expectedErr: bascule.ErrBadCredentials,
		},
		{
			name: "wrong password",
			allowed: map[string]string{
				"user": "pass",
			},
			raw:         basculehttp.BasicAuth("user", "wrong"),
			expectedErr: bascule.ErrBadCredentials,
		},
		{
			name:        "invalid base64",
			allowed:     map[string]string{"user": "pass"},
			raw:         "%%%",
			expectedErr: bascule.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := basicAllowedTokenParser{allowed: tt.allowed}
			token, err := parser.Parse(context.Background(), tt.raw)
			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tt.expectedErr))
				assert.Nil(t, token)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, token)
			assert.Equal(t, tt.expectedPrn, token.Principal())
		})
	}
}

func TestNewEndpointRegexCheck(t *testing.T) {
	tests := []struct {
		name      string
		prefix    string
		shouldErr bool
	}{
		{name: "valid prefix", prefix: "perm:", shouldErr: false},
		{name: "invalid regex prefix", prefix: "[", shouldErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := newEndpointRegexCheck(tt.prefix, "all")
			if tt.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, checker.prefixToMatch)
		})
	}
}

func TestEndpointRegexCheckAuthorized(t *testing.T) {
	checker, err := newEndpointRegexCheck("perm:", "all")
	require.NoError(t, err)

	tests := []struct {
		name       string
		capability string
		url        string
		method     string
		expected   bool
	}{
		{
			name:       "exact method match",
			capability: "perm:device/.*/stat:get",
			url:        "/device/abc/stat",
			method:     "GET",
			expected:   true,
		},
		{
			name:       "accept all method",
			capability: "perm:device/.*/stat:all",
			url:        "/device/abc/stat",
			method:     "PATCH",
			expected:   true,
		},
		{
			name:       "method mismatch",
			capability: "perm:device/.*/stat:get",
			url:        "/device/abc/stat",
			method:     "POST",
			expected:   false,
		},
		{
			name:       "endpoint mismatch",
			capability: "perm:device/.*/stat:get",
			url:        "/device/abc/config",
			method:     "GET",
			expected:   false,
		},
		{
			name:       "bad capability regex",
			capability: "perm:[invalid:get",
			url:        "/device/abc/stat",
			method:     "GET",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := checker.authorized(tt.capability, tt.url, tt.method)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestURLPathNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty", input: "", expected: "/"},
		{name: "already normalized", input: "/device/1", expected: "/device/1"},
		{name: "missing leading slash", input: "device/1", expected: "/device/1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, urlPathNormalization(tt.input))
		})
	}
}

func TestTrimVersionPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "v3 prefix", input: "/api/v3/device/send", expected: "/device/send"},
		{name: "v2 prefix", input: "/api/v2/device/send", expected: "/device/send"},
		{name: "not prefixed", input: "/device/send", expected: "/device/send"},
		{name: "prefix without trailing slash", input: "/api/v3", expected: "/api/v3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, trimVersionPrefix(tt.input))
		})
	}
}

func TestDeterminePartnerMetric(t *testing.T) {
	tests := []struct {
		name     string
		partners []string
		expected string
	}{
		{name: "none", partners: []string{}, expected: "none"},
		{name: "single value", partners: []string{"p0"}, expected: "p0"},
		{name: "single wildcard", partners: []string{"*"}, expected: "wildcard"},
		{name: "many values", partners: []string{"p0", "p1"}, expected: "many"},
		{name: "many with wildcard", partners: []string{"p0", "*"}, expected: "wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, determinePartnerMetric(tt.partners))
		})
	}
}

func TestDetermineEndpointMetric(t *testing.T) {
	bucketA := regexp.MustCompile("/device/.*/stat\\b")
	bucketB := regexp.MustCompile("/hook\\b")

	tests := []struct {
		name      string
		endpoints []*regexp.Regexp
		url       string
		expected  string
	}{
		{
			name:      "matched first bucket",
			endpoints: []*regexp.Regexp{bucketA, bucketB},
			url:       "/device/abc/stat",
			expected:  bucketA.String(),
		},
		{
			name:      "matched second bucket",
			endpoints: []*regexp.Regexp{bucketA, bucketB},
			url:       "/hook",
			expected:  bucketB.String(),
		},
		{
			name:      "no match",
			endpoints: []*regexp.Regexp{bucketA, bucketB},
			url:       "/device/abc/config",
			expected:  "not_recognized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, determineEndpointMetric(tt.endpoints, tt.url))
		})
	}
}
