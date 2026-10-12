// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinas/alice"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/zap"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
)

const (
	authTestPath   = "/api/v3/device/send"
	authTestPrefix = "x1:webpa:api:"
)

type authChainFixture struct {
	chain    alice.Chain
	registry xmetrics.Registry
}

func newAuthChainViper(t *testing.T, config string) *viper.Viper {
	t.Helper()

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(config)))

	return v
}

func newAuthChainMetrics(t *testing.T) (xmetrics.Registry, *touchstone.Factory) {
	t.Helper()

	registry, err := xmetrics.NewRegistry(&xmetrics.Options{DisableGoCollector: true, DisableProcessCollector: true}, Metrics)
	require.NoError(t, err)

	promReg, ok := registry.(prometheus.Registerer)
	require.True(t, ok)

	return registry, touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), promReg)
}

func newAuthChainFixture(t *testing.T, config string) (authChainFixture, error) {
	t.Helper()

	registry, tf := newAuthChainMetrics(t)
	chain, err := authChain(newAuthChainViper(t, config), zap.NewNop(), registry, tf)

	return authChainFixture{chain: chain, registry: registry}, err
}

// serve sends a request with the given Authorization header through the chain,
// returning the status and the auth metric series that the request added.
func (f authChainFixture) serve(t *testing.T, method, authorization string) (int, []string) {
	t.Helper()

	before := f.authSeries(t)

	h := f.chain.Then(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(method, authTestPath, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var added []string
	for series, count := range f.authSeries(t) {
		if count > before[series] {
			added = append(added, series)
		}
	}

	return rec.Code, added
}

// serveLabels sends a request and returns the labels of the single auth
// metric series that it added.
func (f authChainFixture) serveLabels(t *testing.T, authorization string) (int, map[string]string) {
	t.Helper()

	status, added := f.serve(t, http.MethodPost, authorization)
	require.Len(t, added, 1)

	families, err := f.registry.Gather()
	require.NoError(t, err)

	for _, mf := range families {
		if !strings.HasSuffix(mf.GetName(), AuthCapabilityCheckCount) {
			continue
		}

		for _, m := range mf.GetMetric() {
			labels := make(map[string]string)
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}

			key := strings.Join([]string{labels[OutcomeLabel], labels[ReasonLabel], labels[ClientIDLabel], labels[PartnerIDLabel]}, "/")
			if key == added[0] {
				return status, labels
			}
		}
	}

	t.Fatalf("series %s not found", added[0])
	return 0, nil
}

// authSeries returns the AuthCapabilityCheckCount series as outcome/reason/client/partner.
func (f authChainFixture) authSeries(t *testing.T) map[string]float64 {
	t.Helper()

	families, err := f.registry.Gather()
	require.NoError(t, err)

	series := make(map[string]float64)
	for _, mf := range families {
		if !strings.HasSuffix(mf.GetName(), AuthCapabilityCheckCount) {
			continue
		}

		for _, m := range mf.GetMetric() {
			labels := make(map[string]string)
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}

			key := strings.Join([]string{labels[OutcomeLabel], labels[ReasonLabel], labels[ClientIDLabel], labels[PartnerIDLabel]}, "/")
			series[key] = m.GetCounter().GetValue()
		}
	}

	return series
}

func basicAuthorization(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func basicConfig(creds ...string) string {
	encoded := make([]string, 0, len(creds))
	for _, c := range creds {
		encoded = append(encoded, `"`+base64.StdEncoding.EncodeToString([]byte(c))+`"`)
	}

	return "authHeader: [" + strings.Join(encoded, ", ") + "]"
}

// jwtConfig returns a jwtValidator config with a single key source, followed by
// any extra configuration.
func jwtConfig(source, extra string) string {
	return `
jwtValidator:
  Config:
    Refresh:
      Sources:
        - URI: "` + source + `"
` + extra
}

const validCapabilityCheck = `
capabilityCheck:
  prefixes: ["` + authTestPrefix + `"]
  acceptAllMethod: all
  cacheSize: 100
`

func TestAuthChainConfig(t *testing.T) {
	var tests = []struct {
		name   string
		config string
		errMsg string
	}{
		{
			name:   "neither basic nor jwt",
			config: "foo: bar",
			errMsg: "must be set",
		},
		{
			name:   "both basic and jwt",
			config: basicConfig("user:pass") + jwtConfig("http://localhost", validCapabilityCheck),
			errMsg: "can't both be set",
		},
		{
			name:   "no valid basic credentials",
			config: `authHeader: ["", "not base64", "` + base64.StdEncoding.EncodeToString([]byte("no colon")) + `"]`,
			errMsg: "must contain at least 1 valid basic cred",
		},
		{
			name:   "basic password too long to hash",
			config: basicConfig("user:" + strings.Repeat("x", 73)),
			errMsg: "failed to hash password for basic auth user `user`",
		},
		{
			name: "no key sources",
			config: `
jwtValidator:
  Config:
    Refresh:
      Sources: []
` + validCapabilityCheck,
			errMsg: "KeySetProvider",
		},
		{
			name: "invalid key source interval",
			config: `
jwtValidator:
  Config:
    Refresh:
      Sources:
        - URI: "http://localhost"
          interval: "not a duration"
` + validCapabilityCheck,
			errMsg: "failed to parse jwt configuration:",
		},
		{
			name:   "invalid capability check",
			config: jwtConfig("http://localhost", "capabilityCheck:\n  cacheSize: \"not a number\"\n"),
			errMsg: "failed to parse jwt configuration `capabilityCheck`",
		},
		{
			name:   "missing capability cache size",
			config: jwtConfig("http://localhost", "capabilityCheck:\n  prefixes: [\""+authTestPrefix+"\"]\n"),
			errMsg: "error setting up JWT capability checks",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newAuthChainFixture(t, test.config)
			assert.ErrorContains(t, err, test.errMsg)
		})
	}
}

func TestAuthChainNilRegistry(t *testing.T) {
	_, err := authChain(newAuthChainViper(t, basicConfig("user:pass")), zap.NewNop(), nil, nil)
	assert.ErrorContains(t, err, "nil registry")
}

func TestAuthChainSkipsEmptyBasicCredential(t *testing.T) {
	f, err := newAuthChainFixture(t, `authHeader: ["", "`+base64.StdEncoding.EncodeToString([]byte("user:pass"))+`"]`)
	require.NoError(t, err)

	status, _ := f.serve(t, http.MethodPost, basicAuthorization("user", "pass"))
	assert.Equal(t, http.StatusOK, status)
}

func TestAuthChainClorthoMetricsRegisteredTwice(t *testing.T) {
	registry, tf := newAuthChainMetrics(t)
	config := jwtConfig("http://localhost", validCapabilityCheck)

	_, err := authChain(newAuthChainViper(t, config), zap.NewNop(), registry, tf)
	require.NoError(t, err)

	_, err = authChain(newAuthChainViper(t, config), zap.NewNop(), registry, tf)
	assert.ErrorContains(t, err, "failed to create clortho metrics listener")
}

func TestAuthChainEndpointBuckets(t *testing.T) {
	f, err := newAuthChainFixture(t, jwtConfig("http://localhost", validCapabilityCheck+`  endpointBuckets: ["(unclosed", "/api/v3/device/send"]
`))
	require.NoError(t, err)

	// A malformed bearer token is rejected during authentication, which labels
	// the endpoint using the buckets that compiled.
	_, labels := f.serveLabels(t, "Bearer not.a.jwt")
	assert.Equal(t, "/api/v3/device/send", labels[EndpointLabel])
}

func TestAuthChainBasic(t *testing.T) {
	f, err := newAuthChainFixture(t, `authHeader: ["`+base64.StdEncoding.EncodeToString([]byte("user:pass"))+`"]`)
	require.NoError(t, err)

	var tests = []struct {
		name          string
		authorization string
		status        int
		series        []string
	}{
		{
			name:          "valid",
			authorization: basicAuthorization("user", "pass"),
			status:        http.StatusOK,
			series:        []string{"accepted//user/"},
		},
		{
			name:          "wrong password",
			authorization: basicAuthorization("user", "wrong"),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/bad_creds/user/"},
		},
		{
			name:          "unknown user",
			authorization: basicAuthorization("nobody", "pass"),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/bad_creds/nobody/"},
		},
		{
			name:   "missing authorization",
			status: http.StatusUnauthorized,
			series: []string{"rejected/missing_creds//"},
		},
		{
			name:          "bearer scheme",
			authorization: "Bearer abc",
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/invalid_scheme//"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, series := f.serve(t, http.MethodPost, test.authorization)
			assert.Equal(t, test.status, status)
			assert.ElementsMatch(t, test.series, series)
		})
	}
}

func TestAuthChainJWT(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	require.NoError(t, signer.Set(jwk.KeyIDKey, "k1"))
	require.NoError(t, signer.Set(jwk.AlgorithmKey, jwa.ES256()))

	pub, err := jwk.PublicKeyOf(signer)
	require.NoError(t, err)

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	data, err := json.Marshal(set)
	require.NoError(t, err)

	keys := filepath.Join(t.TempDir(), "keys.jwk-set")
	require.NoError(t, os.WriteFile(keys, data, 0o600))

	f, err := newAuthChainFixture(t, `
jwtValidator:
  Config:
    Refresh:
      Sources:
        - URI: "file://`+keys+`"
capabilityCheck:
  type: enforce
  prefixes: ["`+authTestPrefix+`"]
  acceptAllMethod: all
  cacheSize: 100
`)
	require.NoError(t, err)

	unknownKey, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	require.NoError(t, unknownKey.Set(jwk.KeyIDKey, "nope"))
	require.NoError(t, unknownKey.Set(jwk.AlgorithmKey, jwa.ES256()))

	now := time.Now()
	token := func(key jwk.Key, build func(*jwt.Builder) *jwt.Builder) string {
		b := jwt.NewBuilder().
			Subject(testClient).
			IssuedAt(now.Add(-time.Minute)).
			Expiration(now.Add(time.Hour)).
			Claim("capabilities", []string{authTestPrefix + ".*:all"}).
			Claim(allowedResources, map[string]any{allowedPartners: []string{testPartner}})

		tok, err := build(b).Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key))
		require.NoError(t, err)

		return "Bearer " + string(signed)
	}
	same := func(b *jwt.Builder) *jwt.Builder { return b }

	// The keys are loaded in the background.
	valid := token(signer, same)
	require.Eventually(t, func() bool {
		status, _ := f.serve(t, http.MethodPost, valid)
		return status == http.StatusOK
	}, 5*time.Second, 10*time.Millisecond)

	var tests = []struct {
		name          string
		authorization string
		status        int
		series        []string
	}{
		{
			name:          "valid",
			authorization: valid,
			status:        http.StatusOK,
			series:        []string{"accepted//client0/partner0"},
		},
		{
			name:          "expired",
			authorization: token(signer, func(b *jwt.Builder) *jwt.Builder { return b.Expiration(now.Add(-time.Hour)) }),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/exp_not_satisfied//"},
		},
		{
			name:          "not yet valid",
			authorization: token(signer, func(b *jwt.Builder) *jwt.Builder { return b.NotBefore(now.Add(time.Hour)) }),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/nbf_not_satisfied//"},
		},
		{
			name:          "unknown key id",
			authorization: token(unknownKey, same),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/jwk_key_not_found//"},
		},
		{
			name:          "garbage",
			authorization: "Bearer not.a.jwt",
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/could_not_verify_message//"},
		},
		{
			name: "no matching capability",
			authorization: token(signer, func(b *jwt.Builder) *jwt.Builder {
				return b.Claim("capabilities", []string{authTestPrefix + "/hooks:all"})
			}),
			status: http.StatusForbidden,
			series: []string{"rejected/no_capabilities_match/client0/partner0"},
		},
		{
			name: "missing partner claim",
			authorization: token(signer, func(b *jwt.Builder) *jwt.Builder {
				return b.Claim(allowedResources, map[string]any{})
			}),
			status: http.StatusUnauthorized,
			series: []string{"rejected/missing_expected_claims/client0/missing_expected_claims"},
		},
		{
			name: "empty partner claim",
			authorization: token(signer, func(b *jwt.Builder) *jwt.Builder {
				return b.Claim(allowedResources, map[string]any{allowedPartners: []string{}})
			}),
			status: http.StatusUnauthorized,
			series: []string{"rejected/invalid_claim_values/client0/none"},
		},
		{
			name:          "basic scheme",
			authorization: basicAuthorization("user", "pass"),
			status:        http.StatusUnauthorized,
			series:        []string{"rejected/invalid_scheme//"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, series := f.serve(t, http.MethodPost, test.authorization)
			assert.Equal(t, test.status, status)
			assert.ElementsMatch(t, test.series, series)
		})
	}
}
