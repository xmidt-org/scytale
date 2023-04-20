package basculehelper

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"testing"

	"github.com/go-kit/kit/metrics/generic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/bascule"
)

// MetricValidatorTests
type mockCapabilitiesChecker struct {
	mock.Mock
}

func (m *mockCapabilitiesChecker) Check(auth bascule.Authentication, v ParsedValues) (string, error) {
	args := m.Called(auth, v)
	return args.String(0), args.Error(1)
}

func TestMetricValidatorFunc(t *testing.T) {
	goodURL, err := url.Parse("/test")
	require.Nil(t, err)
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	goodAttributes := bascule.NewAttributes(map[string]interface{}{
		CapabilityKey: capabilities,
		"allowedResources": map[string]interface{}{
			"allowedPartners": []string{"meh"},
		},
	})

	tests := []struct {
		description       string
		includeAuth       bool
		attributes        bascule.Attributes
		checkCallExpected bool
		checkReason       string
		checkErr          error
		errorOut          bool
		errExpected       bool
	}{
		{
			description:       "Success",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			errorOut:          true,
		},
		{
			description: "Include Auth Error",
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "Include Auth Suppressed Error",
			errorOut:    false,
		},
		{
			description: "Prep Metrics Error",
			includeAuth: true,
			attributes:  nil,
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "Prep Metrics Suppressed Error",
			includeAuth: true,
			attributes:  nil,
			errorOut:    false,
		},
		{
			description:       "Check Error",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			checkReason:       NoCapabilitiesMatch,
			checkErr:          errors.New("test check error"),
			errorOut:          true,
			errExpected:       true,
		},
		{
			description:       "Check Suppressed Error",
			includeAuth:       true,
			attributes:        goodAttributes,
			checkCallExpected: true,
			checkReason:       NoCapabilitiesMatch,
			checkErr:          errors.New("test check error"),
			errorOut:          false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)

			ctx := context.Background()
			auth := bascule.Authentication{
				Token: bascule.NewToken("test", "princ", tc.attributes),
				Request: bascule.Request{
					URL:    goodURL,
					Method: "GET",
				},
			}
			if tc.includeAuth {
				ctx = bascule.WithAuthentication(ctx, auth)
			}
			mockCapabilitiesChecker := new(mockCapabilitiesChecker)
			if tc.checkCallExpected {
				mockCapabilitiesChecker.On("Check", mock.Anything, mock.Anything).Return(tc.checkReason, tc.checkErr).Once()
			}

			counter := generic.NewCounter("test_capability_check")
			mockMeasures := AuthCapabilityCheckMeasures{
				CapabilityCheckOutcome: counter,
			}

			m := MetricValidator{
				C:        mockCapabilitiesChecker,
				Measures: &mockMeasures,
			}
			err := m.CreateValidator(tc.errorOut)(ctx, nil)
			mockCapabilitiesChecker.AssertExpectations(t)
			if tc.errExpected {
				assert.NotNil(err)
				return
			}
			assert.Nil(err)
		})
	}
}

func TestPrepMetrics(t *testing.T) {
	type testType int
	var (
		goodURL        = "/asnkfn/aefkijeoij/aiogj"
		matchingURL    = "/fnvvdsjkfji/mac:12345544322345334/geigosj"
		client         = "special"
		prepErr        = errors.New("couldn't get partner IDs from attributes")
		badValErr      = errors.New("couldn't be cast to string slice")
		goodEndpoint   = `/fnvvdsjkfji/.*/geigosj\b`
		goodRegex      = regexp.MustCompile(goodEndpoint)
		unusedEndpoint = `/a/b\b`
		unusedRegex    = regexp.MustCompile(unusedEndpoint)
	)

	tests := []struct {
		description       string
		noPartnerID       bool
		partnerIDs        interface{}
		url               string
		includeToken      bool
		includeAttributes bool
		includeURL        bool
		expectedPartner   string
		expectedEndpoint  string
		expectedReason    string
		expectedErr       error
	}{
		{
			description:       "Success",
			partnerIDs:        []string{"partner"},
			url:               goodURL,
			includeToken:      true,
			includeAttributes: true,
			includeURL:        true,
			expectedPartner:   "partner",
			expectedEndpoint:  "not_recognized",
			expectedReason:    "",
			expectedErr:       nil,
		},
		{
			description:       "Success Abridged URL",
			partnerIDs:        []string{"partner"},
			url:               matchingURL,
			includeToken:      true,
			includeAttributes: true,
			includeURL:        true,
			expectedPartner:   "partner",
			expectedEndpoint:  goodEndpoint,
			expectedReason:    "",
			expectedErr:       nil,
		},
		{
			description:    "Nil Token Error",
			expectedReason: TokenMissingValues,
			expectedErr:    ErrNoToken,
		},
		{
			description:    "Nil Token Attributes Error",
			url:            goodURL,
			includeToken:   true,
			expectedReason: TokenMissingValues,
			expectedErr:    ErrNilAttributes,
		},
		{
			description:       "No Partner ID Error",
			noPartnerID:       true,
			url:               goodURL,
			includeToken:      true,
			includeAttributes: true,
			expectedPartner:   "",
			expectedEndpoint:  "",
			expectedReason:    UndeterminedPartnerID,
			expectedErr:       prepErr,
		},
		{
			description:       "Non String Slice Partner ID Error",
			partnerIDs:        []testType{0, 1, 2},
			url:               goodURL,
			includeToken:      true,
			includeAttributes: true,
			expectedPartner:   "",
			expectedEndpoint:  "",
			expectedReason:    UndeterminedPartnerID,
			expectedErr:       badValErr,
		},
		{
			description:       "Non Slice Partner ID Error",
			partnerIDs:        struct{ string }{},
			url:               goodURL,
			includeToken:      true,
			includeAttributes: true,
			expectedPartner:   "",
			expectedEndpoint:  "",
			expectedReason:    UndeterminedPartnerID,
			expectedErr:       badValErr,
		},
		{
			description:       "Nil URL Error",
			partnerIDs:        []string{"partner"},
			url:               goodURL,
			includeToken:      true,
			includeAttributes: true,
			expectedPartner:   "partner",
			expectedReason:    TokenMissingValues,
			expectedErr:       ErrNoURL,
		},
	}

	m := MetricValidator{
		Endpoints: []*regexp.Regexp{unusedRegex, goodRegex},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			require := require.New(t)
			assert := assert.New(t)

			// setup auth
			token := bascule.NewToken("mehType", client, nil)
			if tc.includeAttributes {
				a := map[string]interface{}{
					"allowedResources": map[string]interface{}{
						"allowedPartners": tc.partnerIDs,
					},
				}

				if tc.noPartnerID {
					a["allowedResources"] = 5
				}
				attributes := bascule.NewAttributes(a)
				token = bascule.NewToken("mehType", client, attributes)
			}
			auth := bascule.Authentication{
				Authorization: "testAuth",
				Request: bascule.Request{
					Method: "get",
				},
			}
			if tc.includeToken {
				auth.Token = token
			}
			if tc.includeURL {
				u, err := url.ParseRequestURI(tc.url)
				require.Nil(err)
				auth.Request.URL = u
			}

			c, partner, endpoint, reason, err := m.prepMetrics(auth)
			if tc.includeToken {
				assert.Equal(client, c)
			}
			assert.Equal(tc.expectedPartner, partner)
			assert.Equal(tc.expectedEndpoint, endpoint)
			assert.Equal(tc.expectedReason, reason)
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}

func TestDeterminePartnerMetric(t *testing.T) {
	tests := []struct {
		description    string
		partnersInput  []string
		expectedResult string
	}{
		{
			description:    "No Partners",
			expectedResult: "none",
		},
		{
			description:    "one wildcard",
			partnersInput:  []string{"*"},
			expectedResult: "wildcard",
		},
		{
			description:    "one partner",
			partnersInput:  []string{"TestPartner"},
			expectedResult: "TestPartner",
		},
		{
			description:    "many partners",
			partnersInput:  []string{"partner1", "partner2", "partner3"},
			expectedResult: "many",
		},
		{
			description:    "many partners with wildcard",
			partnersInput:  []string{"partner1", "partner2", "partner3", "*"},
			expectedResult: "wildcard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			partner := DeterminePartnerMetric(tc.partnersInput)
			assert.Equal(tc.expectedResult, partner)
		})
	}
}

// CapabilitiesValidator Tests
func TestCapabilitiesChecker(t *testing.T) {
	//nolint:gosimple
	var v interface{}
	v = CapabilitiesValidator{}
	_, ok := v.(CapabilitiesChecker)
	assert.True(t, ok)
}

func TestCapabilitiesValidatorFunc(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	goodURL, err := url.Parse("/test")
	require.Nil(t, err)
	goodRequest := bascule.Request{
		URL:    goodURL,
		Method: "GET",
	}
	tests := []struct {
		description  string
		includeAuth  bool
		includeToken bool
		errorOut     bool
		errExpected  bool
	}{
		{
			description:  "Success",
			includeAuth:  true,
			includeToken: true,
			errorOut:     true,
		},
		{
			description: "No Auth Error",
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "No Auth Suppressed Error",
		},
		{
			description: "Check Error",
			includeAuth: true,
			errorOut:    true,
			errExpected: true,
		},
		{
			description: "Check Suppressed Error",
			includeAuth: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			ctx := context.Background()
			auth := bascule.Authentication{
				Request: goodRequest,
			}
			if tc.includeToken {
				auth.Token = bascule.NewToken("test", "princ",
					bascule.NewAttributes(map[string]interface{}{CapabilityKey: capabilities}))
			}
			if tc.includeAuth {
				ctx = bascule.WithAuthentication(ctx, auth)
			}
			c := CapabilitiesValidator{
				Checker: ConstCheck("it's a match"),
			}
			err := c.CreateValidator(tc.errorOut)(ctx, bascule.NewToken("", "", nil))
			if tc.errExpected {
				assert.NotNil(err)
				return
			}
			assert.Nil(err)
		})
	}
}

func TestCapabilitiesValidatorCheck(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}
	pv := ParsedValues{}
	tests := []struct {
		description       string
		includeToken      bool
		includeAttributes bool
		includeURL        bool
		checker           CapabilityChecker
		expectedReason    string
		expectedErr       error
	}{
		{
			description:       "Success",
			includeAttributes: true,
			includeURL:        true,
			checker:           ConstCheck("it's a match"),
			expectedErr:       nil,
		},
		{
			description:    "No Token Error",
			expectedReason: TokenMissingValues,
			expectedErr:    ErrNoToken,
		},
		{
			description:    "Get Capabilities Error",
			includeToken:   true,
			expectedReason: UndeterminedCapabilities,
			expectedErr:    ErrNilAttributes,
		},
		{
			description:       "No URL Error",
			includeAttributes: true,
			expectedReason:    TokenMissingValues,
			expectedErr:       ErrNoURL,
		},
		{
			description:       "Check Capabilities Error",
			includeAttributes: true,
			includeURL:        true,
			checker:           AlwaysCheck(false),
			expectedReason:    NoCapabilitiesMatch,
			expectedErr:       ErrNoValidCapabilityFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			c := CapabilitiesValidator{
				Checker: tc.checker,
			}
			a := bascule.Authentication{}
			if tc.includeToken {
				a.Token = bascule.NewToken("", "", nil)
			}
			if tc.includeAttributes {
				a.Token = bascule.NewToken("test", "princ",
					bascule.NewAttributes(map[string]interface{}{CapabilityKey: capabilities}))
			}
			if tc.includeURL {
				goodURL, err := url.Parse("/test")
				require.Nil(err)
				a.Request = bascule.Request{
					URL:    goodURL,
					Method: "GET",
				}
			}
			reason, err := c.Check(a, pv)
			assert.Equal(tc.expectedReason, reason)
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
				return
			}
			assert.Contains(err.Error(), tc.expectedErr.Error())
		})
	}
}

func TestCheckCapabilities(t *testing.T) {
	capabilities := []string{
		"test",
		"a",
		"joweiafuoiuoiwauf",
		"it's a match",
	}

	tests := []struct {
		description    string
		goodCapability string
		expectedErr    error
	}{
		{
			description:    "Success",
			goodCapability: "it's a match",
		},
		{
			description: "No Capability Found Error",
			expectedErr: ErrNoValidCapabilityFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			c := CapabilitiesValidator{
				Checker: ConstCheck(tc.goodCapability),
			}
			err := c.checkCapabilities(capabilities, "", "")
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
				return
			}
			assert.Contains(err.Error(), tc.expectedErr.Error())
		})
	}
}

func TestGetCapabilities(t *testing.T) {
	type testType int
	goodKeyVal := []string{"cap1", "cap2"}
	emptyVal := []string{}
	getCapabilitiesErr := errors.New("couldn't get capabilities using key")
	badCapabilitiesErr := errors.New("not the expected string slice")
	tests := []struct {
		description      string
		nilAttributes    bool
		missingAttribute bool
		keyValue         interface{}
		expectedVals     []string
		expectedReason   string
		expectedErr      error
	}{
		{
			description:    "Success",
			keyValue:       goodKeyVal,
			expectedVals:   goodKeyVal,
			expectedReason: "",
			expectedErr:    nil,
		},
		{
			description:    "Nil Attributes Error",
			nilAttributes:  true,
			expectedVals:   emptyVal,
			expectedReason: UndeterminedCapabilities,
			expectedErr:    ErrNilAttributes,
		},
		{
			description:      "No Attribute Error",
			missingAttribute: true,
			expectedVals:     emptyVal,
			expectedReason:   UndeterminedCapabilities,
			expectedErr:      getCapabilitiesErr,
		},
		{
			description:    "Nil Capabilities Error",
			keyValue:       nil,
			expectedVals:   emptyVal,
			expectedReason: UndeterminedCapabilities,
			expectedErr:    badCapabilitiesErr,
		},
		{
			description:    "Non List Capabilities Error",
			keyValue:       struct{ string }{"abcd"},
			expectedVals:   emptyVal,
			expectedReason: UndeterminedCapabilities,
			expectedErr:    badCapabilitiesErr,
		},
		{
			description:    "Non String List Capabilities Error",
			keyValue:       []testType{0, 1, 2},
			expectedVals:   emptyVal,
			expectedReason: UndeterminedCapabilities,
			expectedErr:    badCapabilitiesErr,
		},
		{
			description:    "Empty Capabilities Error",
			keyValue:       emptyVal,
			expectedVals:   emptyVal,
			expectedReason: EmptyCapabilitiesList,
			expectedErr:    ErrNoVals,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			m := map[string]interface{}{CapabilityKey: tc.keyValue}
			if tc.missingAttribute {
				m = map[string]interface{}{}
			}
			attributes := bascule.NewAttributes(m)
			if tc.nilAttributes {
				attributes = nil
			}
			vals, reason, err := getCapabilities(attributes)
			assert.Equal(tc.expectedVals, vals)
			assert.Equal(tc.expectedReason, reason)
			if err == nil || tc.expectedErr == nil {
				assert.Equal(tc.expectedErr, err)
			} else {
				assert.Contains(err.Error(), tc.expectedErr.Error())
			}
		})
	}
}

// CapabilityChecker Tests
func TestAlwaysCheck(t *testing.T) {
	assert := assert.New(t)
	alwaysTrue := AlwaysCheck(true)
	assert.True(alwaysTrue.Authorized("a", "b", "c"))
	alwaysFalse := AlwaysCheck(false)
	assert.False(alwaysFalse.Authorized("a", "b", "c"))
}

func TestConstCapabilityChecker(t *testing.T) {
	//nolint:gosimple
	var v interface{}
	v = ConstCheck("test")
	_, ok := v.(CapabilityChecker)
	assert.True(t, ok)
}

func TestConstCheck(t *testing.T) {
	tests := []struct {
		description string
		capability  string
		okExpected  bool
	}{
		{
			description: "Success",
			capability:  "perfectmatch",
			okExpected:  true,
		},
		{
			description: "Not a Match",
			capability:  "meh",
			okExpected:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			c := ConstCheck("perfectmatch")
			ok := c.Authorized(tc.capability, "ignored1", "ignored2")
			assert.Equal(tc.okExpected, ok)
		})
	}
}

func TestEndpointRegexCapabilityChecker(t *testing.T) {
	assert := assert.New(t)
	var v interface{}
	v, err := NewEndpointRegexCheck("test", "")
	assert.Nil(err)
	_, ok := v.(CapabilityChecker)
	assert.True(ok)
}
func TestNewEndpointRegexError(t *testing.T) {
	e, err := NewEndpointRegexCheck(`\M`, "")
	assert := assert.New(t)
	assert.Empty(e)
	assert.NotNil(err)
}

func TestEndpointRegexCheck(t *testing.T) {
	tests := []struct {
		description     string
		prefix          string
		acceptAllMethod string
		capability      string
		url             string
		method          string
		okExpected      bool
	}{
		{
			description:     "Success",
			prefix:          "a:b:c:",
			acceptAllMethod: "all",
			capability:      "a:b:c:.*:get",
			url:             "/test/ffff//",
			method:          "get",
			okExpected:      true,
		},
		{
			description: "No Match Error",
			prefix:      "a:b:c:",
			capability:  "a:.*:get",
			method:      "get",
		},
		{
			description:     "Wrong Method Error",
			prefix:          "a:b:c:",
			acceptAllMethod: "all",
			capability:      "a:b:c:.*:get",
			method:          "post",
		},
		{
			description:     "Regex Doesn't Compile Error",
			prefix:          "a:b:c:",
			acceptAllMethod: "all",
			capability:      `a:b:c:\M:get`,
			method:          "get",
		},
		{
			description:     "URL Doesn't Match Capability Error",
			prefix:          "a:b:c:",
			acceptAllMethod: "all",
			capability:      "a:b:c:[A..Z]+:get",
			url:             "1111",
			method:          "get",
		},
		{
			description:     "URL Capability Match Wrong Location Error",
			prefix:          "a:b:c:",
			acceptAllMethod: "all",
			capability:      "a:b:c:[A..Z]+:get",
			url:             "11AAAAA",
			method:          "get",
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)
			e, err := NewEndpointRegexCheck(tc.prefix, tc.acceptAllMethod)
			require.Nil(err)
			require.NotEmpty(e)
			ok := e.Authorized(tc.capability, tc.url, tc.method)
			assert.Equal(tc.okExpected, ok)
		})
	}
}
