package basculehelper

//Deprecated: this is a bascule helper package that uses older bascule functions from webpa-common in order to implement
//sallust and zap logger in scytale

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jwt"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/spf13/cast"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"

	//nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
	"go.uber.org/multierr"
)

var (
	ErrNoVals                 = errors.New("expected at least one value")
	ErrNoAuth                 = errors.New("couldn't get request info: authorization not found")
	ErrNoToken                = errors.New("no token found in Auth")
	ErrNoValidCapabilityFound = errors.New("no valid capability for endpoint")
	ErrNilAttributes          = errors.New("nil attributes interface")
	ErrNoURL                  = errors.New("invalid URL found in Auth")
	partnerKeys               = []string{"allowedResources", "allowedPartners"}
)

const (
	CapabilityKey = "capabilities"

	RejectedOutcome = "rejected"
	AcceptedOutcome = "accepted"
	// reasons
	TokenMissing               = "auth_missing"
	UndeterminedPartnerID      = "undetermined_partner_ID"
	NoCapabilityChecker        = "no_capability_checker"
	EmptyParsedURL             = "empty_parsed_URL"
	AuthCapabilityCheckOutcome = "auth_capability_check"
	capabilityCheckHelpMsg     = "Counter for the capability checker, providing outcome information by client, partner, and endpoint"
	EmptyCapabilitiesList      = "empty_capabilities_list"
	MissingValues              = "auth_is_missing_values"
	UndeterminedCapabilities   = "undetermined_capabilities"
	NoCapabilitiesMatch        = "no_capabilities_match"
	//nolint:gosec
	TokenMissingValues = "auth_is_missing_values"

	//labels
	OutcomeLabel   = "outcome"
	ReasonLabel    = "reason"
	ClientIDLabel  = "clientid"
	EndpointLabel  = "endpoint"
	PartnerIDLabel = "partnerid"
	ServerLabel    = "server"

	// Names for Auth Validation metrics
	AuthValidationOutcome = "auth_validation"
	NBFHistogram          = "auth_from_nbf_seconds"
	EXPHistogram          = "auth_from_exp_seconds"

	// Help messages for Auth Validation metrics
	authValidationOutcomeHelpMsg = "Counter for success and failure reason results through bascule"
	nbfHelpMsg                   = "Difference (in seconds) between time of JWT validation and nbf (including leeway)"
	expHelpMsg                   = "Difference (in seconds) between time of JWT validation and exp (including leeway)"
)

// AuthCapabilityCheckMeasures describes the defined metrics that will be used by clients
type AuthCapabilityCheckMeasures struct {
	CapabilityCheckOutcome metrics.Counter
}

// NewAuthCapabilityCheckMeasures realizes desired metrics. It's intended to be used alongside Metrics() for
// our older non uber/fx applications.
func NewAuthCapabilityCheckMeasures(p provider.Provider) *AuthCapabilityCheckMeasures {
	return &AuthCapabilityCheckMeasures{
		CapabilityCheckOutcome: p.NewCounter(AuthCapabilityCheckOutcome),
	}
}

// AuthCapabilitiesMetrics returns the Metrics relevant to this package targeting our older non uber/fx applications.
// To initialize the metrics, use NewAuthCapabilityCheckMeasures().
func AuthCapabilitiesMetrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		{
			Name:       AuthCapabilityCheckOutcome,
			Type:       xmetrics.CounterType,
			Help:       capabilityCheckHelpMsg,
			LabelNames: []string{OutcomeLabel, ReasonLabel, ClientIDLabel, PartnerIDLabel, EndpointLabel},
		},
	}
}

// AuthValidationMeasures describes the defined metrics that will be used by clients
type AuthValidationMeasures struct {
	NBFHistogram      metrics.Histogram
	ExpHistogram      metrics.Histogram
	ValidationOutcome metrics.Counter
}

// NewAuthValidationMeasures realizes desired metrics. It's intended to be used alongside Metrics() for
// our older non uber/fx applications.
func NewAuthValidationMeasures(r xmetrics.Registry) *AuthValidationMeasures {
	return &AuthValidationMeasures{
		ValidationOutcome: r.NewCounter(AuthValidationOutcome),
	}
}

// AuthValidationMetrics returns the Metrics relevant to this package targeting our older non uber/fx applications.
// To initialize the metrics, use NewAuthValidationMeasures().
func AuthValidationMetrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		{
			Name:       AuthValidationOutcome,
			Type:       xmetrics.CounterType,
			Help:       authValidationOutcomeHelpMsg,
			LabelNames: []string{OutcomeLabel},
		},
		{
			Name:    NBFHistogram,
			Type:    xmetrics.HistogramType,
			Help:    nbfHelpMsg,
			Buckets: []float64{-61, -11, -2, -1, 0, 9, 60}, // defines the upper inclusive (<=) bounds
		},
		{
			Name:    EXPHistogram,
			Type:    xmetrics.HistogramType,
			Help:    expHelpMsg,
			Buckets: []float64{-61, -11, -2, -1, 0, 9, 60},
		},
	}
}

// MetricValidator determines if a request is authorized and then updates a
// metric to show those results.
type MetricValidator struct {
	C         CapabilitiesChecker
	Measures  *AuthCapabilityCheckMeasures
	Endpoints []*regexp.Regexp
}

// CapabilitiesChecker is an object that can determine if a request is
// authorized given a bascule.Authentication object.  If it's not authorized, a
// reason and error are given for logging and metrics.
type CapabilitiesChecker interface {
	Check(auth bascule.Authentication, vals ParsedValues) (string, error)
}

// ParsedValues are values determined from the bascule Authentication.
type ParsedValues struct {
	// Endpoint is the string representation of a regular expression that
	// matches the URL for the request.  The main benefit of this string is it
	// most likely won't include strings that change from one request to the
	// next (ie, device ID).
	Endpoint string
	// Partner is a string representation of the list of partners found in the
	// JWT, where:
	//   - any list including "*" as a partner is determined to be "wildcard".
	//   - when the list is <1 item, the partner is determined to be "none".
	//   - when the list is >1 item, the partner is determined to be "many".
	//   - when the list is only one item, that is the partner value.
	Partner string
}

// CreateValidator provides a function for authorization middleware.  The
// function parses the information needed for the CapabilitiesChecker, calls it
// to determine if the request is authorized, and maintains the results in a
// metric.  The function can actually mark the request as unauthorized or just
// update the metric and allow the request, depending on configuration.  This
// allows for monitoring before being more strict with authorization.
func (m MetricValidator) CreateValidator(errorOut bool) bascule.ValidatorFunc {
	return func(ctx context.Context, _ bascule.Token) error {
		// if we're not supposed to error out, the outcome should be accepted on failure
		failureOutcome := AcceptedOutcome
		if errorOut {
			// if we actually error out, the outcome is the request being rejected
			failureOutcome = RejectedOutcome
		}

		auth, ok := bascule.FromContext(ctx)
		if !ok {
			m.Measures.CapabilityCheckOutcome.With(OutcomeLabel, failureOutcome, ReasonLabel, TokenMissing, ClientIDLabel, "", PartnerIDLabel, "", EndpointLabel, "").Add(1)
			if errorOut {
				return ErrNoAuth
			}
			return nil
		}

		client, partnerID, endpoint, reason, err := m.prepMetrics(auth)
		labels := []string{ClientIDLabel, client, PartnerIDLabel, partnerID, EndpointLabel, endpoint}
		if err != nil {
			labels = append(labels, OutcomeLabel, failureOutcome, ReasonLabel, reason)
			m.Measures.CapabilityCheckOutcome.With(labels...).Add(1)
			if errorOut {
				return err
			}
			return nil
		}

		v := ParsedValues{
			Endpoint: endpoint,
			Partner:  partnerID,
		}

		reason, err = m.C.Check(auth, v)
		if err != nil {
			labels = append(labels, OutcomeLabel, failureOutcome, ReasonLabel, reason)
			m.Measures.CapabilityCheckOutcome.With(labels...).Add(1)
			if errorOut {
				return err
			}
			return nil
		}

		labels = append(labels, OutcomeLabel, AcceptedOutcome, ReasonLabel, "")
		m.Measures.CapabilityCheckOutcome.With(labels...).Add(1)
		return nil
	}
}

// prepMetrics gathers the information needed for metric label information.  It
// gathers the client ID, partnerID, and endpoint (bucketed) for more information
// on the metric when a request is unauthorized.
func (m MetricValidator) prepMetrics(auth bascule.Authentication) (string, string, string, string, error) {
	if auth.Token == nil {
		return "", "", "", TokenMissingValues, ErrNoToken
	}
	client := auth.Token.Principal()
	if auth.Token.Attributes() == nil {
		return client, "", "", TokenMissingValues, ErrNilAttributes
	}

	partnerVal, ok := bascule.GetNestedAttribute(auth.Token.Attributes(), PartnerKeys()...)
	if !ok {
		return client, "", "", UndeterminedPartnerID, fmt.Errorf("couldn't get partner IDs from attributes using keys %v", PartnerKeys())
	}
	partnerIDs, err := cast.ToStringSliceE(partnerVal)
	if err != nil {
		//nolint:errorlint
		return client, "", "", UndeterminedPartnerID, fmt.Errorf("partner IDs \"%v\" couldn't be cast to string slice: %v", partnerVal, err)
	}
	partnerID := DeterminePartnerMetric(partnerIDs)

	if auth.Request.URL == nil {
		return client, partnerID, "", TokenMissingValues, ErrNoURL
	}
	escapedURL := auth.Request.URL.EscapedPath()
	endpoint := determineEndpointMetric(m.Endpoints, escapedURL)
	return client, partnerID, endpoint, "", nil
}

// DeterminePartnerMetric takes a list of partners and decides what the partner
// metric label should be.
func DeterminePartnerMetric(partners []string) string {
	if len(partners) < 1 {
		return "none"
	}
	if len(partners) == 1 {
		if partners[0] == "*" {
			return "wildcard"
		}
		return partners[0]
	}
	for _, partner := range partners {
		if partner == "*" {
			return "wildcard"
		}
	}
	return "many"
}

// determineEndpointMetric takes a list of regular expressions and applies them
// to the url of the request to decide what the endpoint metric label should be.
func determineEndpointMetric(endpoints []*regexp.Regexp, urlHit string) string {
	for _, r := range endpoints {
		idxs := r.FindStringIndex(urlHit)
		if idxs == nil {
			continue
		}
		if idxs[0] == 0 {
			return r.String()
		}
	}
	return "not_recognized"
}

// Metrics Listener
type MetricListener struct {
	expLeeway time.Duration
	nbfLeeway time.Duration
	measures  *AuthValidationMeasures
}

type Option func(m *MetricListener)

func NewMetricListener(m *AuthValidationMeasures, options ...Option) *MetricListener {
	listener := MetricListener{
		measures: m,
	}

	for _, o := range options {
		o(&listener)
	}
	return &listener
}

func (m *MetricListener) OnErrorResponse(e basculehttp.ErrorResponseReason, _ error) {
	if m.measures == nil {
		return
	}
	m.measures.ValidationOutcome.With(OutcomeLabel, e.String()).Add(1)
}

func (m *MetricListener) OnAuthenticated(auth bascule.Authentication) {
	now := time.Now()

	if m.measures == nil {
		return // measure tools are not defined, skip
	}

	if auth.Token == nil {
		return
	}

	m.measures.ValidationOutcome.With(OutcomeLabel, "Accepted").Add(1)

	c, ok := auth.Token.Attributes().Get("claims")
	if !ok {
		return // if there aren't any claims, skip
	}
	claims, ok := c.(jwt.Claims)
	if !ok {
		return // if claims aren't what we expect, skip
	}

	//how far did we land from the NBF (in seconds): ie. -1 means 1 sec before, 1 means 1 sec after
	if nbf, nbfPresent := claims.NotBefore(); nbfPresent {
		nbf = nbf.Add(-m.nbfLeeway)
		offsetToNBF := now.Sub(nbf).Seconds()
		m.measures.NBFHistogram.Observe(offsetToNBF)
	}

	//how far did we land from the EXP (in seconds): ie. -1 means 1 sec before, 1 means 1 sec after
	if exp, expPresent := claims.Expiration(); expPresent {
		exp = exp.Add(m.expLeeway)
		offsetToEXP := now.Sub(exp).Seconds()
		m.measures.ExpHistogram.Observe(offsetToEXP)
	}
}

// CapabilitiesValidator checks the capabilities provided in a
// bascule.Authentication object to determine if a request is authorized.  It
// can also provide a function to be used in authorization middleware that
// pulls the Authentication object from a context before checking it.
type CapabilitiesValidator struct {
	Checker CapabilityChecker
}

type CapabilitiesError struct {
	CapabilitiesFound []string
	UrlToMatch        string
	MethodToMatch     string
}

func PartnerKeys() []string {
	return partnerKeys
}

func NewCapabilitiesError(capabilities []string, reqUrl string, method string) *CapabilitiesError {
	return &CapabilitiesError{
		CapabilitiesFound: capabilities,
		UrlToMatch:        reqUrl,
		MethodToMatch:     method,
	}
}

func (c *CapabilitiesError) Error() string {
	return fmt.Sprintf("%v", &c)
}

// CreateValidator creates a function that determines whether or not a
// client is authorized to make a request to an endpoint.  It uses the
// bascule.Authentication from the context to get the information needed by the
// CapabilityChecker to determine authorization.
func (c CapabilitiesValidator) CreateValidator(errorOut bool) bascule.ValidatorFunc {
	return func(ctx context.Context, _ bascule.Token) error {
		auth, ok := bascule.FromContext(ctx)
		if !ok {
			if errorOut {
				return ErrNoAuth
			}
			return nil
		}

		_, err := c.Check(auth, ParsedValues{})
		if err != nil && errorOut {
			return err
		}

		return nil
	}
}

// Check takes the needed values out of the given Authentication object in
// order to determine if a request is authorized.  It determines this through
// iterating through each capability and calling the CapabilityChecker.  If no
// capability authorizes the client for the given endpoint and method, it is
// unauthorized.
func (c CapabilitiesValidator) Check(auth bascule.Authentication, _ ParsedValues) (string, error) {
	if auth.Token == nil {
		return TokenMissingValues, ErrNoToken
	}
	vals, reason, err := getCapabilities(auth.Token.Attributes())
	if err != nil {
		return reason, err
	}

	if auth.Request.URL == nil {
		return TokenMissingValues, ErrNoURL
	}
	reqURL := auth.Request.URL.EscapedPath()
	method := auth.Request.Method
	err = c.checkCapabilities(vals, reqURL, method)
	if err != nil {
		return NoCapabilitiesMatch, err
	}
	return "", nil
}

// checkCapabilities uses a CapabilityChecker to check if each capability
// provided is authorized.  If an authorized capability is found, no error is
// returned.
func (c CapabilitiesValidator) checkCapabilities(capabilities []string, reqURL string, method string) error {
	for _, val := range capabilities {
		if c.Checker.Authorized(val, reqURL, method) {
			return nil
		}
	}

	return multierr.Append(ErrNoValidCapabilityFound, NewCapabilitiesError(capabilities, reqURL, method))

}

// getCapabilities runs some error checks while getting the list of
// capabilities from the attributes.
func getCapabilities(attributes bascule.Attributes) ([]string, string, error) {
	if attributes == nil {
		return []string{}, UndeterminedCapabilities, ErrNilAttributes
	}

	val, ok := attributes.Get(CapabilityKey)
	if !ok {
		return []string{}, UndeterminedCapabilities, fmt.Errorf("couldn't get capabilities using key %v", CapabilityKey)
	}

	vals, err := cast.ToStringSliceE(val)
	if err != nil {
		//nolint:errorlint
		return []string{}, UndeterminedCapabilities, fmt.Errorf("capabilities \"%v\" not the expected string slice: %v", val, err)
	}

	if len(vals) == 0 {
		return []string{}, EmptyCapabilitiesList, ErrNoVals
	}

	return vals, "", nil

}

// CapabilityChecker is an object that can determine if a capability provides
// authorization to the endpoint.
type CapabilityChecker interface {
	Authorized(string, string, string) bool
}

// EndpointRegexCheck uses a regular expression to validate an endpoint and
// method provided in a capability against the endpoint hit and method used for
// the request.
type EndpointRegexCheck struct {
	prefixToMatch   *regexp.Regexp
	acceptAllMethod string
}

// NewEndpointRegexCheck creates an object that implements the
// CapabilityChecker interface.  It takes a prefix that is expected at the
// beginning of a capability and a string that, if provided in the capability,
// authorizes all methods for that endpoint.  After the prefix, the
// EndpointRegexCheck expects there to be an endpoint regular expression and an
// http method - separated by a colon. The expected format of a capability is:
// <prefix><endpoint regex>:<method>
func NewEndpointRegexCheck(prefix string, acceptAllMethod string) (EndpointRegexCheck, error) {
	matchPrefix, err := regexp.Compile("^" + prefix + "(.+):(.+?)$")
	if err != nil {
		return EndpointRegexCheck{}, fmt.Errorf("failed to compile prefix [%v]: %w", prefix, err)
	}

	e := EndpointRegexCheck{
		prefixToMatch:   matchPrefix,
		acceptAllMethod: acceptAllMethod,
	}
	return e, nil
}

// Authorized checks the capability against the endpoint hit and method used.
// If the capability has the correct prefix and is meant to be used with the
// method provided to access the endpoint provided, it is authorized.
func (e EndpointRegexCheck) Authorized(capability string, urlToMatch string, methodToMatch string) bool {
	matches := e.prefixToMatch.FindStringSubmatch(capability)

	if matches == nil || len(matches) < 2 {
		return false
	}

	method := matches[2]
	if method != e.acceptAllMethod && method != strings.ToLower(methodToMatch) {
		return false
	}

	re, err := regexp.Compile(matches[1]) //url regex that capability grants access to
	if err != nil {
		return false
	}

	matchIdxs := re.FindStringIndex(urlToMatch)
	if matchIdxs == nil || matchIdxs[0] != 0 {
		return false
	}

	return true
}

// AlwaysCheck is a CapabilityChecker that always returns either true or false.
type AlwaysCheck bool

// Authorized returns the saved boolean value, rather than checking the
// parameters given.
func (a AlwaysCheck) Authorized(_, _, _ string) bool {
	return bool(a)
}

// ConstCheck is a basic capability checker that determines a capability is
// authorized if it matches the ConstCheck's string.
type ConstCheck string

// Authorized validates the capability provided against the stored string.
func (c ConstCheck) Authorized(capability, _, _ string) bool {
	return string(c) == capability
}
