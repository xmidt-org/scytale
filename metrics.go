package main

import (
	"github.com/go-kit/kit/metrics"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
)

// Names for our metrics
const (
	ReceivedWRPMessageCount = "received_wrp_message_total"
)

// labels
const (
	ClientIDLabel = "clientid"
	OutcomeLabel  = "outcome"
	ReasonLabel   = "reason"
)

// label values
const (
	Accepted = "accepted"
	Rejected = "rejected"

	TokenMissing = "token_not_found"
	// nolint:gosec
	TokenTypeMismatch = "token_type_mismatch"

	WRPPIDMissing  = "wrp_pid_missing"
	WRPPIDMismatch = "wrp_pid_mismatch"
	WRPPIDMatch    = "wrp_pid_match"

	JWTPIDWildcard = "jwt_pid_wildcard"
	JWTPIDInvalid  = "jwt_pid_invalid"
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
	}
}

// NewReceivedWRPCounter initializes a counter to keep track of
// scytale users which do not populate the partnerIDs field in their WRP messages
func NewReceivedWRPCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(ReceivedWRPMessageCount)
}
