package main

import (
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/provider"
	"github.com/xmidt-org/webpa-common/xmetrics"
)

// Metric names
const (
	ReceivedWRPMessageCount = "received_wrp_message_total"
	WebhookListSizeGauge    = "webhook_list_size_value"
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

	TokenMissing      = "token_not_found"
	TokenTypeMismatch = "token_type_mismatch"

	WRPPIDMissing  = "wrp_pid_missing"
	WRPPIDMismatch = "wrp_pid_mismatch"
	WRPPIDMatch    = "wrp_pid_match"

	JWTPIDMissing  = "jwt_pid_missing"
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
		{
			Name: WebhookListSizeGauge,
			Help: "Amount of current listeners",
			Type: "gauge",
		},
	}
}

// NewReceivedWRPCounter initializes a counter to keep track of
// scytale users which do not populate the partnerIDs field in their WRP messages
func NewReceivedWRPCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(ReceivedWRPMessageCount)
}

// NewWebhookListSizeGauge initializes a gauge representing the size of the list
// of currently registered webhook listeners
func NewWebhookListSizeGauge(p provider.Provider) metrics.Gauge {
	return p.NewGauge(WebhookListSizeGauge)
}
