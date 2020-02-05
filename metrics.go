package main

import (
	"github.com/go-kit/kit/metrics"
	"github.com/xmidt-org/webpa-common/xmetrics"
)

//Names for our metrics
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

	WRPPIDMissing  = "wrp_pid_missing"
	WRPPIDMismatch = "wrp_pid_mismatch"
	JWTPIDMissing  = "jwt_pid_missing"

	JWTPIDWildcard = "jwt_pid_wildcard"
	WRPPIDMatch    = "wrp_pid_match"
)

//received_wrp_message_count
//outcome: [rejected,accepted]
//reason: [ wrp_pid_missing, pid_wrp_mismatch, ]
//*Logging

//Metrics returns the Metrics relevant to this package
func Metrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		xmetrics.Metric{
			Name:       ReceivedWRPMessageCount,
			Type:       xmetrics.CounterType,
			Help:       "Number of WRP Messages successfully decoded and ready for fanout.",
			LabelNames: []string{OutcomeLabel, ClientIDLabel, ReasonLabel},
		},
	}
}

//NewReceivedWRPCounter initializes a counter to keep track of
//scytale users which do not populate the partnerIDs field in their WRP messages
func NewReceivedWRPCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(ReceivedWRPMessageCount)
}
