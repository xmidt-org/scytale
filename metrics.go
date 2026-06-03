// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/go-kit/kit/metrics"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
)

// Names for our metrics
const (
	ReceivedWRPMessageCount  = "received_wrp_message_total"
	AuthCapabilityCheckCount = "auth_capability_check"
)

// labels
const (
	ClientIDLabel  = "clientid"
	OutcomeLabel   = "outcome"
	ReasonLabel    = "reason"
	PartnerIDLabel = "partnerid"
	EndpointLabel  = "endpoint"
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

	UndeterminedCapabilities = "undetermined_capabilities"
	EmptyCapabilitiesList    = "empty_capabilities_list"
	NoCapabilitiesMatch      = "no_capabilities_match"
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
			Name:       AuthCapabilityCheckCount,
			Type:       xmetrics.CounterType,
			Help:       "Counter for capability checks with outcome information by client, partner, and endpoint.",
			LabelNames: []string{OutcomeLabel, ReasonLabel, ClientIDLabel, PartnerIDLabel, EndpointLabel},
		},
	}
}

// NewReceivedWRPCounter initializes a counter to keep track of
// scytale users which do not populate the partnerIDs field in their WRP messages
func NewReceivedWRPCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(ReceivedWRPMessageCount)
}

func NewAuthCapabilityCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(AuthCapabilityCheckCount)
}
