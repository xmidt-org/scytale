package main

import (
	"github.com/go-kit/kit/metrics"
	"github.com/xmidt-org/webpa-common/xmetrics"
)

//Names for our metrics
const (
	EmptyWRPPartnerIDCounter = "empty_wrp_partnerids"
)

// labels
const (
	ClientIDLabel = "clientid"
)

//Metrics returns the Metrics relevant to this package
func Metrics() []xmetrics.Metric {
	return []xmetrics.Metric{
		xmetrics.Metric{
			Name:       EmptyWRPPartnerIDCounter,
			Type:       xmetrics.CounterType,
			Help:       "Counter for api users who send WRP Messages without ParnerIDs",
			LabelNames: []string{ClientIDLabel},
		},
	}
}

//NewEmptyWRPPartnerIDsCounter initializes a counter to keep track of
//scytale users which do not populate the partnerIDs field in their WRP messages
func NewEmptyWRPPartnerIDsCounter(r xmetrics.Registry) metrics.Counter {
	return r.NewCounter(EmptyWRPPartnerIDCounter)
}
