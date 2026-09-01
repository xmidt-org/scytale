// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/xmidt-org/arrange/arrangehttp"
)

// KeyResolver contains the configuration for accessing the public keys for JWT
// verification.
type KeyResolver struct {
	// URL is the URL to get the public keys from.
	URL string

	// RefreshInterval is the interval to refresh the public keys.
	RefreshInterval time.Duration

	// FetcherWorkerCount specifies the number of HTTP fetch workers that are spawned in the backend. By default 3 workers are spawned.
	FetcherWorkerCount int

	// HTTPClient is the configuration for the http client to use to get the public keys.
	HTTPClient arrangehttp.ClientConfig
}

func (kr *KeyResolver) Build() (set jwk.Set, errs error) {
	jwk.SetGlobalFetcher(httprc.NewFetcher(context.Background(), httprc.WithFetcherWorkerCount(kr.FetcherWorkerCount)))
	cache := jwk.NewCache(context.Background())
	client, err := kr.HTTPClient.NewClient()

	return jwk.NewCachedSet(cache, kr.URL),
		errors.Join(err, cache.Register(kr.URL,
			jwk.WithRefreshInterval(kr.RefreshInterval),
			jwk.WithHTTPClient(client)))
}

func (kr KeyResolver) isZero() bool { return len(kr.URL) == 0 }
