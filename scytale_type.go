// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/url"
	"time"

	"github.com/xmidt-org/clortho"
)

// keySourceTimeout bounds each request made to fetch JWT verification keys.
const keySourceTimeout = 30 * time.Second

// JWTValidator provides a convenient way to define jwt validator through config files
type JWTValidator struct {
	// Config is used to create the clortho KeySetProvider for JWT verification keys
	Config KeyConfig
}

// KeyConfig preserves the configuration layout used by earlier clortho releases.
type KeyConfig struct {
	Refresh RefreshConfig
}

// RefreshConfig lists the sources polled for JWT verification keys.
type RefreshConfig struct {
	Sources []RefreshSource
}

// RefreshSource is a single location where JWT verification keys are served.
type RefreshSource struct {
	// URI is a file path, or a file, http, or https URI.
	URI string

	// Interval is the time between refreshes when the server gives no hint.
	Interval time.Duration

	// MinInterval is the shortest time between refreshes.
	MinInterval time.Duration

	// Jitter is the percentage, plus or minus, applied to every refresh interval.
	Jitter float64
}

// keySetConfig maps the service configuration onto a clortho.KeySetConfig.
func (kc KeyConfig) keySetConfig() clortho.KeySetConfig {
	client := &http.Client{Timeout: keySourceTimeout}

	var cfg clortho.KeySetConfig
	for _, s := range kc.Refresh.Sources {
		src := clortho.RefreshSource{
			URI:                s.URI,
			RefreshInterval:    s.Interval,
			MinRefreshInterval: s.MinInterval,
			JitterPercentage:   s.Jitter,
		}
		if isRemoteURI(s.URI) {
			src.Client = client
		}

		cfg.Sources = append(cfg.Sources, src)
	}

	return cfg
}

// isRemoteURI reports whether the uri is fetched over http, and so needs a client.
func isRemoteURI(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}
