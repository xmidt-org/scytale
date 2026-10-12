// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/clortho"
)

func TestKeySetConfig(t *testing.T) {
	// The layout used with earlier clortho releases must still unmarshal.
	const config = `
jwtValidator:
  Config:
    Refresh:
      Sources:
        - URI: "https://keys.example.com/jwks"
          interval: 1h
          minInterval: 5m
          jitter: 15
        - uri: "/etc/scytale/keys.jwk"
`
	assert := assert.New(t)
	require := require.New(t)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(v.ReadConfig(strings.NewReader(config)))

	var jwtVal JWTValidator
	require.NoError(v.UnmarshalKey(jwtAuthConfigKey, &jwtVal))

	cfg := jwtVal.Config.keySetConfig()
	require.Len(cfg.Sources, 2)

	remote := cfg.Sources[0]
	assert.Equal("https://keys.example.com/jwks", remote.URI)
	assert.Equal(time.Hour, remote.RefreshInterval)
	assert.Equal(5*time.Minute, remote.MinRefreshInterval)
	assert.InDelta(15.0, remote.JitterPercentage, 0)
	if assert.NotNil(remote.Client) {
		assert.Equal(keySourceTimeout, remote.Client.Timeout)
	}

	file := cfg.Sources[1]
	assert.Equal("/etc/scytale/keys.jwk", file.URI)
	assert.Nil(file.Client)

	// clortho accepts the result: a client for the remote source and none for the file.
	_, err := clortho.NewKeySetProvider(cfg)
	assert.NoError(err)
}

func TestIsRemoteURI(t *testing.T) {
	assert.True(t, isRemoteURI("http://localhost"))
	assert.True(t, isRemoteURI("https://keys.example.com/jwks"))
	assert.True(t, isRemoteURI("HTTPS://keys.example.com/jwks"))
	assert.False(t, isRemoteURI("file:///etc/scytale/keys.jwk"))
	assert.False(t, isRemoteURI("/etc/scytale/keys.jwk"))
}
