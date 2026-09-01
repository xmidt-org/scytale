// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

// JWTValidator provides a convenient way to define jwt validator through config files
type JWTValidator struct {
	// Config contains the KeyResolver configuration for accessing the public keys for JWT
	// verification.
	Config KeyResolver
}
