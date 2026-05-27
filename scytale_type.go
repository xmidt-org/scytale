// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/xmidt-org/clortho"
)

// JWTValidator provides a convenient way to define jwt validator through config files
type JWTValidator struct {
	// Config is used to create the clortho Resolver & Refresher for JWT verification keys
	Config clortho.Config

	// Leeway is used to set the amount of time buffer should be given to JWT
	// time values, such as nbf
	Leeway Leeway `json:"leeway" mapstructure:"leeway"`
}

type Leeway struct {
	EXP int64 `json:"expLeeway" mapstructure:"expLeeway"`
	NBF int64 `json:"nbfLeeway" mapstructure:"nbfLeeway"`
	IAT int64 `json:"iatLeeway" mapstructure:"iatLeeway"`
}
