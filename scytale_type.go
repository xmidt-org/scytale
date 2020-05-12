/**
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"github.com/xmidt-org/argus/webhookclient"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/key"
)

//JWTValidator provides a convenient way to define jwt validator through config files
type JWTValidator struct {
	// JWTKeys is used to create the key.Resolver for JWT verification keys
	Keys key.ResolverFactory

	// Leeway is used to set the amount of time buffer should be given to JWT
	// time values, such as nbf
	Leeway bascule.Leeway
}

type webhookConfig struct {
	CacheConfig webhookclient.CacheConfig
	ArgusConfig webhookclient.ArgusConfig
}
