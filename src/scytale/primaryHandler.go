/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
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
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/Comcast/webpa-common/secure"
	"github.com/Comcast/webpa-common/secure/handler"
	"github.com/Comcast/webpa-common/secure/key"
	"github.com/Comcast/webpa-common/service"
	"github.com/Comcast/webpa-common/wrp"
	"github.com/Comcast/webpa-common/wrp/wrphttp"
	"github.com/Comcast/webpa-common/xhttp"
	"github.com/Comcast/webpa-common/xhttp/fanout"
	"github.com/Comcast/webpa-common/xmetrics"
	"github.com/SermoDigital/jose/jwt"
	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
)

const (
	baseURI = "/api"
	version = "v2"
)

func addDeviceSendRoutes(logger log.Logger, handlerChain alice.Chain, r *mux.Router, endpoints fanout.Endpoints, o fanout.Options) error {
	subrouter := r.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Methods("POST", "PUT").Subrouter()

	subrouter.Headers(wrphttp.MessageTypeHeader, "").Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				fanout.WithOptions(o),
				fanout.WithFanoutBefore(
					fanout.ForwardBody(true),
					func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
						message, err := wrphttp.NewMessageFromHeaders(original.Header, bytes.NewReader(body))
						if err != nil {
							return ctx, err
						}

						fanout.Header.Set("X-Webpa-Device-Name", message.Destination)
						return ctx, nil
					},
				),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.JSON.ContentType()).Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				fanout.WithOptions(o),
				fanout.WithFanoutBefore(
					func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
						var (
							message wrp.Message
							decoder = wrp.NewDecoderBytes(body, wrp.JSON)
						)

						if err := decoder.Decode(&message); err != nil {
							return ctx, err
						}

						var (
							buffer  bytes.Buffer
							encoder = wrp.NewEncoder(&buffer, wrp.Msgpack)
						)

						if err := encoder.Encode(&message); err != nil {
							return ctx, err
						}

						fanoutBody := buffer.Bytes()
						fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(fanoutBody)
						fanout.ContentLength = int64(len(fanoutBody))
						fanout.Header.Set("Content-Type", wrp.Msgpack.ContentType())
						fanout.Header.Set("X-Webpa-Device-Name", message.Destination)
						return ctx, nil
					},
				),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.Msgpack.ContentType()).Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				fanout.WithOptions(o),
				fanout.WithFanoutBefore(
					func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
						var (
							message wrp.Message
							decoder = wrp.NewDecoderBytes(body, wrp.Msgpack)
						)

						if err := decoder.Decode(&message); err != nil {
							return ctx, err
						}

						fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(body)
						fanout.ContentLength = int64(len(body))
						fanout.Header.Set("Content-Type", wrp.Msgpack.ContentType())
						fanout.Header.Set("X-Webpa-Device-Name", message.Destination)
						return ctx, nil
					},
				),
			),
		),
	)

	return nil
}

func addFanoutRoutes(logger log.Logger, handlerChain alice.Chain, r *mux.Router, endpoints fanout.Endpoints, o fanout.Options) error {
	handler := fanout.New(
		endpoints,
		fanout.WithOptions(o),
		fanout.WithFanoutBefore(fanout.ForwardVariableAsHeader("deviceID", "X-Webpa-Device-Name")),
	)

	r.Handle(
		fmt.Sprintf("%s/%s/device/{deviceID}/stat", baseURI, version),
		handlerChain.Then(handler),
	).Methods("GET")

	return nil
}

func authChain(v *viper.Viper, logger log.Logger, registry xmetrics.Registry) (alice.Chain, error) {
	var (
		m              = secure.NewJWTValidationMeasures(registry)
		validator, err = validators(v, m)
	)

	if err != nil {
		return alice.Chain{}, err
	}

	authHandler := handler.AuthorizationHandler{
		HeaderName:          "Authorization",
		ForbiddenStatusCode: 403,
		Validator:           validator,
		Logger:              logger,
	}

	authHandler.DefineMeasures(m)
	return alice.New(authHandler.Decorate), nil
}

func validators(v *viper.Viper, m *secure.JWTValidationMeasures) (validator secure.Validator, err error) {
	var jwtVals []JWTValidator

	v.UnmarshalKey("jwtValidators", &jwtVals)

	// if a JWTKeys section was supplied, configure a JWS validator
	// and append it to the chain of validators
	validators := make(secure.Validators, 0, len(jwtVals))

	for _, validatorDescriptor := range jwtVals {
		validatorDescriptor.Custom.DefineMeasures(m)

		var keyResolver key.Resolver
		keyResolver, err = validatorDescriptor.Keys.NewResolver()
		if err != nil {
			validator = validators
			return
		}

		validator := secure.JWSValidator{
			DefaultKeyId:  DefaultKeyID,
			Resolver:      keyResolver,
			JWTValidators: []*jwt.Validator{validatorDescriptor.Custom.New()},
		}

		validator.DefineMeasures(m)
		validators = append(validators, validator)
	}

	basicAuth := v.GetStringSlice("authHeader")
	for _, authValue := range basicAuth {
		validators = append(
			validators,
			secure.ExactMatchValidator(authValue),
		)
	}

	validator = validators

	return
}

func NewPrimaryHandler(logger log.Logger, v *viper.Viper, registry xmetrics.Registry, e service.Environment) (http.Handler, error) {
	var o fanout.Options
	if err := v.Unmarshal(&o); err != nil {
		return nil, err
	}

	var handlerChain alice.Chain
	if authChain, err := authChain(v, logger, registry); err != nil {
		return nil, err
	} else {
		handlerChain = authChain.Extend(fanout.NewChain(o))
	}

	endpoints, err := fanout.NewEndpoints(o, fanout.ServiceEndpointsAlternate(fanout.WithAccessorFactory(e.AccessorFactory())))
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()

	/*
		if err := addDeviceSendRoutes(logger, handlerChain, router, o); err != nil {
			return nil, err
		}
	*/

	if err := addFanoutRoutes(logger, handlerChain, router, endpoints, o); err != nil {
		return nil, err
	}

	return router, nil
}
