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
	"github.com/Comcast/webpa-common/bookkeeping"
	"github.com/Comcast/webpa-common/logging/logginghttp"
	"github.com/Comcast/webpa-common/secure"
	"github.com/Comcast/webpa-common/secure/handler"
	"github.com/Comcast/webpa-common/secure/key"
	"github.com/Comcast/webpa-common/service"
	"github.com/Comcast/webpa-common/wrp"
	"github.com/Comcast/webpa-common/wrp/wrphttp"
	"github.com/Comcast/webpa-common/xhttp"
	"github.com/Comcast/webpa-common/xhttp/fanout"
	"github.com/Comcast/webpa-common/xhttp/xcontext"
	"github.com/Comcast/webpa-common/xmetrics"
	"github.com/SermoDigital/jose/jwt"
	"github.com/go-kit/kit/log"
	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	baseURI = "/api"
	version = "v2"
)

func populateMessage(ctx context.Context, message *wrp.Message) {
	if values, ok := handler.FromContext(ctx); ok {
		message.PartnerIDs = values.PartnerIDs
	}
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

	bookkeeperPop := xcontext.Populate(0,
		logginghttp.SetLogger(logger, // custom logger func for Bookkeeping
			func(kv []interface{}, request *http.Request) []interface{} {
				if reqContextValues, ok := handler.FromContext(request.Context()); ok {
					kv = append(kv, "satClientID", reqContextValues.SatClientID)
					kv = append(kv, "partnerIDs", "["+strings.Join(reqContextValues.PartnerIDs, ", ")+"]")
				}

				body, err := ioutil.ReadAll(request.Body)
				if err != nil {
					return kv
				}
				request.Body.Close()
				request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

				var message wrp.Message

				switch request.Header.Get("Content-Type") {
				case wrp.Msgpack.ContentType():
					decoder := wrp.NewDecoderBytes(body, wrp.Msgpack)
					if err := decoder.Decode(&message); err != nil {
						return kv
					}
				case wrp.JSON.ContentType():
					decoder := wrp.NewDecoderBytes(body, wrp.JSON)
					if err := decoder.Decode(&message); err != nil {
						return kv
					}
				default:
					msg, err := wrphttp.NewMessageFromHeaders(request.Header, bytes.NewReader(body))
					if err != nil {
						return kv
					}
					message = *msg
				}

				// get the values
				if message.TransactionUUID != "" {
					kv = append(kv, "wrp.transaction_uuid", message.TransactionUUID)
				}
				if message.TransactionUUID != "" {
					kv = append(kv, "wrp.dest", message.Destination)
				}
				if message.TransactionUUID != "" {
					kv = append(kv, "wrp.source", message.Source)
				}
				if message.TransactionUUID != "" {
					kv = append(kv, "wrp.msg_type", message.MessageType())
				}
				if message.Status != nil {
					kv = append(kv, "wrp.status", *message.Status)
				}
				return kv
			}, ),
		gokithttp.PopulateRequestContext,
	)

	bookkeeper := bookkeeping.New(bookkeeping.WithResponses(bookkeeping.ResponseHeadersWithPrefix("X-")))
	return alice.New(authHandler.Decorate, bookkeeperPop, bookkeeper), nil
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
	var cfg fanout.Configuration
	if err := v.UnmarshalKey("fanout", &cfg); err != nil {
		return nil, err
	}

	authChain, err := authChain(v, logger, registry)
	if err != nil {
		return nil, err
	}

	var (
		handlerChain = authChain.Extend(
			fanout.NewChain(
				cfg,
				logginghttp.SetLogger(
					logger,
					logginghttp.RequestInfo,

					// custom logger func that extracts the intended destination of requests from the headers and context
					func(kv []interface{}, request *http.Request) []interface{} {

						if deviceName := request.Header.Get("X-Webpa-Device-Name"); len(deviceName) > 0 {
							return append(kv, "X-Webpa-Device-Name", deviceName)
						}

						if variables := mux.Vars(request); len(variables) > 0 {
							if deviceID := variables["deviceID"]; len(deviceID) > 0 {
								return append(kv, "deviceID", deviceID)
							}
						}

						return kv
					},
				),
			),
		)

		transactor = fanout.NewTransactor(cfg)
		options    = []fanout.Option{
			fanout.WithTransactor(transactor),
		}
	)

	if len(cfg.Authorization) > 0 {
		options = append(
			options,
			fanout.WithClientBefore(
				gokithttp.SetRequestHeader("Authorization", "Basic "+cfg.Authorization),
			),
		)
	}

	// use the inject endpoints if present, or fallback to the alternate service discovery endpoints
	var alternate func() (fanout.Endpoints, error)
	if e != nil {
		alternate = fanout.ServiceEndpointsAlternate(fanout.WithAccessorFactory(e.AccessorFactory()))
	}

	endpoints, err := fanout.NewEndpoints(cfg, alternate)
	if err != nil {
		return nil, err
	}

	var (
		router        = mux.NewRouter()
		sendSubrouter = router.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Methods("POST", "PUT").Subrouter()
	)

	router.NotFoundHandler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
	})

	sendSubrouter.Headers(wrphttp.MessageTypeHeader, "").Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						fanout.UsePath(fmt.Sprintf("%s/%s/device/send", baseURI, version)),
						func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
							message, err := wrphttp.NewMessageFromHeaders(original.Header, bytes.NewReader(body))
							if err != nil {
								return ctx, err
							}
							return doFanout(ctx, fanout, message)
						},
					),
					fanout.WithFanoutFailure(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
					fanout.WithFanoutAfter(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
				)...,

			),
		),
	)

	sendSubrouter.Headers("Content-Type", wrp.JSON.ContentType()).Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						fanout.UsePath(fmt.Sprintf("%s/%s/device/send", baseURI, version)),
						func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
							var (
								message wrp.Message
								decoder = wrp.NewDecoderBytes(body, wrp.JSON)
							)
							if err := decoder.Decode(&message); err != nil {
								return ctx, err
							}
							return doFanout(ctx, fanout, &message)
						},
					),
					fanout.WithFanoutFailure(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
					fanout.WithFanoutAfter(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
				)...,
			),
		),
	)

	sendSubrouter.Headers("Content-Type", wrp.Msgpack.ContentType()).Handler(
		handlerChain.Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						fanout.UsePath(fmt.Sprintf("%s/%s/device/send", baseURI, version)),
						func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
							var (
								message wrp.Message
								decoder = wrp.NewDecoderBytes(body, wrp.Msgpack)
							)
							if err := decoder.Decode(&message); err != nil {
								return ctx, err
							}
							return doFanout(ctx, fanout, &message)
						},
					),
					fanout.WithFanoutFailure(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
					fanout.WithFanoutAfter(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
				)...,
			),
		),
	)

	router.Handle(
		fmt.Sprintf("%s/%s/device/{deviceID}/stat", baseURI, version),
		handlerChain.Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						fanout.ForwardVariableAsHeader("deviceID", "X-Webpa-Device-Name"),
					),
					fanout.WithFanoutFailure(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
					fanout.WithFanoutAfter(
						fanout.ReturnHeadersWithPrefix("X-"),
					),
				)...,
			),
		),
	).Methods("GET")

	return router, nil
}

func doFanout(ctx context.Context, fanout *http.Request, message *wrp.Message) (context.Context, error) {
	populateMessage(ctx, message)

	var buffer bytes.Buffer
	if err := wrp.NewEncoder(&buffer, wrp.Msgpack).Encode(message); err != nil {
		return ctx, err
	}

	fanoutBody := buffer.Bytes()
	fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(fanoutBody)
	fanout.ContentLength = int64(len(fanoutBody))
	fanout.Header.Set("Content-Type", wrp.Msgpack.ContentType())
	fanout.Header.Set("X-Webpa-Device-Name", message.Destination)
	return ctx, nil
}
