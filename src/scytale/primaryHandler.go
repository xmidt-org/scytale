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
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Comcast/webpa-common/middleware/fanout"
	"github.com/Comcast/webpa-common/middleware/fanout/fanouthttp"
	"github.com/Comcast/webpa-common/secure"
	"github.com/Comcast/webpa-common/secure/handler"
	"github.com/Comcast/webpa-common/secure/key"
	"github.com/Comcast/webpa-common/tracing"
	"github.com/Comcast/webpa-common/webhook"
	"github.com/Comcast/webpa-common/wrp"
	"github.com/Comcast/webpa-common/wrp/wrphttp"
	"github.com/SermoDigital/jose/jwt"
	"github.com/go-kit/kit/log"
	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
)

const (
	baseURI = "/api"
	version = "v2"
)

// addDeviceSendRoutes is the legacy function that adds the fanout route for device/send
func addDeviceSendRoutes(logger log.Logger, r *mux.Router, v *viper.Viper) error {
	fanoutOptions := new(wrphttp.FanoutOptions)
	if err := v.UnmarshalKey("fanout", fanoutOptions); err != nil {
		return err
	}

	fanoutOptions.Logger = logger
	fanoutEndpoint, err := wrphttp.NewFanoutEndpoint(fanoutOptions)
	if err != nil {
		return err
	}

	subrouter := r.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Methods("POST", "PUT").Subrouter()

	subrouter.Headers(wrphttp.MessageTypeHeader, "").Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestHeaders(fanoutOptions.Logger),
			wrphttp.ServerEncodeResponseHeaders(""),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(""),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.JSON.ContentType()).Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(fanoutOptions.Logger, fanoutOptions.NewDecoderPool(wrp.JSON)),
			wrphttp.ServerEncodeResponseBody("", fanoutOptions.NewEncoderPool(wrp.JSON)),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(""),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.Msgpack.ContentType()).Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(fanoutOptions.Logger, fanoutOptions.NewDecoderPool(wrp.Msgpack)),
			wrphttp.ServerEncodeResponseBody("", fanoutOptions.NewEncoderPool(wrp.Msgpack)),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(""),
			),
		),
	)

	return nil
}

// addFanoutRoutes uses the new generic fanout and adds appropriate routes.  Right now, this is only /device/xxx/stat
func addFanoutRoutes(logger log.Logger, r *mux.Router, v *viper.Viper) error {
	options := new(fanouthttp.Options)
	if err := v.UnmarshalKey("fanout", options); err != nil {
		return err
	}

	// HACK! we need to preprocess the endpoints in order to strip path information
	urls := make([]string, len(options.Endpoints))
	for i := 0; i < len(options.Endpoints); i++ {
		parsed, err := url.Parse(options.Endpoints[i])
		if err != nil {
			return err
		}

		parsed.Path = ""
		parsed.RawPath = ""
		parsed.ForceQuery = false
		parsed.RawQuery = ""
		parsed.Fragment = ""

		urls[i] = parsed.String()
	}

	options.Logger = logger
	requestFuncs := []gokithttp.RequestFunc{
		fanouthttp.VariablesToHeaders("deviceID", "X-Webpa-Device-Name"),
	}

	// TODO: This should probably be handled generically by some infrastructure
	if len(options.Authorization) > 0 {
		requestFuncs = append(
			requestFuncs,
			gokithttp.SetRequestHeader("Authorization", "Basic "+options.Authorization),
		)
	}

	client := options.NewClient()
	client.CheckRedirect = CopyRedirectHeaders

	components, err := fanouthttp.NewComponents(
		urls,
		fanouthttp.EncodePassThroughRequest,
		fanouthttp.DecodePassThroughResponse,
		gokithttp.SetClient(client),
		gokithttp.ClientBefore(requestFuncs...),
	)

	if err != nil {
		return err
	}

	// this fanoutHandler is generic, as opposed to the legacy wrphttp fanout (above)
	fanoutHandler := fanouthttp.NewHandler(
		options.FanoutMiddleware()(
			fanout.New(tracing.NewSpanner(), components),
		),
		fanouthttp.DecodePassThroughRequest,
		fanouthttp.EncodePassThroughResponse,
		gokithttp.ServerErrorEncoder(
			fanouthttp.ServerErrorEncoder(""),
		),
	)

	r.Handle(
		fmt.Sprintf("%s/%s/device/{deviceID}/stat", baseURI, version),
		fanoutHandler,
	).Methods("GET")

	return nil
}

//ConfigureWebHooks sets route paths, initializes and synchronizes hook registries for this tr1d1um instance
//baseRouter is pre-configured with the api/v2 prefix path
//root is the original router used by webHookFactory.Initialize()
func addWebhooks(r *mux.Router, preHandler *alice.Chain, v *viper.Viper, logger log.Logger) (*webhook.Factory, error) {
	webHookFactory, err := webhook.NewFactory(v)

	if err != nil {
		return nil, err
	}

	baseRouter := r.PathPrefix(fmt.Sprintf("%s/%s", baseURI, version)).Subrouter()

	webHookRegistry, webHookHandler := webHookFactory.NewRegistryAndHandler()

	// register webHook end points for api
	baseRouter.Handle("/hook", preHandler.ThenFunc(webHookRegistry.UpdateRegistry))
	baseRouter.Handle("/hooks", preHandler.ThenFunc(webHookRegistry.GetRegistry))

	selfURL := &url.URL{
		Scheme: "https",
		Host:   v.GetString("fqdn") + v.GetString("primary.address"),
	}

	webHookFactory.Initialize(r, selfURL, webHookHandler, logger, nil)
	return webHookFactory, nil
}

//getPreHandler configures the authorization requirements for requests trying to reach subsequent handler
func getPreHandler(v *viper.Viper, logger log.Logger) (preHandler *alice.Chain, err error) {
	validator, err := getValidator(v)

	if err != nil {
		return
	}

	authHandler := handler.AuthorizationHandler{
		HeaderName:          "Authorization",
		ForbiddenStatusCode: 403,
		Validator:           validator,
		Logger:              logger,
	}

	newPreHandler := alice.New(authHandler.Decorate)
	preHandler = &newPreHandler
	return
}

//getValidator returns a validator for JWT/Basic tokens
//It reads in tokens from a config file. Zero or more tokens
//can be read.
func getValidator(v *viper.Viper) (validator secure.Validator, err error) {
	var jwtVals []JWTValidator

	err = v.UnmarshalKey("jwtValidators", &jwtVals)

	if err != nil {
		return nil, err
	}

	// if a JWTKeys section was supplied, configure a JWS validator
	// and append it to the chain of validators
	validators := make(secure.Validators, 0, len(jwtVals))

	for _, validatorDescriptor := range jwtVals {
		var keyResolver key.Resolver
		keyResolver, err = validatorDescriptor.Keys.NewResolver()
		if err != nil {
			validator = validators
			return
		}

		validators = append(
			validators,
			secure.JWSValidator{
				DefaultKeyId:  DefaultKeyID,
				Resolver:      keyResolver,
				JWTValidators: []*jwt.Validator{validatorDescriptor.Custom.New()},
			},
		)
	}

	basicAuth := v.GetStringSlice("authHeader")

	// if basic auth tokens are provided, add them to the validators list as well
	for _, authValue := range basicAuth {
		validators = append(
			validators,
			secure.ExactMatchValidator(authValue),
		)
	}

	validator = validators

	return
}

func NewPrimaryHandler(logger log.Logger, v *viper.Viper) (handler http.Handler, factory *webhook.Factory, err error) {
	router := mux.NewRouter()
	var preHandler *alice.Chain

	if err = addDeviceSendRoutes(logger, router, v); err == nil {
		if err = addFanoutRoutes(logger, router, v); err == nil {
			if preHandler, err = getPreHandler(v, logger); err == nil {
				factory, err = addWebhooks(router, preHandler, v, logger)
			}
		}
	}

	return router, factory, err
}

// Copy the headers when our requests are redirected because go 1.9.2
// and before will NOT copy over the Authorization headers for us.
func CopyRedirectHeaders(r *http.Request, via []*http.Request) error {
	redirects := len(via)
	if 10 <= redirects {
		return errors.New("Too many redirects.")
	}

	for k, vals := range via[0].Header {
		for _, v := range vals {
			r.Header.Add(k, v)
		}
	}

	return nil
}
