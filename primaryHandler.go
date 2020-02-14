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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/goph/emperror"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/webpa-common/basculechecks"
	"github.com/xmidt-org/webpa-common/basculemetrics"
	"github.com/xmidt-org/webpa-common/logging"
	"github.com/xmidt-org/webpa-common/logging/logginghttp"
	"github.com/xmidt-org/webpa-common/service"
	"github.com/xmidt-org/webpa-common/service/monitor"
	"github.com/xmidt-org/webpa-common/xhttp/fanout"
	"github.com/xmidt-org/webpa-common/xmetrics"
	"github.com/xmidt-org/wrp-go/v2"
	"github.com/xmidt-org/wrp-go/v2/wrphttp"
)

const (
	baseURI = "/api"
	version = "v2"
	apiBase = baseURI + "/" + version + "/"

	basicAuthConfigKey = "authHeader"
	jwtAuthConfigKey   = "jwtValidator"
	wrpCheckConfigKey  = "WRPCheck"
)

func SetLogger(logger log.Logger) func(delegate http.Handler) http.Handler {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ctx := r.WithContext(logging.WithLogger(r.Context(),
					log.With(logger, "requestHeaders", r.Header, "requestURL", r.URL.EscapedPath(), "method", r.Method)))
				delegate.ServeHTTP(w, ctx)
			})
	}
}

func GetLogger(ctx context.Context) bascule.Logger {
	logger := log.With(logging.GetLogger(ctx), "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	return logger
}

func authChain(v *viper.Viper, logger log.Logger, registry xmetrics.Registry) (alice.Chain, error) {
	if registry == nil {
		return alice.Chain{}, errors.New("nil registry")
	}

	basculeMeasures := basculemetrics.NewAuthValidationMeasures(registry)
	capabilityCheckMeasures := basculechecks.NewAuthCapabilityCheckMeasures(registry)
	listener := basculemetrics.NewMetricListener(basculeMeasures)

	basicAllowed := make(map[string]string)
	basicAuth := v.GetStringSlice(basicAuthConfigKey)
	for _, a := range basicAuth {
		decoded, err := base64.StdEncoding.DecodeString(a)
		if err != nil {
			logging.Info(logger).Log(logging.MessageKey(), "failed to decode auth header", "authHeader", a, logging.ErrorKey(), err.Error())
		}

		i := bytes.IndexByte(decoded, ':')
		logging.Debug(logger).Log(logging.MessageKey(), "decoded string", "string", decoded, "i", i)
		if i > 0 {
			basicAllowed[string(decoded[:i])] = string(decoded[i+1:])
		}
	}
	logging.Debug(logger).Log(logging.MessageKey(), "Created list of allowed basic auths", "allowed", basicAllowed, "config", basicAuth)

	options := []basculehttp.COption{
		basculehttp.WithCLogger(GetLogger),
		basculehttp.WithCErrorResponseFunc(listener.OnErrorResponse),
		basculehttp.WithParseURLFunc(basculehttp.CreateRemovePrefixURLFunc(apiBase, basculehttp.DefaultParseURLFunc)),
	}
	if len(basicAllowed) > 0 {
		options = append(options, basculehttp.WithTokenFactory("Basic", basculehttp.BasicTokenFactory(basicAllowed)))
	}
	var jwtVal JWTValidator

	v.UnmarshalKey("jwtValidator", &jwtVal)
	if jwtVal.Keys.URI != "" {
		resolver, err := jwtVal.Keys.NewResolver()
		if err != nil {
			return alice.Chain{}, emperror.With(err, "failed to create resolver")
		}

		options = append(options, basculehttp.WithTokenFactory("Bearer", basculehttp.BearerTokenFactory{
			DefaultKeyId: DefaultKeyID,
			Resolver:     resolver,
			Parser:       bascule.DefaultJWTParser,
			Leeway:       jwtVal.Leeway,
		}))
	}

	authConstructor := basculehttp.NewConstructor(options...)

	bearerRules := bascule.Validators{
		bascule.CreateNonEmptyPrincipalCheck(),
		bascule.CreateNonEmptyTypeCheck(),
		bascule.CreateValidTypeCheck([]string{"jwt"}),
		requirePartnersJWTClaim,
	}

	// only add capability check if the configuration is set
	var capabilityCheck CapabilityConfig
	v.UnmarshalKey("capabilityCheck", &capabilityCheck)
	if capabilityCheck.Type == "enforce" || capabilityCheck.Type == "monitor" {
		checker, err := basculechecks.NewCapabilityChecker(capabilityCheckMeasures, capabilityCheck.Prefix, capabilityCheck.AcceptAllMethod)
		if err != nil {
			return alice.Chain{}, emperror.With(err, "failed to create capability check")
		}
		bearerRules = append(bearerRules, checker.CreateBasculeCheck(capabilityCheck.Type == "enforce"))
	}

	authEnforcer := basculehttp.NewEnforcer(
		basculehttp.WithELogger(GetLogger),
		basculehttp.WithRules("Basic", bascule.Validators{
			bascule.CreateAllowAllCheck(),
		}),
		basculehttp.WithRules("Bearer", bearerRules),
		basculehttp.WithEErrorResponseFunc(listener.OnErrorResponse),
	)

	constructors := []alice.Constructor{SetLogger(logger), authConstructor, authEnforcer, basculehttp.NewListenerDecorator(listener)}

	return alice.New(constructors...), nil
}

// createEndpoints examines the configuration and produces an appropriate fanout.Endpoints, either using the configured
// endpoints or service discovery.
func createEndpoints(logger log.Logger, cfg fanout.Configuration, registry xmetrics.Registry, e service.Environment) (fanout.Endpoints, error) {

	if len(cfg.Endpoints) > 0 {
		logger.Log(level.Key(), level.InfoValue(), logging.MessageKey(), "using configured endpoints for fanout", "endpoints", cfg.Endpoints)
		return fanout.ParseURLs(cfg.Endpoints...)
	} else if e != nil {
		logger.Log(level.Key(), level.InfoValue(), logging.MessageKey(), "using service discovery for fanout")
		endpoints := fanout.NewServiceEndpoints(fanout.WithAccessorFactory(e.AccessorFactory()))

		_, err := monitor.New(
			monitor.WithLogger(logger),
			monitor.WithFilter(monitor.NewNormalizeFilter(e.DefaultScheme())),
			monitor.WithEnvironment(e),
			monitor.WithListeners(
				monitor.NewMetricsListener(registry),
				endpoints,
			),
		)

		return endpoints, err
	}

	return nil, errors.New("Unable to create endpoints")
}

func NewPrimaryHandler(logger log.Logger, v *viper.Viper, registry xmetrics.Registry, e service.Environment) (http.Handler, error) {
	var cfg fanout.Configuration
	if err := v.UnmarshalKey("fanout", &cfg); err != nil {
		return nil, err
	}
	logging.Error(logger).Log(logging.MessageKey(), "creating primary handler")

	endpoints, err := createEndpoints(logger, cfg, registry, e)
	if err != nil {
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

					// custom logger func that extracts the intended destination of requests
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

	var (
		router        = mux.NewRouter()
		sendSubrouter = router.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Methods("POST", "PUT").Subrouter()
	)

	router.NotFoundHandler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
	})

	fanoutHandler := fanout.New(
		endpoints,
		append(
			options,
			fanout.WithFanoutBefore(
				fanout.UsePath(fmt.Sprintf("%s/%s/device/send", baseURI, version)),
			),
			fanout.WithFanoutFailure(
				fanout.ReturnHeadersWithPrefix("X-"),
			),
			fanout.WithFanoutAfter(
				fanout.ReturnHeadersWithPrefix("X-"),
			),
		)...,
	)

	var (
		wrpCheckConfig   WRPCheckConfig
		WRPFanoutHandler wrphttp.Handler
	)

	if v.IsSet(wrpCheckConfigKey) {
		if v.IsSet(basicAuthConfigKey) {
			return nil, errors.New("WRP PartnerID checks cannot be enabled with basic authentication")
		}

		if !v.IsSet(jwtAuthConfigKey) {
			return nil, errors.New("WRP PartnerID checks require JWT authentication to be enabled")
		}
	}

	v.UnmarshalKey(wrpCheckConfigKey, &wrpCheckConfig)

	if wrpCheckConfig.Type == "enforce" || wrpCheckConfig.Type == "monitor" {
		WRPFanoutHandler = newWRPFanoutHandlerWithPIDCheck(
			fanoutHandler,
			&wrpPartnersAccess{
				strict:                  wrpCheckConfig.Type == "enforce",
				receivedWRPMessageCount: NewReceivedWRPCounter(registry),
			})
	} else {
		WRPFanoutHandler = newWRPFanoutHandler(fanoutHandler)
	}

	sendWRPHandler := wrphttp.NewHTTPHandler(WRPFanoutHandler,
		wrphttp.WithDecoder(wrphttp.DecodeEntityFromSources(wrp.Msgpack, true)),
		wrphttp.WithNewResponseWriter(nonWRPResponseWriterFactory))

	sendSubrouter.Headers(
		wrphttp.MessageTypeHeader, "",
		"Content-Type", wrp.Msgpack.ContentType(),
		"Content-Type", wrp.JSON.ContentType()).
		Handler(handlerChain.Then(sendWRPHandler))

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
