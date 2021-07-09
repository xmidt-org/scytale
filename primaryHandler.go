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
	"regexp"

	"github.com/xmidt-org/candlelight"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"

	"github.com/xmidt-org/webpa-common/device"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/goph/emperror"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
	"github.com/xmidt-org/bascule"
	bchecks "github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/webpa-common/basculechecks"
	"github.com/xmidt-org/webpa-common/basculemetrics"
	"github.com/xmidt-org/webpa-common/logging"
	"github.com/xmidt-org/webpa-common/logging/logginghttp"
	"github.com/xmidt-org/webpa-common/service"
	"github.com/xmidt-org/webpa-common/service/monitor"
	"github.com/xmidt-org/webpa-common/xhttp"
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

var errNoDeviceName = errors.New("no device name")

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
		basculehttp.WithCLogger(getLogger),
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
			DefaultKeyID: DefaultKeyID,
			Resolver:     resolver,
			Parser:       bascule.DefaultJWTParser,
			Leeway:       jwtVal.Leeway,
		}))
	}

	authConstructor := basculehttp.NewConstructor(options...)

	bearerRules := bascule.Validators{
		bchecks.NonEmptyPrincipal(),
		bchecks.NonEmptyType(),
		bchecks.ValidType([]string{"jwt"}),
		requirePartnersJWTClaim,
	}

	// only add capability check if the configuration is set
	var capabilityCheck CapabilityConfig
	v.UnmarshalKey("capabilityCheck", &capabilityCheck)
	if capabilityCheck.Type == "enforce" || capabilityCheck.Type == "monitor" {
		var endpoints []*regexp.Regexp
		c, err := basculechecks.NewEndpointRegexCheck(capabilityCheck.Prefix, capabilityCheck.AcceptAllMethod)
		if err != nil {
			return alice.Chain{}, emperror.With(err, "failed to create capability check")
		}
		for _, e := range capabilityCheck.EndpointBuckets {
			r, err := regexp.Compile(e)
			if err != nil {
				logging.Error(logger).Log(logging.MessageKey(), "failed to compile regular expression", "regex", e, logging.ErrorKey(), err.Error())
				continue
			}
			endpoints = append(endpoints, r)
		}
		m := basculechecks.MetricValidator{
			C:         basculechecks.CapabilitiesValidator{Checker: c},
			Measures:  capabilityCheckMeasures,
			Endpoints: endpoints,
		}
		bearerRules = append(bearerRules, m.CreateValidator(capabilityCheck.Type == "enforce"))
	}

	authEnforcer := basculehttp.NewEnforcer(
		basculehttp.WithELogger(getLogger),
		basculehttp.WithRules("Basic", bascule.Validators{
			bchecks.AllowAll(),
		}),
		basculehttp.WithRules("Bearer", bearerRules),
		basculehttp.WithEErrorResponseFunc(listener.OnErrorResponse),
	)

	constructors := []alice.Constructor{setLogger(logger), authConstructor, authEnforcer, basculehttp.NewListenerDecorator(listener)}

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
		endpoints := fanout.NewServiceEndpoints(
			fanout.WithAccessorFactory(e.AccessorFactory()),
			// required to get deviceID from either the header or the path
			fanout.WithKeyFunc(func(request *http.Request) ([]byte, error) {
				deviceName := request.Header.Get(device.DeviceNameHeader)
				// If deviceID is present in url us it instead.
				// This is important for routing to the correct talaria.
				if variables := mux.Vars(request); len(variables) > 0 {
					if deviceID := variables["deviceID"]; len(deviceID) > 0 {
						deviceName = deviceID
					}
				}
				if len(deviceName) == 0 {
					return nil, errNoDeviceName
				}

				id, err := device.ParseID(deviceName)
				if err != nil {
					return nil, err
				}

				return id.Bytes(), nil
			}),
		)

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

func NewPrimaryHandler(logger log.Logger, v *viper.Viper, registry xmetrics.Registry, e service.Environment, tracing candlelight.Tracing) (http.Handler, error) {
	var cfg fanout.Configuration
	if err := v.UnmarshalKey("fanout", &cfg); err != nil {
		return nil, err
	}
	logging.Error(logger).Log(logging.MessageKey(), "creating primary handler")
	cfg.Tracing = tracing
	endpoints, err := createEndpoints(logger, cfg, registry, e)
	if err != nil {
		return nil, err
	}

	authChain, err := authChain(v, logger, registry)
	if err != nil {
		return nil, err
	}

	var (
		transactor = fanout.NewTransactor(cfg)
		options    = []fanout.Option{
			fanout.WithTransactor(transactor),
			fanout.WithErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("X-Midt-Error", err.Error())
				if headerer, ok := err.(gokithttp.Headerer); ok {
					for k, values := range headerer.Headers() {
						for _, v := range values {
							w.Header().Add(k, v)
						}
					}
				}
				code := http.StatusInternalServerError
				switch err {
				case device.ErrorInvalidDeviceName:
					code = http.StatusBadRequest
				case device.ErrorDeviceNotFound:
					code = http.StatusNotFound
				case device.ErrorNonUniqueID:
					code = http.StatusBadRequest
				case device.ErrorInvalidTransactionKey:
					code = http.StatusBadRequest
				case device.ErrorTransactionAlreadyRegistered:
					code = http.StatusBadRequest
				case device.ErrorMissingPathVars:
					code = http.StatusBadRequest
				case device.ErrorNoSuchTransactionKey:
					code = http.StatusBadGateway
				case device.ErrorMissingDeviceNameHeader:
					code = http.StatusBadRequest
				case errNoDeviceName:
					code = http.StatusBadRequest
				}
				if sc, ok := err.(gokithttp.StatusCoder); ok {
					code = sc.StatusCode()
				}
				w.WriteHeader(code)
			}),
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

	otelMuxOptions := []otelmux.Option{
		otelmux.WithPropagators(tracing.Propagator()),
		otelmux.WithTracerProvider(tracing.TracerProvider()),
	}
	router.Use(otelmux.Middleware("mainSpan", otelMuxOptions...), candlelight.EchoFirstTraceNodeInfo(tracing.Propagator()))

	router.NotFoundHandler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		xhttp.WriteError(response, http.StatusBadRequest, "Invalid endpoint")
	})

	fanoutChain := fanout.NewChain(
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
			}, candlelight.InjectTraceInfoInLogger(),
		),
	)

	HTTPFanoutHandler := fanoutChain.Then(
		fanout.New(
			endpoints,
			append(
				options,
				fanout.WithFanoutBefore(
					fanout.ForwardHeaders("Content-Type", "X-Webpa-Device-Name"),
					fanout.UsePath(fmt.Sprintf("%s/%s/device/send", baseURI, version)),

					func(ctx context.Context, _, fanout *http.Request, body []byte) (context.Context, error) {
						fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(body)
						fanout.ContentLength = int64(len(body))
						return ctx, nil
					},
				),
				fanout.WithFanoutFailure(
					fanout.ReturnHeadersWithPrefix("X-"),
				),
				fanout.WithFanoutAfter(
					fanout.ReturnHeadersWithPrefix("X-"),
				),
			)...,
		))

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
			HTTPFanoutHandler,
			&wrpPartnersAccess{
				strict:                  wrpCheckConfig.Type == "enforce",
				receivedWRPMessageCount: NewReceivedWRPCounter(registry),
			})
	} else {
		WRPFanoutHandler = newWRPFanoutHandler(HTTPFanoutHandler)
	}

	sendWRPHandler := wrphttp.NewHTTPHandler(WRPFanoutHandler,
		wrphttp.WithDecoder(wrphttp.DecodeEntityFromSources(wrp.Msgpack, true)),
		wrphttp.WithNewResponseWriter(nonWRPResponseWriterFactory))

	sendSubrouter.Headers(
		wrphttp.MessageTypeHeader, "").
		Handler(authChain.Then(sendWRPHandler))

	sendSubrouter.Headers("Content-Type", wrp.Msgpack.ContentType()).
		Handler(authChain.Then(sendWRPHandler))

	sendSubrouter.Headers("Content-Type", wrp.JSON.ContentType()).
		Handler(authChain.Then(sendWRPHandler))

	router.Handle(
		fmt.Sprintf("%s/%s/device/{deviceID}/stat", baseURI, version),
		authChain.Extend(fanoutChain).Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						// required for petasos
						fanout.ForwardVariableAsHeader("deviceID", "X-Webpa-Device-Name"),
						// required for consul fanout
						func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
							fanout.URL.Path = original.URL.Path
							fanout.URL.RawPath = ""
							return ctx, nil
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
	).Methods("GET")

	return router, nil
}
