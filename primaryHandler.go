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
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/candlelight"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/clortho/clorthometrics"
	"github.com/xmidt-org/clortho/clorthozap"
	"github.com/xmidt-org/sallust"
	"github.com/xmidt-org/touchstone"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.uber.org/zap"

	"github.com/xmidt-org/webpa-common/secure/handler"
	"github.com/xmidt-org/webpa-common/v2/device"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/goph/emperror"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/viper"
	"github.com/xmidt-org/bascule"
	bchecks "github.com/xmidt-org/bascule/basculechecks"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/webpa-common/v2/basculechecks"
	"github.com/xmidt-org/webpa-common/v2/basculemetrics"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/logging"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/service"
	"github.com/xmidt-org/webpa-common/v2/service/monitor"
	"github.com/xmidt-org/webpa-common/v2/xhttp"
	"github.com/xmidt-org/webpa-common/v2/xhttp/fanout"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/xmetrics"
	"github.com/xmidt-org/wrp-go/v3"
	"github.com/xmidt-org/wrp-go/v3/wrpcontext"
	"github.com/xmidt-org/wrp-go/v3/wrphttp"
)

const (
	apiVersion         = "v3"
	prevAPIVersion     = "v2"
	apiBase            = "api/" + apiVersion
	prevAPIBase        = "api/" + prevAPIVersion
	apiBaseDualVersion = "api/{version:" + apiVersion + "|" + prevAPIVersion + "}"

	basicAuthConfigKey = "authHeader"
	jwtAuthConfigKey   = "jwtValidator"
	wrpCheckConfigKey  = "WRPCheck"

	deviceID = "deviceID"

	enforceCheck = "enforce"
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
			continue
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
	}
	if len(basicAllowed) > 0 {
		options = append(options, basculehttp.WithTokenFactory("Basic", basculehttp.BasicTokenFactory(basicAllowed)))
	}

	var jwtVal JWTValidator
	// Get jwt configuration, including clortho's configuration
	v.UnmarshalKey("jwtValidator", &jwtVal)
	// Instantiate a keyring for refresher and resolver to share
	kr := clortho.NewKeyRing()

	// Instantiate a fetcher for refresher and resolver to share
	f, err := clortho.NewFetcher()
	if err != nil {
		return alice.Chain{}, emperror.With(err, "failed to create clortho fetcher")
	}

	ref, err := clortho.NewRefresher(
		clortho.WithConfig(jwtVal.Config),
		clortho.WithFetcher(f),
	)
	if err != nil {
		return alice.Chain{}, emperror.With(err, "failed to create clortho refresher")
	}

	resolver, err := clortho.NewResolver(
		clortho.WithConfig(jwtVal.Config),
		clortho.WithKeyRing(kr),
		clortho.WithFetcher(f),
	)
	if err != nil {
		return alice.Chain{}, emperror.With(err, "failed to create clortho resolver")
	}

	promReg, ok := registry.(prometheus.Registerer)
	if !ok {
		return alice.Chain{}, errors.New("failed to get prometheus registerer")
	}

	var (
		tsConfig touchstone.Config
		zConfig  sallust.Config
	)
	// Get touchstone & zap configurations
	v.UnmarshalKey("touchstone", &tsConfig)
	v.UnmarshalKey("zap", &zConfig)
	zlogger := zap.Must(zConfig.Build())
	tf := touchstone.NewFactory(tsConfig, zlogger, promReg)
	// Instantiate a metric listener for refresher and resolver to share
	cml, err := clorthometrics.NewListener(clorthometrics.WithFactory(tf))
	if err != nil {
		return alice.Chain{}, emperror.With(err, "failed to create clortho metrics listener")
	}

	// Instantiate a logging listener for refresher and resolver to share
	czl, err := clorthozap.NewListener(
		clorthozap.WithLogger(zlogger),
	)
	if err != nil {
		return alice.Chain{}, emperror.With(err, "failed to create clortho zap logger listener")
	}

	resolver.AddListener(cml)
	resolver.AddListener(czl)
	ref.AddListener(cml)
	ref.AddListener(czl)
	ref.AddListener(kr)
	// context.Background() is for the unused `context.Context` argument in refresher.Start
	ref.Start(context.Background())
	// Shutdown refresher's goroutines when SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		<-sigs
		// context.Background() is for the unused `context.Context` argument in refresher.Stop
		ref.Stop(context.Background())
	}()

	options = append(options, basculehttp.WithTokenFactory("Bearer", basculehttp.BearerTokenFactory{
		DefaultKeyID: DefaultKeyID,
		Resolver:     resolver,
		Parser:       bascule.DefaultJWTParser,
		Leeway:       jwtVal.Leeway,
	}))
	authConstructor := basculehttp.NewConstructor(append([]basculehttp.COption{
		basculehttp.WithParseURLFunc(basculehttp.CreateRemovePrefixURLFunc("/"+apiBase+"/", basculehttp.DefaultParseURLFunc)),
	}, options...)...)
	authConstructorLegacy := basculehttp.NewConstructor(append([]basculehttp.COption{
		basculehttp.WithParseURLFunc(basculehttp.CreateRemovePrefixURLFunc("/api/"+prevAPIVersion+"/", basculehttp.DefaultParseURLFunc)),
		basculehttp.WithCErrorHTTPResponseFunc(basculehttp.LegacyOnErrorHTTPResponse),
	}, options...)...)
	bearerRules := bascule.Validators{
		bchecks.NonEmptyPrincipal(),
		bchecks.NonEmptyType(),
		bchecks.ValidType([]string{"jwt"}),
		requirePartnersJWTClaim,
	}

	// only add capability check if the configuration is set
	var capabilityCheck CapabilityConfig
	v.UnmarshalKey("capabilityCheck", &capabilityCheck)
	if capabilityCheck.Type == enforceCheck || capabilityCheck.Type == "monitor" {
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
		bearerRules = append(bearerRules, m.CreateValidator(capabilityCheck.Type == enforceCheck))
	}

	authEnforcer := basculehttp.NewEnforcer(
		basculehttp.WithELogger(getLogger),
		basculehttp.WithRules("Basic", bascule.Validators{
			bchecks.AllowAll(),
		}),
		basculehttp.WithRules("Bearer", bearerRules),
		basculehttp.WithEErrorResponseFunc(listener.OnErrorResponse),
	)

	authChain := alice.New(setLogger(logger), authConstructor, authEnforcer, basculehttp.NewListenerDecorator(listener))
	authChainLegacy := alice.New(setLogger(logger), authConstructorLegacy, authEnforcer, basculehttp.NewListenerDecorator(listener))

	versionCompatibleAuth := alice.New(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(r http.ResponseWriter, req *http.Request) {
			vars := mux.Vars(req)
			if vars != nil {
				if vars["version"] == prevAPIVersion {
					authChainLegacy.Then(next).ServeHTTP(r, req)
					return
				}
			}
			authChain.Then(next).ServeHTTP(r, req)
		})
	})
	return versionCompatibleAuth, nil
}

// createEndpoints examines the configuration and produces an appropriate fanout.Endpoints, either using the configured
// endpoints or service discovery.
// nolint:govet
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

	return nil, fmt.Errorf("unable to create endpoints")
}

func NewPrimaryHandler(logger log.Logger, v *viper.Viper, registry xmetrics.Registry, e service.Environment, tracing candlelight.Tracing) (http.Handler, error) {
	var cfg fanout.Configuration
	if err := v.UnmarshalKey("fanout", &cfg); err != nil {
		return nil, err
	}
	fanoutPrefix := v.GetString("fanout.pathPrefix")
	logging.Error(logger).Log(logging.MessageKey(), "creating primary handler")
	cfg.Tracing = tracing
	// nolint:govet
	endpoints, err := createEndpoints(logger, cfg, registry, e)
	if err != nil {
		return nil, err
	}

	authChain, err := authChain(v, logger, registry)
	if err != nil {
		return nil, err
	}

	var (
		// nolint:govet,bodyclose
		transactor = fanout.NewTransactor(cfg)
		options    = []fanout.Option{
			fanout.WithTransactor(transactor),
			fanout.WithErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("X-Midt-Error", err.Error())
				// nolint:errorlint
				if headerer, ok := err.(gokithttp.Headerer); ok {
					for k, values := range headerer.Headers() {
						for _, v := range values {
							w.Header().Add(k, v)
						}
					}
				}
				code := http.StatusInternalServerError
				// nolint:errorlint
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

				// nolint:errorlint
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

	router := mux.NewRouter()
	// if we want to support the previous API version, then include it in the
	// api base.
	urlPrefix := fmt.Sprintf("/%s", apiBase)
	if v.GetBool("previousVersionSupport") {
		urlPrefix = fmt.Sprintf("/%s", apiBaseDualVersion)
	}
	sendSubrouter := router.Path(fmt.Sprintf("%s/device", urlPrefix)).Methods("POST", "PUT").Subrouter()

	otelMuxOptions := []otelmux.Option{
		otelmux.WithPropagators(tracing.Propagator()),
		otelmux.WithTracerProvider(tracing.TracerProvider()),
	}
	router.Use(otelmux.Middleware("mainSpan", otelMuxOptions...), candlelight.EchoFirstTraceNodeInfo(tracing.Propagator()))

	router.NotFoundHandler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		xhttp.WriteError(response, http.StatusBadRequest, "Invalid endpoint")
	})
	// nolint:govet
	fanoutChain := fanout.NewChain(cfg)

	HTTPFanoutHandler := fanoutChain.Then(
		fanout.New(
			endpoints,
			append(
				options,
				fanout.WithFanoutBefore(
					func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
						var m wrp.Message

						if m, ok := wrpcontext.Get[wrp.Message](ctx); !ok {
							f, err := wrphttp.DetermineFormat(wrp.JSON, original.Header, "Content-Type")
							if err != nil {
								return nil, err
							}

							err = wrp.NewDecoderBytes(body, f).Decode(&m)
							if err != nil {
								return nil, err
							}

						}

						return context.WithValue(ctx, ContextKeyWRP, m), nil
					},
					fanout.ForwardHeaders("Content-Type", "X-Webpa-Device-Name"),
					fanout.UsePath(fmt.Sprintf("%s/device/send", fanoutPrefix)),
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
					func(ctx context.Context, response http.ResponseWriter, result fanout.Result) context.Context {
						var satClientID = "N/A"
						reqContextValues, ok := handler.FromContext(result.Request.Context())
						if ok {
							satClientID = reqContextValues.SatClientID
						}

						wrpFromCtx, ok := ctx.Value("wrp").(wrp.Message)
						if ok {
							logging.Info(logger).Log(
								logging.MessageKey(), "Bookkeeping response",
								"messageType", wrpFromCtx.Type,
								"destination", wrpFromCtx.Destination,
								"source", wrpFromCtx.Source,
								"transactionUUID", wrpFromCtx.TransactionUUID,
								"status", wrpFromCtx.Status,
								"partnerIDs", wrpFromCtx.PartnerIDs,
								"satClientID", satClientID,
							)
						} else {
							logging.Error(logger).Log(logging.MessageKey(), "no wrp found")
							logging.Info(logger).Log(
								logging.MessageKey(), "Bookkeeping response",
								"satClientID", satClientID,
							)
						}
						return ctx
					},
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

	if wrpCheckConfig.Type == enforceCheck || wrpCheckConfig.Type == "monitor" {
		WRPFanoutHandler = newWRPFanoutHandlerWithPIDCheck(
			HTTPFanoutHandler,
			&wrpPartnersAccess{
				strict:                  wrpCheckConfig.Type == enforceCheck,
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
		fmt.Sprintf("%s/device/{%s}/stat", urlPrefix, deviceID),
		authChain.Extend(fanoutChain.Extend(validateDeviceID())).Then(
			fanout.New(
				endpoints,
				append(
					options,
					fanout.WithFanoutBefore(
						// required for petasos
						fanout.ForwardVariableAsHeader(deviceID, "X-Webpa-Device-Name"),
						// required for consul fanout
						func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
							// strip the initial path and provide the configured one instead.
							urlToUse := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(original.URL.Path, "/"), apiBase), prevAPIBase)
							fanout.URL.Path = fmt.Sprintf("%s%s", fanoutPrefix, urlToUse)
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

// validateDeviceID checks the device ID in the URL to make sure it is good before fanout.
func validateDeviceID() alice.Chain {
	return alice.New(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)
			_, err := device.ParseID(vars[deviceID])
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)

				fmt.Fprintf(
					w,
					`{"code": %d, "message": "%s"}`,
					http.StatusBadRequest,
					fmt.Sprintf("failed to extract device ID: %s", err),
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
}
