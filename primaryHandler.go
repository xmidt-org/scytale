// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/bascule/basculehttp/basculecaps"
	"github.com/xmidt-org/bascule/basculejwt"
	"github.com/xmidt-org/candlelight"
	"github.com/xmidt-org/touchstone"
	"github.com/xmidt-org/webpa-common/v2/device"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.uber.org/zap"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/service"
	"github.com/xmidt-org/webpa-common/v2/service/monitor"
	"github.com/xmidt-org/webpa-common/v2/service/multiaccessor"
	"github.com/xmidt-org/webpa-common/v2/service/servicecfg"
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

	basicAuthConfigKey    = "authHeader"
	jwtAuthConfigKey      = "jwtValidator"
	jwtCapabilityCheckKey = "capabilityCheck"
	wrpCheckConfigKey     = "WRPCheck"
	wrpValidatorConfigKey = "wrpValidators"

	deviceID = "deviceID"

	enforceCheck = "enforce"
)

// Default values
const (
	UnknownPartner = "unknown"
)

var (
	errNoDeviceName = errors.New("no device name")
)

func authChain(v *viper.Viper, logger *zap.Logger, registry xmetrics.Registry, tf *touchstone.Factory) (alice.Chain, error) {
	if registry == nil {
		return alice.Chain{}, errors.New("nil registry")
	}

	basicAllowed := make(map[string]string)
	basicAuth := v.GetStringSlice(basicAuthConfigKey)
	for _, a := range basicAuth {
		decoded, err := base64.StdEncoding.DecodeString(a)
		if err != nil {
			logger.Info("failed to decode auth header", zap.Any("authHeader", a))
			logger.Error(err.Error())
			continue
		}

		i := bytes.IndexByte(decoded, ':')
		logger.Debug("decoded string", zap.Any("string", decoded), zap.Int("i", i))
		if i > 0 {
			basicAllowed[string(decoded[:i])] = string(decoded[i+1:])
		}
	}
	logger.Debug("Created list of allowed basic auths", zap.Any("allowed", basicAllowed), zap.Any("config", basicAuth))

	var authParserOptions []basculehttp.AuthorizationParserOption
	if len(basicAllowed) > 0 {
		authParserOptions = append(authParserOptions, basculehttp.WithBasic())
	}

	approverOpts := []basculecaps.ApproverOption{}
	authorizerEventListeners := []bascule.Listener[bascule.AuthorizeEvent[*http.Request]]{}
	authenticatorEventListeners := []bascule.Listener[bascule.AuthenticateEvent[*http.Request]]{}
	if v.IsSet(jwtAuthConfigKey) {
		var jwtVal JWTValidator
		if err := v.UnmarshalKey(jwtAuthConfigKey, &jwtVal); err != nil {
			return alice.Chain{}, fmt.Errorf("failed to parse jwt configuration: %v", err)
		}

		if jwtVal.Config.isZero() {
			return alice.Chain{}, fmt.Errorf("jwt configuration was set, `%s.Config` can't be empty", jwtAuthConfigKey)
		}

		ks, err := jwtVal.Config.Build()
		if err != nil {
			return alice.Chain{}, fmt.Errorf("error setting up JWT key resolver: %v", err)
		}

		jwtp, err := basculejwt.NewTokenParser(
			jwt.WithKeySet(ks, jws.WithInferAlgorithmFromKey(true)))
		if err != nil {
			return alice.Chain{}, fmt.Errorf("error setting up JWT parser: %v", err)
		}

		authParserOptions = append(authParserOptions, basculehttp.WithScheme(basculehttp.SchemeBearer, jwtp))

		var capabilityCheck CapabilityConfig
		if err := v.UnmarshalKey(jwtCapabilityCheckKey, &capabilityCheck); err != nil {
			return alice.Chain{}, fmt.Errorf("failed to parse jwt configuration `%s`: %v", jwtCapabilityCheckKey, err)
		}

		v.UnmarshalKey("capabilityCheck", &capabilityCheck)
		approverOpts = append(approverOpts,
			basculecaps.WithPrefixes(capabilityCheck.Capabilities...),
			basculecaps.WithAllMethod(capabilityCheck.AcceptAllMethod))

		endpointBuckets := make([]*regexp.Regexp, 0, len(capabilityCheck.EndpointBuckets))
		for _, pattern := range capabilityCheck.EndpointBuckets {
			re, err := regexp.Compile(pattern)
			if err != nil {
				logger.Error("failed to compile endpoint bucket regex", zap.String("regex", pattern), zap.Error(err))
				continue
			}

			endpointBuckets = append(endpointBuckets, re)
		}

		authorizerEventListeners = append(authorizerEventListeners,
			authorizerEvent{
				l:         logger,
				counter:   registry.NewCounterVec(AuthCapabilityCheckCount),
				endpoints: endpointBuckets})
		authenticatorEventListeners = append(authenticatorEventListeners,
			authenticatorEvent{
				l:          logger,
				counter:    registry.NewCounterVec(AuthCapabilityCheckCount),
				parserOpts: []jwt.ParseOption{jwt.WithKeySet(ks, jws.WithInferAlgorithmFromKey(true))}})
	}

	tp, err := basculehttp.NewAuthorizationParser(authParserOptions...)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error setting up authorization parser: %v", err)
	}

	approver, err := basculecaps.NewApprover(approverOpts...)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error setting up JWT capability checks: %v", err)
	}

	auth, err := basculehttp.NewMiddleware(
		basculehttp.UseAuthenticator(basculehttp.NewAuthenticator(
			bascule.WithTokenParsers(tp),
			bascule.WithValidators(
				basculehttp.AsValidator(authSchemeValidator),
				basculehttp.AsValidator(authPrincipalValidator)),
			bascule.WithAuthenticateListeners(authenticatorEventListeners...),
		)),
		basculehttp.UseAuthorizer(basculehttp.NewAuthorizer(
			bascule.WithApprovers(approver),
			bascule.WithApproverFuncs(jwtClaimPartnerIDsValidator),
			bascule.WithApproverFuncs(basicPasswordValidator(basicAllowed)),
			bascule.WithAuthorizeListeners(authorizerEventListeners...),
		)),
	)

	if err != nil {
		return alice.Chain{}, fmt.Errorf("failed to create auth middleware: %v", err)
	}

	return alice.New(setLogger(logger), auth.Then), nil
}

// createEndpoints examines the configuration and produces an appropriate fanout.Endpoints, either using the configured
// endpoints or service discovery.
// nolint:govet
func createEndpoints(logger *zap.Logger, cfg *fanout.Configuration, registry xmetrics.Registry, e service.Environment, b multiaccessor.Builder, vnodeCount int) (fanout.Endpoints, error) {
	if len(cfg.Endpoints) > 0 {
		logger.Info("using configured endpoints for fanout", zap.Any("endpoints", cfg.Endpoints))
		return fanout.ParseURLs(cfg.Endpoints...)
	} else if e != nil {
		logger.Info("using service discovery for fanout")
		endpoints := fanout.NewServiceEndpoints(
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

func NewPrimaryHandler(logger *zap.Logger, v *viper.Viper, registry xmetrics.Registry, e service.Environment, tracing candlelight.Tracing) (http.Handler, error) {
	var cfg fanout.Configuration
	if err := v.UnmarshalKey("fanout", &cfg); err != nil {
		return nil, err
	}
	fanoutPrefix := v.GetString("fanout.pathPrefix")
	logger.Info("creating primary handler")
	cfg.Tracing = tracing

	var o servicecfg.Options
	if err := v.UnmarshalKey("service", &o); err != nil {
		return nil, err
	}

	var b multiaccessor.Builder
	if s, err := json.Marshal(v.Get("service")); err != nil {
		return nil, err
	} else if err := json.Unmarshal(s, &b); err != nil {
		return nil, err
	}

	endpoints, err := createEndpoints(logger, &cfg, registry, e, b, o.VnodeCount)
	if err != nil {
		return nil, err
	}

	promReg, ok := registry.(prometheus.Registerer)
	if !ok {
		return nil, errors.New("failed to get prometheus registerer")
	}

	var tsConfig touchstone.Config
	// Get touchstone & zap configurations
	v.UnmarshalKey("touchstone", &tsConfig)
	tf := touchstone.NewFactory(tsConfig, logger, promReg)
	authChain, err := authChain(v, logger, registry, tf)
	if err != nil {
		return nil, err
	}

	var (
		// nolint:govet,bodyclose
		transactor = fanout.NewTransactor(&cfg)
		options    = []fanout.Option{
			fanout.WithTransactor(transactor),
			fanout.WithErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("X-Xmidt-Error", err.Error())
				// nolint:errorlint
				if headerer, ok := err.(gokithttp.Headerer); ok {
					for k, values := range headerer.Headers() {
						// nolint: gosec
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

	valWRP, err := validateWRP(v, logger, tf)
	if err != nil {
		return nil, fmt.Errorf("failed to get wrp validators: %w", err)
	}

	router.Use(otelmux.Middleware("mainSpan", otelMuxOptions...), candlelight.EchoFirstTraceNodeInfo(tracing, true), valWRP)

	router.NotFoundHandler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		xhttp.WriteError(response, http.StatusBadRequest, "Invalid endpoint")
	})
	// nolint:govet
	fanoutChain := fanout.NewChain(&cfg)

	HTTPFanoutHandler := fanoutChain.Then(
		fanout.New(
			endpoints,
			append(
				options,
				fanout.WithFanoutBefore(
					func(ctx context.Context, original, fanout *http.Request, body []byte) (context.Context, error) {
						m, ok := wrpcontext.GetMessage(ctx)

						if !ok {
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
						reqContextValues, ok := FromContext(result.Request.Context())
						if ok {
							satClientID = reqContextValues.SatClientID
						}

						wrpFromCtx, ok := ctx.Value(ContextKeyWRP).(*wrp.Message)
						if ok {
							logger.Info("Bookkeping response",
								zap.Any("messageType", wrpFromCtx.Type),
								zap.String("destination", wrpFromCtx.Destination),
								zap.String("source", wrpFromCtx.Source),
								zap.String("transactionUUID", wrpFromCtx.TransactionUUID),
								zap.Any("status", wrpFromCtx.Status),
								zap.Strings("partnerIDS", wrpFromCtx.PartnerIDs),
								zap.String("satClientID", satClientID))

						} else {
							logger.Error("no wrp found")
							logger.Info("Bookkeeping response", zap.String("satClientID", satClientID))
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
				receivedWRPMessageCount: registry.NewCounter(ReceivedWRPMessageCount),
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

func validateWRP(v *viper.Viper, logger *zap.Logger, tf *touchstone.Factory) (func(http.Handler) http.Handler, error) {
	_ = tf

	if v.Get(wrpValidatorConfigKey) != nil {
		logger.Warn("wrpValidators are configured but ignored because the current wrp-go dependency does not provide validator middleware")
	}

	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			delegate.ServeHTTP(w, r)
		})
	}, nil
}
