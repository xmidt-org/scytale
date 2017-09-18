package main

import (
	"fmt"
	"net/http"

	"github.com/Comcast/webpa-common/wrp"
	"github.com/Comcast/webpa-common/wrp/wrphttp"
	"github.com/go-kit/kit/log"
	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

const (
	baseURI = "/api"
	version = "v2"
)

func NewPrimaryHandler(logger log.Logger, v *viper.Viper) (http.Handler, error) {
	fanoutOptions := new(wrphttp.FanoutOptions)
	if err := v.UnmarshalKey("fanout", fanoutOptions); err != nil {
		return nil, err
	}

	fanoutOptions.Logger = logger
	fanoutEndpoint, err := wrphttp.NewFanoutEndpoint(fanoutOptions)
	if err != nil {
		return nil, err
	}

	var (
		router     = mux.NewRouter()
		subrouter  = router.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Subrouter()
		timeLayout = ""
	)

	subrouter.Headers(wrphttp.MessageTypeHeader, "").Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestHeaders(logger),
			wrphttp.ServerEncodeResponseHeaders(timeLayout),
			gokithttp.ServerErrorEncoder(
				wrphttp.ServerErrorEncoder(timeLayout),
			),
		),
	)

	subrouter.Headers("Content-Type", "application/json").Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(logger, fanoutOptions.NewDecoderPool(wrp.JSON)),
			wrphttp.ServerEncodeResponseBody(timeLayout, fanoutOptions.NewEncoderPool(wrp.JSON)),
			gokithttp.ServerErrorEncoder(
				wrphttp.ServerErrorEncoder(timeLayout),
			),
		),
	)

	subrouter.Headers("Content-Type", "application/msgpack").Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(logger, fanoutOptions.NewDecoderPool(wrp.Msgpack)),
			wrphttp.ServerEncodeResponseBody(timeLayout, fanoutOptions.NewEncoderPool(wrp.Msgpack)),
			gokithttp.ServerErrorEncoder(
				wrphttp.ServerErrorEncoder(timeLayout),
			),
		),
	)

	return router, nil
}
