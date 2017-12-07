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
	"fmt"
	"net/http"

	"github.com/Comcast/webpa-common/middleware/fanout/fanouthttp"
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

	var (
		subrouter  = r.Path(fmt.Sprintf("%s/%s/device", baseURI, version)).Methods("POST", "PUT").Subrouter()
		timeLayout = ""
	)

	subrouter.Headers(wrphttp.MessageTypeHeader, "").Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestHeaders(fanoutOptions.Logger),
			wrphttp.ServerEncodeResponseHeaders(timeLayout),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(timeLayout),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.JSON.ContentType()).Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(fanoutOptions.Logger, fanoutOptions.NewDecoderPool(wrp.JSON)),
			wrphttp.ServerEncodeResponseBody(timeLayout, fanoutOptions.NewEncoderPool(wrp.JSON)),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(timeLayout),
			),
		),
	)

	subrouter.Headers("Content-Type", wrp.Msgpack.ContentType()).Handler(
		gokithttp.NewServer(
			fanoutEndpoint,
			wrphttp.ServerDecodeRequestBody(fanoutOptions.Logger, fanoutOptions.NewDecoderPool(wrp.Msgpack)),
			wrphttp.ServerEncodeResponseBody(timeLayout, fanoutOptions.NewEncoderPool(wrp.Msgpack)),
			gokithttp.ServerErrorEncoder(
				fanouthttp.ServerErrorEncoder(timeLayout),
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

	options.Logger = logger
	return nil
}

func NewPrimaryHandler(logger log.Logger, v *viper.Viper) (http.Handler, error) {
	router := mux.NewRouter()
	err := addDeviceSendRoutes(logger, router, v)
	if err == nil {
		err = addFanoutRoutes(logger, router, v)
	}

	return router, err
}
