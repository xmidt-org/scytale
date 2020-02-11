package main

import (
	"net/http"

	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/xmidt-org/webpa-common/xhttp"
	"github.com/xmidt-org/wrp-go/wrp"
	"github.com/xmidt-org/wrp-go/wrp/wrphttp"
)

func NewWRPFanoutHandler(fanoutHandler http.Handler) wrphttp.HandlerFunc {
	if fanoutHandler == nil {
		panic("fanoutHandler must be defined")
	}
	return func(w wrphttp.ResponseWriter, r *wrphttp.Request) {
		//TODO: uncomment once wrp-go/v2 release is out
		//fanoutPrep(r.Original, r.Entity.Source, r.Entity)
		fanoutPrep(r.Original, []byte("stub"), r.Entity)
		fanoutHandler.ServeHTTP(w, r.Original)
	}
}

func NewWRPFanoutHandlerWithPIDCheck(fanoutHandler http.Handler, p partnersAuthority) wrphttp.HandlerFunc {
	if fanoutHandler == nil || p == nil {
		panic("fanoutHandler and partnersAuthority arguments must be defined")
	}
	encodeError := gokithttp.DefaultErrorEncoder

	return func(w wrphttp.ResponseWriter, r *wrphttp.Request) {
		var (
			ctx    = r.Context()
			entity = r.Entity
			fanout = r.Original
			//TODO: uncomment once wrp-go/v2 release is out
			// fanoutBody = r.entity.source
			fanoutBody = []byte("stub")
		)

		modified, err := p.authorizeWRP(ctx, &entity.Message)

		if err != nil {
			encodeError(ctx, err, w)
			return
		}

		if modified {
			if err := wrp.NewEncoderBytes(&fanoutBody, entity.Format).Encode(&entity.Message); err != nil {
				encodeError(ctx, err, w)
				return
			}
		}

		fanoutPrep(fanout, fanoutBody, entity)
		fanoutHandler.ServeHTTP(w, fanout)
	}
}

func fanoutPrep(fanout *http.Request, fanoutBody []byte, entity *wrphttp.Entity) {
	fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(fanoutBody)
	fanout.ContentLength = int64(len(fanoutBody))
	fanout.Header.Set("Content-Type", entity.Format.ContentType())
	fanout.Header.Set("X-Webpa-Device-Name", entity.Message.Destination)
}
