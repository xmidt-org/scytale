package main

import (
	"net/http"

	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/xmidt-org/webpa-common/xhttp"
	"github.com/xmidt-org/wrp-go/v2"
	"github.com/xmidt-org/wrp-go/v2/wrphttp"
)

type nonWRPResponseWriter struct {
	http.ResponseWriter
}

func (o *nonWRPResponseWriter) WriteWRP(interface{}) (int, error) {
	return 0, nil
}

//nonWRPResponseWriterFactory helps configure the WRP handler to fulfill scytale's use case of only consuming
//WRP requests but not produce WRP responses
func nonWRPResponseWriterFactory(w http.ResponseWriter, _ *wrphttp.Request) (wrphttp.ResponseWriter, error) {
	return &nonWRPResponseWriter{
		ResponseWriter: w,
	}, nil
}

func newWRPFanoutHandler(fanoutHandler http.Handler) wrphttp.HandlerFunc {
	if fanoutHandler == nil {
		panic("fanoutHandler must be defined")
	}
	return func(w wrphttp.ResponseWriter, r *wrphttp.Request) {
		fanoutPrep(r.Original, r.Entity.Bytes, r.Entity)
		fanoutHandler.ServeHTTP(w, r.Original)
	}
}

func newWRPFanoutHandlerWithPIDCheck(fanoutHandler http.Handler, p wrpAccessAuthority) wrphttp.HandlerFunc {
	if fanoutHandler == nil || p == nil {
		panic("fanoutHandler and partnersAuthority arguments must be defined")
	}

	encodeError := gokithttp.DefaultErrorEncoder

	return func(w wrphttp.ResponseWriter, r *wrphttp.Request) {
		var (
			ctx        = r.Context()
			entity     = r.Entity
			fanout     = r.Original
			fanoutBody = r.Entity.Bytes
		)

		modified, err := p.authorizeWRP(ctx, &entity.Message)

		if err != nil {
			encodeError(ctx, err, w)
			return
		}

		if modified {
			if err := wrp.NewEncoderBytes(&fanoutBody, entity.Format).Encode(entity.Message); err != nil {
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
