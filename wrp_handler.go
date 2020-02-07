package main

import (
	"net/http"

	gokithttp "github.com/go-kit/kit/transport/http"
	"github.com/xmidt-org/webpa-common/xhttp"
	"github.com/xmidt-org/wrp-go/wrp"
	"github.com/xmidt-org/wrp-go/wrp/wrphttp"
)

func NewWRPFanoutHandler(fanoutHandler http.Handler, p *partnersValidator) wrphttp.HandlerFunc {
	encodeError := gokithttp.DefaultErrorEncoder

	return func(w wrphttp.ResponseWriter, r *wrphttp.Request) {
		var (
			ctx        = r.Context()
			entity     = r.Entity
			fanout     = r.Original
			fanoutBody = r.Entity.Original
		)

		//authorizeWRP returns an error with a status code when necessary
		err, modified := p.authorizeWRP(ctx, &entity.Message)

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

		fanout.Body, fanout.GetBody = xhttp.NewRewindBytes(fanoutBody)
		fanout.ContentLength = int64(len(fanoutBody))
		fanout.Header.Set("Content-Type", entity.Format.ContentType())
		fanout.Header.Set("X-Webpa-Device-Name", entity.Message.Destination)

		fanoutHandler.ServeHTTP(w, fanout)
	}
}
