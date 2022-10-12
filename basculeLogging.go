package main

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/xmidt-org/candlelight"
)

type contextKey uint32

const loggerKey contextKey = 1

// LoggerFunc is a strategy for adding key/value pairs (possibly) based on an HTTP request.
// Functions of this type must append key/value pairs to the supplied slice and then return
// the new slice.
type LoggerFunc func([]interface{}, *http.Request) []interface{}

func sanitizeHeaders(headers http.Header) (filtered http.Header) {
	filtered = headers.Clone()
	if authHeader := filtered.Get("Authorization"); authHeader != "" {
		filtered.Del("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			filtered.Set("Authorization-Type", parts[0])
		}
	}
	return
}

func setLogger(logger log.Logger, lf ...LoggerFunc) func(delegate http.Handler) http.Handler {

	if logger == nil {
		panic("The base Logger cannot be nil")
	}

	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				kvs := []interface{}{"requestHeaders", sanitizeHeaders(r.Header), "requestURL", r.URL.EscapedPath(), "method", r.Method}
				for _, f := range lf {
					if f != nil {
						kvs = f(kvs, r)
					}
				}
				kvs, _ = candlelight.AppendTraceInfo(r.Context(), kvs)
				ctx := r.WithContext(context.WithValue(r.Context(), loggerKey, log.With(logger, kvs...)))
				delegate.ServeHTTP(w, ctx)
			})
	}
}

func getLogger(ctx context.Context) log.Logger {
	logger, ok := ctx.Value(loggerKey).(log.Logger)
	if !ok {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	}

	return log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
}
