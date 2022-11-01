package main

import (
	"net/http"
	"strings"

	"github.com/xmidt-org/candlelight"
	"github.com/xmidt-org/sallust"
	"go.uber.org/zap"
)

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

func setLogger(logger *zap.Logger) func(delegate http.Handler) http.Handler {
	return func(delegate http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				kvs := []zap.Field{zap.Any("requestHeaders", sanitizeHeaders(r.Header)), zap.String("requestURL", r.URL.EscapedPath()), zap.String("method", r.Method)}
				traceID, spanID, ok := candlelight.ExtractTraceInfo(r.Context())
				if ok {
					kvs = append(kvs, zap.String(candlelight.SpanIDLogKeyName, spanID), zap.String(candlelight.TraceIdLogKeyName, traceID))
				}

				ctx := r.WithContext(sallust.With(r.Context(), logger.With(kvs...)))
				delegate.ServeHTTP(w, ctx)
			})
	}
}
