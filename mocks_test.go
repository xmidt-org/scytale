package main

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/wrp-go/v3"
	"github.com/xmidt-org/wrp-go/v3/wrphttp"
)

type mockWRPAccessAuthority struct {
	mock.Mock
}

func (m *mockWRPAccessAuthority) authorizeWRP(ctx context.Context, message *wrp.Message) (bool, error) {
	arguments := m.Called(ctx, message)
	return arguments.Bool(0), arguments.Error(1)
}

type testWRPResponseWriter struct {
	http.ResponseWriter
}

func (t *testWRPResponseWriter) WriteWRP(i *wrphttp.Entity) (int, error) {
	return 0, nil
}

func (t *testWRPResponseWriter) WriteWRPBytes(_ wrp.Format, _ []byte) (int, error) {
	return 0, nil
}

func (t *testWRPResponseWriter) WRPFormat() wrp.Format {
	return wrp.Msgpack
}

func newTestWRPResponseWriter(w *httptest.ResponseRecorder) *testWRPResponseWriter {
	return &testWRPResponseWriter{
		ResponseWriter: w,
	}
}
