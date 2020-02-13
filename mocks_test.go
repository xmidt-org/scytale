package main

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/xmidt-org/wrp-go/v2"
)

type mockWRPAccessAuthority struct {
	mock.Mock
}

func (m *mockWRPAccessAuthority) authorizeWRP(ctx context.Context, message *wrp.Message) (bool, error) {
	arguments := m.Called(ctx, message)
	return arguments.Bool(0), arguments.Error(1)
}
