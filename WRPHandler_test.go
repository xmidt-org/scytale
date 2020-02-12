package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFanoutHandler(t *testing.T) {
	assert := assert.New(t)

	assert.Panics(func() {
		NewWRPFanoutHandler(nil)
	})

	assert.NotPanics(func() {
		assert.NotNil(NewWRPFanoutHandler(http.NotFoundHandler()))
	})
}

func TestNewWRPFanoutHandlerWithPIDCheck(t *testing.T) {}
