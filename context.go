// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import "context"

type contextKey string

const (
	ContextKeyWRP contextKey = "wrp"
)

type contextValuesKey struct{}

// ContextValues contains the values shared under the satClientIDKey from this package
type ContextValues struct {
	SatClientID string
	Method      string
	Path        string
	PartnerIDs  []string
	Trust       string
}

// NewContextWithValue returns a context with the specified context values
func NewContextWithValue(ctx context.Context, vals *ContextValues) context.Context {
	return context.WithValue(ctx, contextValuesKey{}, vals)
}

// FromContext returns ContextValues type (if any) along with a boolean that indicates whether
// the returned value is of the required/correct type for this package.
func FromContext(ctx context.Context) (*ContextValues, bool) {
	vals, ofType := ctx.Value(contextValuesKey{}).(*ContextValues)
	return vals, ofType
}
