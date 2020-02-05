package main

//TODO: this should probably go in wrp-go or a more fitting package
//since it will likely be used in talaria as well
import (
	"context"

	"github.com/xmidt-org/wrp-go/wrp/wrphttp"
)

//TODO: this file fits somewhere in xmidt-org/wrp-go better
type entityKey struct{}

func WithEntity(ctx context.Context, wrp *wrphttp.Entity) context.Context {
	return context.WithValue(ctx, entityKey{}, wrp)
}

func FromContext(ctx context.Context) (*wrphttp.Entity, bool) {
	message, ok := ctx.Value(entityKey{}).(*wrphttp.Entity)
	return message, ok
}

// // FromContext gets the Authentication from the context provided.
// func FromContext(ctx context.Context) (Authentication, bool) {
// 	auth, ok := ctx.Value(authenticationKey{}).(Authentication)
// 	return auth, ok
// }
