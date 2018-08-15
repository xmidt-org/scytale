package main

import (
	"github.com/Comcast/webpa-common/wrp"
	"github.com/go-kit/kit/log"

	"github.com/Comcast/webpa-common/logging"
	"net/http"
	"github.com/Comcast/webpa-common/secure/handler"
)

type Bookkeeper struct {
	Message *wrp.Message
	Request *http.Request
}

func NewBookkeeper(msg *wrp.Message, request *http.Request) *Bookkeeper {
	return &Bookkeeper{
		Message: msg,
		Request: request,
	}
}

func (book *Bookkeeper) Log(logger log.Logger, statusCode int, otherkeyvals ...interface{}) {
	var satClientID = "N/A"

	// retrieve satClientID from request context
	if reqContextValues, ok := handler.FromContext(book.Request.Context()); ok {
		satClientID = reqContextValues.SatClientID
	}

	keyvals := []interface{}{logging.MessageKey(), "Bookkeeping response",
		"method", book.Request.Method,
		"requestURLPath", book.Request.URL.Path,
		"responseCode", statusCode,
		"satClientID", satClientID,
	}

	if book.Message != nil {
		if len(book.Message.PartnerIDs) > 0 {
			keyvals = append(keyvals, "wrp.partner_ids", book.Message.PartnerIDs)
		}
		if book.Message.TransactionUUID != "" {
			keyvals = append(keyvals, "wrp.transaction_uuid", book.Message.TransactionUUID)
		}
		if book.Message.Destination != "" {
			keyvals = append(keyvals, "wrp.dest", book.Message.Destination)
		}
		if book.Message.Source != "" {
			keyvals = append(keyvals, "wrp.source", book.Message.Source)
		}
		if book.Message.Type != 0 {
			keyvals = append(keyvals, "wrp.msg_type", book.Message.Type)
		}
		if book.Message.Status != nil {
			keyvals = append(keyvals, "wrp.status", *book.Message.Status)
		}
	}

	keyvals = append(keyvals, otherkeyvals...)

	logger.Log(keyvals...)
}
