package main

//TODO: this code can be re-used in talaria. Should be put it in wrp-go/http?
func WRPEntityDecorator(h http.Handler) http.Handler {
	decodeEntity := wrphttp.DecodeEntity(wrp.Msgpack)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx    = r.Context()
			entity *wrphttp.Entity
		)

		body, err := ioutil.ReadAll(r.Body)

		if err != nil {
			xhttp.WriteErrorf(w, http.StatusInternalServerError, "Could not read request body. %v", err)
			return
		}

		r.Body, r.GetBody = xhttp.NewRewindBytes(body)

		if r.Header.Get(wrphttp.MessageTypeHeader) != "" {
			entity, err = wrphttp.DecodeRequestHeaders(ctx, r)
			if err != nil {
				xhttp.WriteErrorf(w, http.StatusBadRequest, "Could not decode wrp message from headers. %v", err)
				return
			}
		} else {
			entity, err = decodeEntity(ctx, r)

			if err != nil {
				xhttp.WriteErrorf(w, http.StatusBadRequest, "Could not decode wrp message from body. %v", err)
				return
			}
		}

		r.Body, r.GetBody = xhttp.NewRewindBytes(body)

		h.ServeHTTP(w, r.WithContext(WithEntity(ctx, entity)))
	})
}
