FROM docker.io/library/golang:1.15-alpine as builder

MAINTAINER Jack Murdock <jack_murdock@comcast.com>

WORKDIR /src

ARG VERSION
ARG GITCOMMIT
ARG BUILDTIME


RUN apk add --no-cache --no-progress \
    ca-certificates \
    make \
    git \
    openssh \
    gcc \
    libc-dev \
    upx

RUN go get github.com/geofffranks/spruce/cmd/spruce && chmod +x /go/bin/spruce
COPY . .
RUN make test release

FROM alpine:3.12.1

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/scytale /src/scytale.yaml /src/deploy/packaging/entrypoint.sh /go/bin/spruce /src/Dockerfile /src/NOTICE /src/LICENSE /src/CHANGELOG.md /
COPY --from=builder /src/deploy/packaging/scytale_spruce.yaml /tmp/scytale_spruce.yaml

RUN mkdir /etc/scytale/ && touch /etc/scytale/scytale.yaml && chmod 666 /etc/scytale/scytale.yaml

USER nobody

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 6300
EXPOSE 6301
EXPOSE 6302
EXPOSE 6303

CMD ["/scytale"]