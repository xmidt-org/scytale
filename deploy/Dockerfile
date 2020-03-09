FROM docker.io/library/golang:1.14-alpine as builder

MAINTAINER Jack Murdock <jack_murdock@comcast.com>

WORKDIR /go/src/github.com/xmidt-org/scytale

ARG VERSION=unknown
ARG GITCOMMIT=unknown
ARG BUILDTIME=unknown

ADD https://github.com/geofffranks/spruce/releases/download/v1.25.2/spruce-linux-amd64 /usr/local/bin/spruce
RUN chmod +x /usr/local/bin/spruce

RUN apk add --no-cache --no-progress \
    ca-certificates \
    make \
    git \
    openssh \
    gcc \
    libc-dev \
    upx

COPY . .
RUN make build

FROM alpine:latest

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/github.com/xmidt-org/scytale/scytale.yaml /scytale.yaml
COPY --from=builder /go/src/github.com/xmidt-org/scytale/scytale /scytale
COPY --from=builder /go/src/github.com/xmidt-org/scytale/deploy/Dockerfile /go/src/github.com/xmidt-org/scytale/NOTICE /go/src/github.com/xmidt-org/scytale/LICENSE /go/src/github.com/xmidt-org/scytale/CHANGELOG.md /
COPY --from=builder /go/src/github.com/xmidt-org/scytale/deploy/packaging/entrypoint.sh /entrypoint.sh
COPY --from=builder /go/src/github.com/xmidt-org/scytale/deploy/packaging/scytale_spruce.yaml /tmp/scytale_spruce.yaml
COPY --from=builder /usr/local/bin/spruce /spruce

RUN mkdir /etc/scytale/ && touch /etc/scytale/scytale.yaml && chmod 666 /etc/scytale/scytale.yaml

USER nobody

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 6300
EXPOSE 6301
EXPOSE 6302
EXPOSE 6303

CMD ["/scytale"]