FROM golang:alpine as builder
MAINTAINER Jack Murdock <jack_murdock@comcast.com>

# build the binary
WORKDIR /go/src
COPY src/ /go/src/

RUN go build -o scytale_linux_amd64 scytale

EXPOSE 6300 6301 6302
RUN mkdir -p /etc/scytale
VOLUME /etc/scytale

# the actual image
FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN mkdir -p /etc/scytale
VOLUME /etc/scytale
WORKDIR /root/
COPY --from=builder /go/src/scytale_linux_amd64 .
ENTRYPOINT ["./scytale_linux_amd64"]
