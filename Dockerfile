FROM docker.io/library/golang:1.19-alpine as builder

WORKDIR /src

ARG VERSION
ARG GITCOMMIT
ARG BUILDTIME

RUN apk add --no-cache --no-progress \
    ca-certificates \
    make \
    curl \
    git \
    openssh \
    gcc \
    libc-dev \
    upx

# If arch is arm64 or aarch64, use arm64 download, else, do the amd64 default
# Download spruce here to eliminate the need for curl in the final image
RUN mkdir -p /go/bin && \
    uname -m && \
    if [ $(uname -m) = "aarch64" ] || [ $(uname -m) = "arm64" ]; then export PROC_ARCH="arm64"; else export PROC_ARCH="amd64"; fi && \
    curl -L -o /go/bin/spruce https://github.com/geofffranks/spruce/releases/download/v1.29.0/spruce-linux-"${PROC_ARCH}" && \
    chmod +x /go/bin/spruce

COPY . .

RUN make test release

##########################
# Build the final image.
##########################

FROM alpine:latest

# Copy over the standard things you'd expect.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt  /etc/ssl/certs/
COPY --from=builder /src/scytale                        /
COPY --from=builder /src/.release/docker/entrypoint.sh  /

# Copy over spruce and the spruce template file used to make the actual configuration file.
COPY --from=builder /src/.release/docker/scytale_spruce.yaml  /tmp/scytale_spruce.yaml
COPY --from=builder /go/bin/spruce                            /bin/

# Include compliance details about the container and what it contains.
COPY --from=builder /src/Dockerfile \
                    /src/NOTICE \
                    /src/LICENSE \
                    /src/CHANGELOG.md   /

# Make the location for the configuration file that will be used.
RUN     mkdir /etc/scytale/ \
    &&  touch /etc/scytale/scytale.yaml \
    &&  chmod 666 /etc/scytale/scytale.yaml

USER nobody

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 6300
EXPOSE 6301
EXPOSE 6302
EXPOSE 6303

CMD ["/scytale"]
