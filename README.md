# scytale
(pronounced "skit-uh-​lee")

[![Build Status](https://github.com/xmidt-org/scytale/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/scytale/actions/workflows/ci.yml)
[![codecov.io](http://codecov.io/github/xmidt-org/scytale/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/scytale?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/scytale)](https://goreportcard.com/report/github.com/xmidt-org/scytale)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=xmidt-org_scytale&metric=alert_status)](https://sonarcloud.io/dashboard?id=xmidt-org_scytale)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/scytale/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/scytale.svg)](CHANGELOG.md)

## Summary
Scytale is the API server of [XMiDT](https://xmidt.io/). Scytale will fanout the
API request to all the [petasoses](https://github.com/xmidt-org/petasos) that scytale knows of.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Details](#details)
- [Build](#build)
- [Deploy](#deploy)
- [Contributing](#contributing)

## Code of Conduct

This project and everyone participating in it are governed by the [XMiDT Code Of Conduct](https://xmidt.io/code_of_conduct/). 
By participating, you agree to this Code.

## Details
Scytale has two API endpoints to interact with the devices: 1) get the statistics for
a device and 2) send a [WRP Message](https://github.com/xmidt-org/wrp-c/wiki/Web-Routing-Protocol)
to the device.  If the device isn't connected, a 404 is returned.

#### Device Statistics - `/api/v2/device/{deviceID}/stat` endpoint
This will return the statistics of the connected device,
including information such as uptime and bytes sent.
This information is retrieved from the talaria that the device is connected to.

#### Send WRP to Device - `/api/v2/device/send` endpoint
This will send a WRP message to the device.
Scytale will accept a WRP message encoded in a valid WRP representation - generally `msgpack` or `json`
and will forward the request to the correct talaria.

## Build

### Source

In order to build from the source, you need a working Go environment with
version 1.11 or greater. Find more information on the [Go website](https://golang.org/doc/install).

You can directly use `go get` to put the scytale binary into your `GOPATH`:
```bash
GO111MODULE=on go get github.com/xmidt-org/scytale
```

You can also clone the repository yourself and build using make:

```bash
mkdir -p $GOPATH/src/github.com/xmidt-org
cd $GOPATH/src/github.com/xmidt-org
git clone git@github.com:xmidt-org/scytale.git
cd scytale
make build
```

### Makefile

The Makefile has the following options you may find helpful:
* `make build`: builds the scytale binary
* `make docker`: builds a docker image for scytale, making sure to get all
   dependencies
* `make local-docker`: builds a docker image for scytale with the assumption
   that the dependencies can be found already
* `make test`: runs unit tests with coverage for scytale
* `make clean`: deletes previously-built binaries and object files

### RPM

First have a local clone of the source and go into the root directory of the 
repository.  Then use rpkg to build the rpm:
```bash
rpkg srpm --spec <repo location>/<spec file location in repo>
rpkg -C <repo location>/.config/rpkg.conf sources --outdir <repo location>'
```

### Docker

The docker image can be built either with the Makefile or by running a docker
command.  Either option requires first getting the source code.

See [Makefile](#Makefile) on specifics of how to build the image that way.

For running a command, either you can run `docker build` after getting all
dependencies, or make the command fetch the dependencies.  If you don't want to
get the dependencies, run the following command:
```bash
docker build -t scytale:local -f deploy/Dockerfile .
```
If you want to get the dependencies then build, run the following commands:
```bash
GO111MODULE=on go mod vendor
docker build -t scytale:local -f deploy/Dockerfile.local .
```

For either command, if you want the tag to be a version instead of `local`,
then replace `local` in the `docker build` command.

### Kubernetes

A helm chart can be used to deploy scytale to kubernetes
```
helm install xmidt-scytale deploy/helm/scytale
```

## Deploy

For deploying a XMiDT cluster refer to [getting started](https://xmidt.io/docs/operating/getting_started/).

For running locally, ensure you have the binary [built](#Source).  If it's in
your `GOPATH`, run:
```
scytale
```
If the binary is in your current folder, run:
```
./scytale
```

## Contributing

Refer to [CONTRIBUTING.md](CONTRIBUTING.md).
