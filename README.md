# scytale
(pronounced "skit-uh-​lee")

[![Build Status](https://travis-ci.com/xmidt-org/scytale.svg?branch=master)](https://travis-ci.com/xmidt-org/scytale)
[![codecov.io](http://codecov.io/github/xmidt-org/scytale/coverage.svg?branch=master)](http://codecov.io/github/xmidt-org/scytale?branch=master)
[![Code Climate](https://codeclimate.com/github/xmidt-org/scytale/badges/gpa.svg)](https://codeclimate.com/github/xmidt-org/scytale)
[![Issue Count](https://codeclimate.com/github/xmidt-org/scytale/badges/issue_count.svg)](https://codeclimate.com/github/xmidt-org/scytale)
[![Go Report Card](https://goreportcard.com/badge/github.com/xmidt-org/scytale)](https://goreportcard.com/report/github.com/xmidt-org/scytale)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/scytale/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/xmidt-org/scytale.svg)](CHANGELOG.md)

## Summary
Scytale is the API server of [XMiDT](https://xmidt.io/). Scytale will fanout the
API request to all the [petasoses](https://github.com/xmidt-org/petasos) that scytale knows of.

## Details
Scytale has two API endpoints to interact with the devices: 1) get the statistics for
a device and 2) send a [WRP Message](https://github.com/xmidt-org/wrp-c/wiki/Web-Routing-Protocol)
to the device.  If the device isn't connected, a 404 is returned.

#### Device Statistics - `/device/{deviceID}/stat` endpoint
This will return the statistics of the connected device,
including information such as uptime and bytes sent.
This information is retrieved from the talaria that the device is connected to.

#### Send WRP to Device - `/device/send` endpoint
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
* `make rpm`: builds an rpm containing scytale
* `make docker`: builds a docker image for scytale, making sure to get all
   dependencies
* `make local-docker`: builds a docker image for scytale with the assumption
   that the dependencies can be found already
* `make test`: runs unit tests with coverage for scytale
* `make clean`: deletes previously-built binaries and object files

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

WIP. TODO: add info

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
