# scytale

[![Build Status](https://travis-ci.org/Comcast/scytale.svg?branch=master)](https://travis-ci.org/Comcast/scytale) 
[![codecov.io](http://codecov.io/github/Comcast/scytale/coverage.svg?branch=master)](http://codecov.io/github/Comcast/scytale?branch=master)
[![Code Climate](https://codeclimate.com/github/Comcast/scytale/badges/gpa.svg)](https://codeclimate.com/github/Comcast/scytale)
[![Issue Count](https://codeclimate.com/github/Comcast/scytale/badges/issue_count.svg)](https://codeclimate.com/github/Comcast/scytale)
[![Go Report Card](https://goreportcard.com/badge/github.com/Comcast/scytale)](https://goreportcard.com/report/github.com/Comcast/scytale)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/Comcast/scytale/blob/master/LICENSE)

The Webpa api interface server written in Go.

# How to Install

## Centos 6

1. Import the public GPG key (replace `0.0.1-65` with the release you want)

```
rpm --import https://github.com/Comcast/scytale/releases/download/0.0.1-65/RPM-GPG-KEY-comcast-xmidt
```

2. Install the rpm with yum (so it installs any/all dependencies for you)

```
yum install https://github.com/Comcast/scytale/releases/download/0.0.1-65/scytale-0.0.1-65.el6.x86_64.rpm
```

