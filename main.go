// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"go.uber.org/zap"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/xmidt-org/bascule/basculehelper"
	"github.com/xmidt-org/candlelight"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/adapter"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/concurrent"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/server"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/service"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/service/consul"
	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/service/servicecfg"
	"github.com/xmidt-org/webpa-common/v2/webhook"

	// nolint:staticcheck
	"github.com/xmidt-org/webpa-common/v2/webhook/aws"
)

const (
	//DefaultKeyID is used to build JWT validators
	DefaultKeyID = "current"

	applicationName  = "scytale"
	tracingConfigKey = "tracing"
)

var (
	GitCommit = "undefined"
	Version   = "undefined"
	BuildTime = "undefined"
)

type CapabilityConfig struct {
	Type            string
	Prefix          string
	AcceptAllMethod string
	EndpointBuckets []string
}

// scytale is the driver function for Scytale.  It performs everything main() would do,
// except for obtaining the command-line arguments (which are passed to it).
func scytale(arguments []string) int {
	//
	// Initialize the server environment: command-line flags, Viper, logging, and the WebPA instance
	//

	var (
		f = pflag.NewFlagSet(applicationName, pflag.ContinueOnError)
		v = viper.New()

		logger, metricsRegistry, webPA, err = server.Initialize(applicationName, arguments, f, v, webhook.Metrics, aws.Metrics, basculehelper.AuthCapabilitiesMetrics, basculehelper.AuthValidationMetrics, consul.Metrics, Metrics, service.Metrics)
	)

	if parseErr, done := printVersion(f, arguments); done {
		// if we're done, we're exiting no matter what
		if parseErr != nil {
			friendlyError := fmt.Sprintf("failed to parse arguments. detailed error: %s", parseErr)
			logger.Error(friendlyError)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize Viper environment: %s\n", err)
		return 1
	}

	logger.Info("initialized viper environment", zap.String("configuartionFile:", v.ConfigFileUsed()))

	tracing, err := loadTracing(v, applicationName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to build tracing component: %v \n", err)
		return 1
	}
	logger.Info("tracing status", zap.Bool("enabled", !tracing.IsNoop()))

	var e service.Environment
	if v.IsSet("service") {
		var err error
		var log = &adapter.Logger{
			Logger: logger,
		}
		e, err = servicecfg.NewEnvironment(log, v.Sub("service"), service.WithProvider(metricsRegistry))
		if err != nil {
			logger.Error("Unable to initialize service discovery environment", zap.Error(err))
			return 4
		}
		defer e.Close()
		e.Register()
	}

	primaryHandler, err := NewPrimaryHandler(logger, v, metricsRegistry, e, tracing)
	if err != nil {
		logger.Error("unable to create primary handler", zap.Error(err))
		return 2
	}

	var (
		_, scytaleServer, done = webPA.Prepare(logger, nil, metricsRegistry, primaryHandler)
		signals                = make(chan os.Signal, 10)
	)

	//
	// Execute the runnable, which runs all the servers, and wait for a signal
	//

	waitGroup, shutdown, err := concurrent.Execute(scytaleServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when starting %s: %s", applicationName, err)
		return 4
	}

	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	for exit := false; !exit; {
		select {
		case s := <-signals:
			logger.Error("exiting due to signal", zap.Any("signal", s))
			exit = true
		case <-done:
			logger.Error("one or more servers exited")
			exit = true
		}
	}

	close(shutdown)
	waitGroup.Wait()
	return 0
}

func loadTracing(v *viper.Viper, appName string) (candlelight.Tracing, error) {
	var traceConfig candlelight.Config
	err := v.UnmarshalKey(tracingConfigKey, &traceConfig)
	if err != nil {
		return candlelight.Tracing{}, err
	}
	traceConfig.ApplicationName = appName

	tracing, err := candlelight.New(traceConfig)
	if err != nil {
		return candlelight.Tracing{}, err
	}

	return tracing, nil
}

func printVersion(f *pflag.FlagSet, arguments []string) (error, bool) {
	printVer := f.BoolP("version", "v", false, "displays the version number")
	if err := f.Parse(arguments); err != nil {
		return err, true
	}

	if *printVer {
		printVersionInfo(os.Stdout)
		return nil, true
	}
	return nil, false
}

func printVersionInfo(writer io.Writer) {
	fmt.Fprintf(writer, "%s:\n", applicationName)
	fmt.Fprintf(writer, "  version: \t%s\n", Version)
	fmt.Fprintf(writer, "  go version: \t%s\n", runtime.Version())
	fmt.Fprintf(writer, "  built time: \t%s\n", BuildTime)
	fmt.Fprintf(writer, "  git commit: \t%s\n", GitCommit)
	fmt.Fprintf(writer, "  os/arch: \t%s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func main() {
	os.Exit(scytale(os.Args))
}
