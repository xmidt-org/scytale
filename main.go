/**
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"

	"github.com/go-kit/kit/log/level"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/xmidt-org/candlelight"
	"github.com/xmidt-org/webpa-common/basculechecks"
	"github.com/xmidt-org/webpa-common/basculemetrics"
	"github.com/xmidt-org/webpa-common/concurrent"
	"github.com/xmidt-org/webpa-common/logging"
	"github.com/xmidt-org/webpa-common/server"
	"github.com/xmidt-org/webpa-common/service"
	"github.com/xmidt-org/webpa-common/service/consul"
	"github.com/xmidt-org/webpa-common/service/servicecfg"
	"github.com/xmidt-org/webpa-common/webhook"
	"github.com/xmidt-org/webpa-common/webhook/aws"
)

const (
	//DefaultKeyID is used to build JWT validators
	DefaultKeyID = "current"

	applicationName  = "scytale"
	release          = "Developer"
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

		logger, metricsRegistry, webPA, err = server.Initialize(applicationName, arguments, f, v, webhook.Metrics, aws.Metrics, basculechecks.Metrics, basculemetrics.Metrics, consul.Metrics, Metrics, service.Metrics)
	)

	if parseErr, done := printVersion(f, arguments); done {
		// if we're done, we're exiting no matter what
		if parseErr != nil {
			friendlyError := fmt.Sprintf("failed to parse arguments. detailed error: %s", parseErr)
			logging.Error(logger).Log(
				logging.ErrorKey(),
				friendlyError)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize Viper environment: %s\n", err)
		return 1
	}

	logger.Log(level.Key(), level.InfoValue(), "configurationFile", v.ConfigFileUsed())

	tracing, err := loadTracing(v, applicationName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to build tracing component: %v \n", err)
		return 1
	}
	level.Info(logger).Log(logging.MessageKey(), "tracing status", "enabled", !tracing.IsNoop())

	var e service.Environment
	if v.IsSet("service") {
		var err error
		e, err = servicecfg.NewEnvironment(logger, v.Sub("service"), service.WithProvider(metricsRegistry))
		if err != nil {
			logger.Log(level.Key(), level.ErrorValue(), logging.MessageKey(), "Unable to initialize service discovery environment", logging.ErrorKey(), err)
			return 4
		}
	}

	primaryHandler, err := NewPrimaryHandler(logger, v, metricsRegistry, e, tracing)
	if err != nil {
		logger.Log(level.Key(), level.ErrorValue(), logging.ErrorKey(), err, logging.MessageKey(), "unable to create primary handler")
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

	signal.Notify(signals, os.Kill, os.Interrupt)
	for exit := false; !exit; {
		select {
		case s := <-signals:
			logger.Log(level.Key(), level.ErrorValue(), logging.MessageKey(), "exiting due to signal", "signal", s)
			exit = true
		case <-done:
			logger.Log(level.Key(), level.ErrorValue(), logging.MessageKey(), "one or more servers exited")
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
