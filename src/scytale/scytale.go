/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
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
	_ "net/http/pprof"
	"os"
	"os/signal"

	"github.com/Comcast/webpa-common/concurrent"
	"github.com/Comcast/webpa-common/logging"
	"github.com/Comcast/webpa-common/server"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	//DefaultKeyID is used to build JWT validators
	DefaultKeyID = "current"

	applicationName = "scytale"
	release         = "Developer"
)

// scytale is the driver function for Scytale.  It performs everything main() would do,
// except for obtaining the command-line arguments (which are passed to it).
func scytale(arguments []string) int {
	//
	// Initialize the server environment: command-line flags, Viper, logging, and the WebPA instance
	//

	var (
		f = pflag.NewFlagSet(applicationName, pflag.ContinueOnError)
		v = viper.New()

		logger, metricsRegistry, webPA, err = server.Initialize(applicationName, arguments, f, v)
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize Viper environment: %s\n", err)
		return 1
	}

	logger.Log(level.Key(), level.InfoValue(), "configurationFile", v.ConfigFileUsed())

	primaryHandler, webhookFactory, err := NewPrimaryHandler(logger, v)
	if err != nil {
		logger.Log(level.Key(), level.ErrorValue(), logging.ErrorKey(), err, logging.MessageKey(), "unable to create primary handler")
		return 2
	}

	var (
		_, caduceusServer = webPA.Prepare(logger, nil, metricsRegistry, primaryHandler)
		signals           = make(chan os.Signal, 10)
	)

	//
	// Execute the runnable, which runs all the servers, and wait for a signal
	//

	go webhookFactory.PrepareAndStart()

	waitGroup, shutdown, err := concurrent.Execute(caduceusServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when starting %s: %s", applicationName, err)
		return 4
	}

	signal.Notify(signals)
	s := server.SignalWait(logging.Info(logger), signals, os.Kill, os.Interrupt)
	logger.Log(level.Key(), level.ErrorValue(), logging.MessageKey(), "exiting due to signal", "signal", s)
	close(shutdown)
	waitGroup.Wait()

	return 0
}

func main() {
	os.Exit(scytale(os.Args))
}
