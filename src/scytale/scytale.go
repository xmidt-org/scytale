package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"

	"github.com/Comcast/webpa-common/concurrent"
	"github.com/Comcast/webpa-common/logging"
	"github.com/Comcast/webpa-common/server"
	"github.com/go-kit/kit/log/level"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
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

		logger, webPA, err = server.Initialize(applicationName, arguments, f, v)
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize Viper environment: %s\n", err)
		return 1
	}

	logger.Log(level.Key(), level.InfoValue(), "configurationFile", v.ConfigFileUsed())

	primaryHandler, err := NewPrimaryHandler(logger, v)
	if err != nil {
		logger.Log(level.Key(), level.ErrorValue(), logging.ErrorKey(), err, logging.MessageKey(), "unable to create primary handler")
		return 2
	}

	var (
		_, runnable = webPA.Prepare(logger, nil, primaryHandler)
		signals     = make(chan os.Signal, 1)
	)

	//
	// Execute the runnable, which runs all the servers, and wait for a signal
	//

	if err := concurrent.Await(runnable, signals); err != nil {
		fmt.Fprintf(os.Stderr, "Error when starting %s: %s", applicationName, err)
		return 4
	}

	return 0
}

func main() {
	os.Exit(scytale(os.Args))
}
