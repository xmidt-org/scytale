package main

import (
	"fmt"
	"github.com/Comcast/webpa-common/concurrent"
	"github.com/Comcast/webpa-common/handler"
	"github.com/Comcast/webpa-common/secure"
	"github.com/Comcast/webpa-common/server"
	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	"os/signal"
)

const (
	applicationName = "scytale"
)

// scytale is the driver function for Scytale.  It performs everything main() would do,
// except for obtaining the command-line arguments (which are passed to it).
func scytale(arguments []string) int {
	var (
		f = pflag.NewFlagSet(applicationName, pflag.ContinueOnError)
		v = viper.New()

		logger, webPA, err = server.Initialize(applicationName, arguments, f, v)
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize Viper environment: %s\n", err)
		return 1
	}

	logger.Info("Using configuration file: %s", v.ConfigFileUsed())

	scytaleConfig := new(ScytaleConfig)
	err = v.Unmarshal(scytaleConfig)
	if err != nil {
		return 1
	}

	workerPool := WorkerPoolFactory{
		NumWorkers: scytaleConfig.NumWorkerThreads,
		QueueSize:  scytaleConfig.JobQueueSize,
	}.New()

	serverWrapper := &ServerHandler{
		Logger: logger,
		scytaleHandler: &ScytaleHandler{
			Logger: logger,
		},
		doJob: workerPool.Send,
	}

	profileWrapper := &ProfileHandler{
		Logger: logger,
	}

	validator := secure.Validators{
		secure.ExactMatchValidator(scytaleConfig.AuthHeader),
	}

	authHandler := handler.AuthorizationHandler{
		HeaderName:          "Authorization",
		ForbiddenStatusCode: 403,
		Validator:           validator,
		Logger:              logger,
	}

	scytaleHandler := alice.New(authHandler.Decorate)

	mux := mux.NewRouter()
	mux.Handle("/api/v1/run", scytaleHandler.Then(serverWrapper))
	mux.Handle("/api/v1/profile", scytaleHandler.Then(profileWrapper))

	scytaleHealth := &ScytaleHealth{}
	var runnable concurrent.Runnable

	scytaleHealth.Monitor, runnable = webPA.Prepare(logger, mux)
	serverWrapper.scytaleHealth = scytaleHealth

	waitGroup, shutdown, err := concurrent.Execute(runnable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start device manager: %s\n", err)
		return 1
	}

	logger.Info("Scytale is up and running!")

	var (
		signals = make(chan os.Signal, 1)
	)

	signal.Notify(signals)
	<-signals
	close(shutdown)
	waitGroup.Wait()

	return 0
}

func main() {
	os.Exit(scytale(os.Args))
}
