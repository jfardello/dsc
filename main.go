package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	gorilla_handlers "github.com/gorilla/handlers"
	"github.com/spf13/viper"
	"github.com/tylerb/graceful"
	"net/http"
	"strings"
	"time"

	"github.com/jfardello/dsc-go/application"
)

func newConfig() (*viper.Viper, error) {
	c := viper.New()
	c.SetEnvPrefix("dsc")
	c.SetDefault("secret", "")
	c.SetDefault("max_time", 3600)
	c.SetDefault("http_addr", ":8888")
	c.SetDefault("upstream", "http://localhost:8080")
	c.SetDefault("http_cert_file", "")
	c.SetDefault("http_key_file", "")
	c.SetDefault("http_drain_interval", "1s")
	c.SetDefault("force_no_tls", false)
	c.SetDefault("cors_origins_allowed", "localhost.host.tld,localhost,www.foo.com")
	c.SetDefault("cors_headers_allowed", "X-Requested-With")
	c.SetDefault("cors_auth_allowed", true)
	c.SetDefault("cors_cache_ttl", 3600)
	c.SetDefault("throttle", "20,5")
	c.SetDefault("throttle_period", "H")
	c.SetDefault("throttle_redis_url", nil)
	c.SetDefault("custom_header", nil)



	c.AutomaticEnv()

	return c, nil
}

func main() {
	config, err := newConfig()
	if len(config.GetString("SECRET")) < 16  {
		logrus.Fatal("SECRET is mandatory and should be at least 16 characters long.")
	}
	if err != nil {
		logrus.Fatal(err)
	}

	app, err := application.New(config)
	if err != nil {
		logrus.Fatal(err)
	}

	middle, err := app.MiddlewareStruct()
	if err != nil {
		logrus.Fatal(err)
	}


	serverAddress := config.Get("http_addr").(string)

	certFile := config.Get("http_cert_file").(string)
	keyFile := config.Get("http_key_file").(string)
	drainIntervalString := config.Get("http_drain_interval").(string)

	drainInterval, err := time.ParseDuration(drainIntervalString)
	if err != nil {
		logrus.Fatal(err)
	}

	headersOk := gorilla_handlers.AllowedHeaders([]string{"X-Requested-With", "Authorization"})
	originsOk := gorilla_handlers.AllowedOrigins(strings.Split(config.GetString("origins_allowed"), ","))
	methodsOk := gorilla_handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	credentials := gorilla_handlers.AllowCredentials()

	srv := &graceful.Server{
		Timeout: drainInterval,
		Server:  &http.Server{Addr: serverAddress,
							  Handler: gorilla_handlers.CORS(headersOk, originsOk, credentials, methodsOk,)(middle)},
	}

	logrus.Infoln("Running HTTP server on " + serverAddress)

	if certFile != "" && keyFile != "" {
		fmt.Println("Serving with TLS enabled")
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		if config.GetBool("force_no_tls") == false{
			fmt.Println("Serving without TLS, X-Forwarded-Proto header required.")
		} else {
			fmt.Println("Serving without TLS, X-Forwarded-Proto header disabled for debugging purposes.")
		}
		err = srv.ListenAndServe()
	}

	if err != nil {
		logrus.Fatal(err)
	}
}
