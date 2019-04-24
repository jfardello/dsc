package main

import (
	"errors"
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
	c.SetDefault("cors_origins_allowed", "localhost.host.tld,localhost,www.foo.com")
	c.SetDefault("cors_headers_allowed", "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range")
	c.SetDefault("cors_expose_headers", "Content-Type,X-DSC-Value,X-Ratelimit-Limit,X-Ratelimit-Reset,X-Ratelimit-Remaining")
	c.SetDefault("cors_auth_allowed", true)
	c.SetDefault("cors_cache_ttl", 3600)
	c.SetDefault("throttle", "20,5")
	c.SetDefault("throttle_period", "H")
	c.SetDefault("throttle_redis_url", nil)
	c.SetDefault("custom_header", nil)
	c.SetDefault("proto", "dsc")

	c.AutomaticEnv()

	if len(c.GetString("SECRET")) < 16 {
		logrus.Fatal("SECRET is mandatory and should be at least 16 characters long.")
	}
	return c, errors.New("must be at leas 16 characters long")
}

func originValidator(origin string) bool {
	config, err := newConfig()
    if err != nil {
        logrus.Fatal(err)
    }
	for _, b := range strings.Split(config.GetString("cors_origins_allowed"), ",") {
		if b == origin {
			return true
		}
	}
	return false
}

func main() {
	config, err := newConfig()
	if err != nil {
		logrus.Fatal(err)
	}
	for _, key := range config.AllKeys() {
		if key != "secret" {
			logrus.Printf("dsc_%s=%s", key, config.GetString(key))
		}
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

	headersOk := gorilla_handlers.AllowedHeaders(strings.Split(config.GetString("cors_headers_allowed"), ","))
	originsOk := gorilla_handlers.AllowedOrigins([]string{})
	validator := gorilla_handlers.AllowedOriginValidator(originValidator)
	//originsOk := gorilla_handlers.AllowedOrigins(strings.Split(config.GetString("cors_origins_allowed"), ","))
	methodsOk := gorilla_handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	credentials := gorilla_handlers.AllowCredentials()
	expose := gorilla_handlers.ExposedHeaders(strings.Split(config.GetString("cors_expose_headers"), ","))

	srv := &graceful.Server{
		Timeout: drainInterval,
		Server: &http.Server{Addr: serverAddress,
			Handler: gorilla_handlers.CORS(headersOk, originsOk, validator, credentials, methodsOk,
				expose)(middle)},
	}

	logrus.Infoln("Running HTTP server on " + serverAddress)

	if certFile != "" && keyFile != "" {
		fmt.Println("Serving with TLS enabled")
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		fmt.Println("Warning! Serving clear text http!")
		err = srv.ListenAndServe()
	}

	if err != nil {
		logrus.Fatal(err)
	}
}
