package application

import (
	"github.com/Sirupsen/logrus"
	"github.com/carbocation/interpose"
	gorilla_mux "github.com/gorilla/mux"
	"github.com/jfardello/dsc-go/handlers"
	"github.com/spf13/viper"
	"github.com/throttled/throttled"
	"github.com/throttled/throttled/store/memstore"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// New is the constructor for Application struct.
func New(config *viper.Viper) (*Application, error) {
	app := &Application{}
	app.config = config
	return app, nil
}

// Application is the application object that runs HTTP server.
type Application struct {
	config      *viper.Viper
}

func (app *Application) MiddlewareStruct() (*interpose.Middleware, error) {
	middle := interpose.New()
	middle.UseHandler(app.mux())
	return middle, nil
}


func singleJoiningSlash(a, b string) string {
    aslash := strings.HasSuffix(a, "/")
    bslash := strings.HasPrefix(b, "/")
    switch {
    case aslash && bslash:
        return a + b[1:]
    case !aslash && !bslash:
        return a + "/" + b
    }
    return a + b
}

func (app *Application) mux() *gorilla_mux.Router {
	router := gorilla_mux.NewRouter()
	u, err := url.Parse(app.config.GetString("upstream"))

	env := handlers.Env{
		MaxTime: app.config.GetInt64("max_time"),
		DSCKey:  app.config.GetString("secret"),
		CustomHeader: app.config.GetString("custom_header"),
		Log: &logrus.Logger{
			Out: os.Stderr,
			Level: logrus.InfoLevel,
			Formatter: &logrus.TextFormatter{
				FullTimestamp :true,
			},
		},


	}
	if err == nil {
		// env.Proxy = httputil.NewSingleHostReverseProxy(u)
		targetQuery := u.RawQuery
		env.Proxy = &httputil.ReverseProxy{
			 Director: func(req *http.Request) {
			 	req.Host = u.Host
            	req.URL.Scheme = u.Scheme
            	req.URL.Host = u.Host
            	req.URL.Path = singleJoiningSlash(u.Path, req.URL.Path)
            	if targetQuery == "" || req.URL.RawQuery == "" {
            		req.URL.RawQuery = targetQuery + req.URL.RawQuery

				} else {
                	req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
            	}
			 },
		}
	}

	store, err := memstore.New(65536)
	if err != nil {
		logrus.Fatal(err)
	}

	var quota throttled.RateQuota
	s := strings.Split(app.config.GetString("throttle"), ",")
	max , _:= strconv.Atoi(s[0])
	burst, _ := strconv.Atoi(s[1])

	switch app.config.GetString("throttle_period") {

	case "D":
		quota = throttled.RateQuota{MaxRate: throttled.PerDay(max), MaxBurst: burst}
	case "H":
		quota = throttled.RateQuota{MaxRate: throttled.PerHour(max), MaxBurst: burst}
	case "M":
		quota = throttled.RateQuota{MaxRate: throttled.PerMin(max), MaxBurst: burst}
	default:
		quota = throttled.RateQuota{MaxRate: throttled.PerMin(max), MaxBurst: burst}

	}
	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		logrus.Fatal(err)
	}

	rl := throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Path: true, RemoteAddr: true, Headers: []string{"X-Forwarded-For", "X-Real-IP"}},
	}


	router.Handle("/_dsc/judge/{orig:.+}", rl.RateLimit(handlers.Handler{Env: &env, H: handlers.JudgeW}))
	router.Handle("/_dsc/dscservice", rl.RateLimit(handlers.Handler{Env: &env, H: handlers.Dsservice}))

    if env.Proxy != nil {
		router.PathPrefix("/").Handler(rl.RateLimit(handlers.Handler{Env: &env, H: handlers.ProxyHandler}))
	}


	return router
}
