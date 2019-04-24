package application

import (
	"github.com/Sirupsen/logrus"
	"github.com/carbocation/interpose"
	"github.com/gomodule/redigo/redis"
	gorilla_mux "github.com/gorilla/mux"
	"github.com/jfardello/dsc-go/handlers"
	"github.com/spf13/viper"
	"github.com/throttled/throttled"
	"github.com/throttled/throttled/store/memstore"
	"github.com/throttled/throttled/store/redigostore"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type responseHeadersTransport struct {
	headers []string
}

func (t responseHeadersTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	for _, each := range t.headers {
		resp.Header.Del(each)
	}

	return resp, nil
}

// New is the constructor for Application struct.
func New(config *viper.Viper) (*Application, error) {
	app := &Application{}
	app.config = config
	return app, nil
}

// Application is the application object that runs HTTP server.
type Application struct {
	config *viper.Viper
}

func (app *Application) MiddlewareStruct() (*interpose.Middleware, error) {
	middle := interpose.New()
	middle.UseHandler(app.mux())
	return middle, nil
}

func getHmacParam(r *http.Request) string {
	raw, _ := url.PathUnescape(r.URL.Query().Get("hmac"))
	return raw
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

func NewProxy(u *url.URL) *httputil.ReverseProxy {
	targetQuery := u.RawQuery
	RemoveHeaders := responseHeadersTransport{headers: []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"}}

	return &httputil.ReverseProxy{
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
		Transport: RemoveHeaders,
	}
}

func newPool(addr string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}

func (app *Application) mux() *gorilla_mux.Router {

	router := gorilla_mux.NewRouter()
	u, err := url.Parse(app.config.GetString("upstream"))

	env := handlers.Env{
		MaxTime:      app.config.GetInt64("max_time"),
		DSCKey:       app.config.GetString("secret"),
		CustomHeader: app.config.GetString("custom_header"),
		Proto:        app.config.GetString("proto"),
		Log: &logrus.Logger{
			Out:   os.Stderr,
			Level: logrus.InfoLevel,
			Formatter: &logrus.TextFormatter{
				FullTimestamp: true,
			},
		},
	}
	if err == nil {
		env.Proxy = NewProxy(u)
	}

	redisUrl := app.config.GetString("throttle_redis_url")

	var store throttled.GCRAStore
	if redisUrl == "" {

		store, err = memstore.New(65536)
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
		pool := newPool(redisUrl)
		store, err = redigostore.New(pool, "", 0)
		if err != nil {
			panic(err)
		}
	}

	var quota throttled.RateQuota
	var re = regexp.MustCompile(`(?P<max>[0-9]+),(?P<burst>[0-9]+)`)

	if !re.MatchString(app.config.GetString("throttle")) {
		panic("Bad  DSC_THROTTLE config.")

	}
	s := re.FindStringSubmatch(app.config.GetString("throttle"))

	max, _ := strconv.Atoi(s[1])
	burst, _ := strconv.Atoi(s[2])
	if max < 1 {
		panic("Invalid config for DSC_THROTTLE: max requests per period can't be zero.")
	}

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
	proxyLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		logrus.Fatal(err)
	}

	//Rate limiter for dscservice & judge endpoints
	rl := throttled.HTTPRateLimiter{RateLimiter: rateLimiter}

	//Rate limiter for the proxy
	pl := throttled.HTTPRateLimiter{RateLimiter: proxyLimiter}

	if env.Proto == "both" {
		rl.VaryBy = &throttled.VaryBy{Path: true, RemoteAddr: true, Headers: []string{"X-Forwarded-For", "X-Real-IP"}}
		pl.VaryBy = &throttled.VaryBy{Path: false, RemoteAddr: false, Custom: getHmacParam}
	} else {
		vb := &throttled.VaryBy{Path: true, RemoteAddr: true, Headers: []string{"X-Forwarded-For", "X-Real-IP"}}
		rl.VaryBy = vb
		pl.VaryBy = vb
	}

	router.Handle("/_dsc/judge/{orig:.+}", rl.RateLimit(handlers.Handler{Env: &env, H: handlers.JudgeW}))
	router.Handle("/_dsc/dscservice", rl.RateLimit(handlers.Handler{Env: &env, H: handlers.Dsservice}))
	router.Handle("/_dsc/status", handlers.Handler{Env: &env, H: handlers.Status})
	if env.Proxy != nil {
		router.PathPrefix("/").Handler(pl.RateLimit(handlers.Handler{Env: &env, H: handlers.ProxyHandler}))
	}

	return router
}
