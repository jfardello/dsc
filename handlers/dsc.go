package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

var (
	ErrorForbidden = StatusError{403, errors.New("Bad dscv.")}

)




// Error represents a handler error. It provides methods for a HTTP status
// code and embeds the built-in error interface.
type Error interface {
	error
	Status() int
}

// StatusError represents an error with an associated HTTP status code.
type StatusError struct {
	Code int
	Err  error
}

// Allows StatusError to satisfy the error interface.
func (se StatusError) Error() string {
	return se.Err.Error()
}

// Returns our HTTP status code.
func (se StatusError) Status() int {
	return se.Code
}

// These are options always present in handlers.
type Env struct {
	MaxTime int64
	DSCKey string
	Proxy *httputil.ReverseProxy
	Log *logrus.Logger
	CustomHeader string
}

type Handler struct {
	*Env
	H func(e *Env, w http.ResponseWriter, r *http.Request) error
}


// ServeHTTP allows our Handler type to satisfy http.Handler.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.H(h.Env, w, r)
	if err != nil {
		switch e := err.(type) {
		case Error:
			// We can retrieve the status here and write out a specific
			// HTTP status code.
			h.Env.Log.Printf("HTTP %d - %s", e.Status(), e)

			http.Error(w, e.Error(), e.Status())
		default:
			// Any error types we don't specifically look out for default
			// to serving a HTTP 500
			http.Error(w, http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError)
		}
	}
}

func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func CreateMAC(u *uuid.UUID, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(u.String()))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type DSCV struct {
	Dscv string `json:"dscv"`

}

func Dsservice(env *Env, w http.ResponseWriter, r *http.Request) error {
	env.Log.Debug("foo")
	u1, _ := uuid.NewUUID()
	cookie := http.Cookie{
		Value: CreateMAC(&u1, []byte(env.DSCKey)),
		Path: "/",
		Name: "dscv",
		Secure: true,
		MaxAge: int(env.MaxTime),
		Domain: r.Host,
	}
	http.SetCookie(w, &cookie)
	jsOut := DSCV{Dscv: u1.String()}
	w.Header().Set("Content-Type", "application/json")
    err := json.NewEncoder(w).Encode(jsOut)
    if err != nil {
    	env.Log.Error(err)
    	panic(err)
	}
	return nil
}

func Judge(env *Env, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("dscv")
	if err != nil {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn(err)
		return StatusError{500, err}
	}

	param := r.URL.Query().Get("dscv")
	u1, err := uuid.Parse(param)
	if err != nil  {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn(err)
		// no dscv query param.
		return StatusError{403, err}
	}

	if u1.Version() != 1 && u1.Version() != 2 {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("Invalid uuid version")
		// not a time based uuid?
		return ErrorForbidden
	}

	t := u1.Time()
	uuidSecs, _ := t.UnixTime()
	now := time.Now()
	secs := now.Unix()

	if (secs - uuidSecs) / 60  >  env.MaxTime {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("Old uud.")
		return ErrorForbidden
	}
	decodedCookie, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Error(err)
		return ErrorForbidden
	}

	if CheckMAC([]byte(param), decodedCookie, []byte(env.DSCKey)) {
		env.Log.WithFields(logrus.Fields{"granted": "true"}).Info("Cookie hmac matches dscv query string.")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-DSC-Status", "valid")
		w.Header().Set("X-DSC-TTL", fmt.Sprintf("%d", env.MaxTime - ((secs - uuidSecs)/60)))
		return nil
	} else {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("Invalid hmac value.")
		return ErrorForbidden
	}
}

func JudgeW(env *Env, w http.ResponseWriter, r *http.Request) error {
	shouldRoute := Judge(env, w, r)
	if shouldRoute == nil {
		w.Write([]byte(""))
	}
	return shouldRoute

}

func ProxyHandler(env *Env, w http.ResponseWriter, r *http.Request) error {
	shouldRoute := Judge(env, w, r)
	if shouldRoute != nil {
		return shouldRoute
	}else {
		if env.CustomHeader != ""  {
			values := strings.Split(env.CustomHeader, ":")
			r.Header.Add(values[0], values[1])
		}
		env.Log.WithFields(logrus.Fields{"path": r.URL}).Info("Forwarding url to upstream.")
		env.Proxy.ServeHTTP(w, r)
		return nil
	}
}
