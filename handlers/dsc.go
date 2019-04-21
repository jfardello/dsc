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
	"net/url"
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
	Proto string
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
	_, err := mac.Write(message)
	if err != nil{
		panic(err)
	}
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func CreateMAC(u *uuid.UUID, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write([]byte(u.String()))
	if err != nil{
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type DSCV struct {
	Dscv string `json:"dscv"`
	Hmac string `json:"hmac"`

}

func Dsservice(env *Env, w http.ResponseWriter, r *http.Request) error {
	u1, _ := uuid.NewUUID()
	encoded := CreateMAC(&u1, []byte(env.DSCKey))
	cookie := http.Cookie{
		Value: encoded,
		Path: "/",
		Name: "hmac",
		Secure: true,
		MaxAge: int(env.MaxTime),
		Domain: r.Host,
	}
	http.SetCookie(w, &cookie)
	jsOut := DSCV{Dscv: u1.String(), Hmac: url.QueryEscape(encoded)}
	w.Header().Set("Content-Type", "application/json")
    err := json.NewEncoder(w).Encode(jsOut)
    if err != nil {
    	env.Log.Error(err)
    	panic(err)
	}
	return nil
}

func Judge(env *Env, w http.ResponseWriter, r *http.Request) error {

	var dscv string

	c, err := r.Cookie("hmac")
	if err != nil {
		if env.Proto != "both" {
			env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("No hmac cookie found.")
			return StatusError{500, errors.New("Bad dscv; no cookie present in request.")}

		}
		raw := r.URL.Query().Get("hmac")
		h, err := url.PathUnescape(raw)
		if err != nil || raw =="" {
			env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("No hmac query string.")
			return StatusError{500, errors.New("Bad dscv; no named cookie, nor hmac" +
				" query string.")}
		}
		dscv = h
	} else {
		dscv = c.Value
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

	if (secs - uuidSecs)  >  env.MaxTime {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("Old uud.")
		return ErrorForbidden
	}
	decodedCookie, err := base64.StdEncoding.DecodeString(dscv)
	if err != nil {
		env.Log.WithFields(logrus.Fields{"granted": "false", "dscv": dscv, "uuid": u1.String()}).Error(err)
		return ErrorForbidden
	}


	if CheckMAC([]byte(param), decodedCookie, []byte(env.DSCKey)) {
		env.Log.WithFields(logrus.Fields{"granted": "true", "address": r.RemoteAddr}).Info("Cookie hmac matches dscv query string.")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-DSC-Status", "valid")
		w.Header().Set("X-DSC-TTL", fmt.Sprintf("%d", env.MaxTime - (secs - uuidSecs)))
		return nil
	} else {
		env.Log.WithFields(logrus.Fields{"granted": "false"}).Warn("Invalid hmac value.")
		return ErrorForbidden
	}
}

func Status(env *Env, w http.ResponseWriter, r *http.Request) error {
	_, err := w.Write([]byte("OK\n"))
	if err != nil {
		return err
	}else {
		return nil
	}
}


func JudgeW(env *Env, w http.ResponseWriter, r *http.Request) error {
	shouldRoute := Judge(env, w, r)
	if shouldRoute == nil {
		n,_ := w.Write([]byte(""))
		env.Log.Debugf("JudgeW wrote %n bytes", n)
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

