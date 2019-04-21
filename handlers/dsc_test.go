package handlers

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

type Resp struct {
	dscv string
	hmac string
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

func TestDSCHandler(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/_dsc/dsservice", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	env := Env{MaxTime:60, DSCKey:"123" }
	handler := http.Handler(Handler{&env, Dsservice})

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var got Resp
	_ = json.Unmarshal([]byte(rr.Body.String()), &got)
	if got.dscv != "" {
		u1, _ := uuid.Parse(got.dscv)
		if got.hmac == url.QueryEscape(CreateMAC(&u1, []byte(env.DSCKey))) {
			t.Log("got a good response.")
		}else{
			t.Fatalf("bad hmac! %s", got.hmac)
		}
	}
}

func TestJudge(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	u1, _ := uuid.NewUUID()

	hmac := url.QueryEscape(CreateMAC(&u1, []byte("123")))
	req, err := http.NewRequest("GET", "/foo/var?dscv=" + u1.String() + "&hmac=" + hmac, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	log := logrus.New()
	env := Env{MaxTime:60, DSCKey:"123", Log: log, Proto:"both"}

	handler := http.Handler(Handler{&env, JudgeW})

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var got Resp
	_ = json.Unmarshal([]byte(rr.Body.String()), &got)
	if got.dscv != "" {
		u2, _ := uuid.Parse(got.dscv)
		if got.hmac == url.QueryEscape(CreateMAC(&u2, []byte(env.DSCKey))) {
			t.Log("got a good response.")
		}else{
			t.Fatalf("bad hmac! %s", got.hmac)
		}
	}
}


func TestJudgeCookie(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	u1, _ := uuid.NewUUID()

	req, err := http.NewRequest("GET", "/foo/var?dscv=" + u1.String(), nil)
	c := http.Cookie{Name:"hmac", Path:"/", Value: CreateMAC(&u1, []byte("123"))}
	req.AddCookie(&c)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	log := logrus.New()
	env := Env{MaxTime:60, DSCKey:"123", Log: log, Proto:"both"}

	handler := http.Handler(Handler{&env, JudgeW})

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	var got Resp
	_ = json.Unmarshal([]byte(rr.Body.String()), &got)
	if got.dscv != "" {
		u2, _ := uuid.Parse(got.dscv)
		if got.hmac == url.QueryEscape(CreateMAC(&u2, []byte(env.DSCKey))) {
			t.Log("got a good response.")
		}else{
			t.Fatalf("bad hmac! %s", got.hmac)
		}
	}
}


func TestFail(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	u1, _ := uuid.Parse("117e2b18-5461-11e9-bbdc-54e1ade48196")
	hmac := url.QueryEscape(CreateMAC(&u1, []byte("123")))
	req, err := http.NewRequest("GET", "/foo/var?dscv=" + u1.String() + "&hmac=" + hmac, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	log := logrus.New()
	env := Env{MaxTime:60, DSCKey:"123", Log: log, Proto:"both"}

	handler := http.Handler(Handler{&env, JudgeW})

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}
}

func TestFailHmac(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	u1, _ := uuid.NewUUID()

	hmac := ""
	req, err := http.NewRequest("GET", "/foo/var?dscv=" + u1.String() + "&hmac=" + hmac, nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	log := logrus.New()
	env := Env{MaxTime:60, DSCKey:"123", Log: log}

	handler := http.Handler(Handler{&env, JudgeW})

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}
}


func TestStatus(t *testing.T) {
	req, err := http.NewRequest("GET", "/_dsc/status", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	env := Env{MaxTime:60, DSCKey:"123" }
	handler := http.Handler(Handler{&env, Status})
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	if rr.Body.String() == "OK\n"{
		t.Log("got a good response.")
	}else{
		t.Fatalf("bad response!")
	}
}

func TestProxy(t *testing.T){
	backendResponse := "I am the backend"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_: w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	u1, _ := uuid.NewUUID()
	hmac := url.QueryEscape(CreateMAC(&u1, []byte("123")))

	req, err := http.NewRequest("GET", backendURL.String() + "?dscv=" + u1.String() + "&hmac=" + hmac, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	log := logrus.New()
	env := Env{MaxTime:60, DSCKey:"123", Log: log, Proto:"both"}
	env.Proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Host = backendURL.Host
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
			req.URL.Path = singleJoiningSlash(backendURL.Path, req.URL.Path)
			if backendURL.RawQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = backendURL.RawQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = backendURL.RawQuery + "&" + req.URL.RawQuery
			}
		},
	}
	handler := http.Handler(Handler{&env, ProxyHandler})
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

}

