# DSC 

DSC is a sidecar-reverse proxy app which provides a CSRF protection to its upstream called double submit cookie.
It follows OWASP's recommendations, throttles requests, handles CORS middleware headers and preflights, and adds 
TLS. In short: DSC *mitigates* the dangers of having public contact forms and public APIs exposed on the wild. 

DSC relies on cryptographic hmacs of time based values rather than persisting information to a backend.

This application serves some extra endpoints to the proxied ones: 
* ``/_dsc/dscservice`` sets the cookie hmac and returns a json containing the uuid and the hmac
 url-encoded. 
* ``/_dsc/judge`` integrates with proxies like envoy using the external auth api.
* ``/_dsc/status`` A liveness/readiness probe. 

This app is intended to work as a CSRF mechanism for very simple apps and for having a standard CSRF
mechanism when integrating with API managers & proxies like ambassador/envoy.

## Calling DSC.

Typical usage is to call DSC from xhr requests, in order to do so, some conditions must be met:

* The xhr call need the withCredentials option set.
* The CORS domain can't be a wildcard.
* At least DSC must be serving via TLS. 

### Protocol 
DSC defines two protocols:  the more secure `Cookie mode`, on which a cooke is checked against a parameter
given via querystring, and the `Url mode`, wich does not rely on cookies and requires small time windows
and throttling to mitigate abuse on the exposed services.   

#### Cookie mode
Cookie mode protocol will check a named cookie ``hmac`` against the request as well as the dscv query string
value, this cookie is set when calling the ``/_dsc/dscservice`` endpoint, the same domain cookie policies that
browsers enforce will offer extra security.

* The flow starts by calling  /_dsc/dscservice

    [browser] -> [dsc] GET /_dsc/dscservice
    > (it sets the cookie and returns the dscv value)

* When calling the protected endpoint the proxy checks the cookie.

    [browser] -> [dsc] /proxied_url?dscv=xxxyyy
    >If cookie, dscv, dscv-age, and throttle info match, the url is routed to the upstream server.


#### URL mode
Url mode checks both the time-based uuid and the hmac from the routed url, but it requires special care
when choosing the throttle parameters and the time window (they need to be short in order to 
prevent hot-linking). 
When in this mode, the json response includes the hmac value and no cookies get involved.

**Note on collisions**: This app's uuid1() is guaranteed to not produce any collisions under 
the assumption you do not create too many of them at the same time, actually more than 65536
in less than 100ns. But even on a collision the side effect will be the early exhaustion of pending
requests by the throttle code.


* The flow starts by calling  /_dsc/dscservice
    [browser] -> [dsc] GET /_dsc/dscservice
    >(returns the dscv value as well as the hmac in the json response.)

* When calling the protected endpoint the proxy checks both values.
    [browser] -> [dsc] /proxied_url?dscv=xxxyyy&hmac=zzzqqq
    >If hmac, dscv, dscv-age, and throttle info match, the url is routed to the upstream server.


## Installation

DSC is distributed as a docker image:

``$ docker run -rm [ENV_VARS] -p 8888:8888 quai.io/jfardello/dsc:latest``

## Environment Variables for Configuration

* **DSC_HTTP_ADDR:** The host and port. Default: `":8888"`

* **DSC_HTTP_CERT_FILE:** Path to cert file. Default: `""`

* **DSC_HTTP_KEY_FILE:** Path to key file. Default: `""`

* **DSC_HTTP_DRAIN_INTERVAL:** How long application will wait to drain old requests before restarting. Default: `"1s"`

* **DSC_SECRET:** Secret key for hmac'ing the cookie value.

* **DSC_MAX_TIME:** TTL in seconds for the dsc value, the server wil reject UUIDs older than this value. 

* **DSC_DOMAINS:** A coma separated lists of hostsnames allowed, the first one being the default (ie, no Host header)

* **DSC_UPSTREAM** Forward incoming requests to this host.

* **DSC_PROTO:** "dsc" for cookie mode or "both" for cookie and url modes.

* **DSC_CORS_ORIGINS_ALLOWED:** Comma separated list of hostnames to be alloed as cors origins.

* **DSC_CORS_HEADERS_ALLOWED** Comma separated list of **requests** headers allowed by CORS.

* **DSC_CORS_EXPOSE_HEADERS** Comma separated list of **response** headers exposed by browsers in xhr calls.

* **DSC_CORS_AUTH_ALLOWED** Allow authorization in cors calls, default: ``true``

* **DSC_CORS_CACHE_TTL:** Cors cache in seconds, default: ``3600``

* **DSC_THROTTLE** 20,5

* **DSC_THROTTLE_PERIOD:** defaults to "H", permitted values are: "M" for minutes, "H" for hour, and "D" for days.

* **DSC_THROTTLE_REDIS_URL:** If set, this is the redis url for storing throttle data, needed when runNing multiple
                              instances of DSC.

## Example:

Setting up a proxy to httpbin.org and post a json.

```
$ mkdir sample && cd sample
$ openssl req -subj '/CN=dsc.127.0.0.1.nip.io/O=dsc/C=ES' -new -newkey rsa:2048 -sha256 -days 365 \
   -nodes -x509 -keyout server.key -out server.crt

$ docker run -e DSC_HTTP_CERT_FILE=/cert/server.crt \
  -e DSC_HTTP_KEY_FILE=/cert/server.key \
  -e DSC_HTTP_ADDR=":8443" \
  -e DSC_SECRET="averylongsecretstring" \
  -e DSC_UPSTREAM=https://httpbin.org \
  -e DSC_DOMAINS=dsc.127.0.0.1.nip.io \
  -e DSC_CORS_ORIGINS_ALLOWED=http://demo.127.0.0.1.nip.io:8000 \
  -v $PWD/sample:/cert --rm -p 8443:8443 quay.io/jfardello/dsc:latest

```
On another terminal, launch the demo js-client:
``` 
$ mkdir /tmp/_test &&  cd /tmp_test
$ curl https://raw.githubusercontent.com/jfardello/dsc/master/sample/index.html \
   > index.html
$ python3 -m http.server
  
```
**⚠️ Note:️**

You'll have to accept the certificate **before** testing as the 
certificate is self-signed, then, you can go to http://demo.127.0.0.1.nip.io:8000/
and test the service.

## Throttle configuration

Throttle configuration affects all requests, including the ``/_dsc/judge`` endpoint. 
The format of DSC_THROTTLE, is a coma separated string of to values, ``"max,burst"``, max is an integer greater than one
which represents the maximum number of permitted requests in the period configured by ``DSC_THROTTLE_PERIOD``, while 
burst defines the number of requests that will be allowed to exceed the rate in a single burst.
``DSC_THROTTLE_PERIOD`` can be either "M" for minutes "H" (the default) for hours or D for days.

By pointing ``DSC_THROTTLE_REDIS_URL`` to a properly configured redis server you can scale the dsc process with common
throttle store data across all instances.

***

