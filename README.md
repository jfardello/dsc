# DSC

DSC is a micro-service which provides a CSRF protection called double submit cookie.
It follows OWASP's recommendations and  it also throttles requests, adds CORS middleware, 
and adds TLS. It *mitigates* the dangers of having public contact forms exposed on the wild. 

DSC relies on cryptographic hmacs of time based values rather than persisting information to a backend.

This application serves two extra endpoints to the proxied ones: one for setting the values the browser
needs and another to integrate with proxies like envoy.

This app is intended to work as a CSRF mechanism for very simple apps and for havin a standard CSRF
mechanism when integrating with API managers & proxyes like ambassador/envoy.


## Cookie mode
Cookie mode protocol will check a named cookie ``hmac`` against the request as well as the dscv query string
value, this cookie is set when calling the ``/_dsc/dscservice`` endpoint, it is more secure because of the same domain 
cookie policies that browsers enforce, but it requires that the script making the calls to be served by the same domain
as the final endpoint and thus, is less flexible but intended to be used with serverless applications. 


* The flow starts by calling  /_dsc/dscservice

    [browser] -> [dsc] GET /_dsc/dscservice
    > (it sets the cookie and returns the dscv value)

* When calling the protected endpoint the proxy checks the cookie.

    [browser] -> [dsc] /proxied_url?dscv=xxxyyy
    >If cookie, dscv, dscv-age, and throttle info match, the url is routed to the upstream server.


## URL mode
Url mode checks both the time-based uuid and the hmac from the routed url, but it requires special care when choosing
the throttle parameters and the time window (they need to be short in order to prevent hot-linking) .
When in this mode, the json_response includes the hmac_value.


* The flow starts by calling  /_dsc/dscservice
    [browser] -> [dsc] GET /_dsc/dscservice
    >(returns the dscv value as well as the hmac in the json response.)

* When calling the protected endpoint the proxy checks both values.
    [browser] -> [dsc] /proxied_url?dscv=xxxyyy&hmac=zzzqqq
    >If hmac, dscv, dscv-age, and throttle info match, the url is routed to the upstream server.


## Installation

DSC is distributed as a DockerFile:

``docker pull xxxy``

``docker run [ENV_VARS] -p 8888:8888 xxyy:latest``

## Environment Variables for Configuration

* **HTTP_ADDR:** The host and port. Default: `":8888"`

* **HTTP_CERT_FILE:** Path to cert file. Default: `""`

* **HTTP_KEY_FILE:** Path to key file. Default: `""`

* **HTTP_DRAIN_INTERVAL:** How long application will wait to drain old requests before restarting. Default: `"1s"`

* **DSC_SECRET:** Secret key for hmac'ing the cookie value.

* **DSC_MAX_TIME:** TTL in seconds for the dsc value, the server wil reject UUIDs older than this value. 

* **DSC_DOMAINS:** A coma separated lists of hostsnames allowed, the first one being the default (ie, no Host header)

* **DSC_UPSTREAM** Forward incoming requests to this host.

* **DSC_FORCE_NO_TLS** If serving requests in clear text, don't require the X-Forwarded-Proto header.

* **DSC_PROTO:** Unimplemented.

* **DSC_CORS_ORIGINS_ALLOWED:** Comma separated list of hostnames to be alloed as cors origins.

* **DSC_CORS_HEADERS_ALLOWED** Comma separated list of headers allowed by CORS.

* **DSC_CORS_AUTH_ALLOWED** Allow authorization in cors calls, default: ``true``

* **DSC_CORS_CACHE_TTL:** Cors cache in seconds, default: ``3600``

* **DSC_THROTTLE** 20,5

* **DSC_THROTTLE_PERIOD:** H

* **DSC_THROTTLE_REDIS_URL:** If set, this is the redis url for storing throttle data, needed when runing multiple
                              instances of DSC.

