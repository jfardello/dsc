# DSC

DSC is a micro-service which provides a CSRF protection called double submit cookie.
It follows OWASP's recommendations and  it also throttles requests, adds CORS middleware, 
and adds TLS. It *mitigates* the dangers of having public contact forms exposed on the wild. 

DSC relies on cryptographic hmacs of time based values rather than persisting information to a backend.

This application serves two extra endpoints to the proxied ones: one for setting the values the browser
needs and another to integrate with proxies like envoy.

Client javascript requires minimal effort to integrate with dsc.

## Quckstart

```
$ docker pull jfardello/dsc:latest

$ DSC_DOMAINS=dsc.127-0-0-1.nip.io:8888 DSC_SECRET=nososecretbutverrylong \
  docker run -rm -p 8888:8888 jfardello/dsservice:latest

#on another terminal:

$curl -i dsc.127-0-0-1.nip.io:8888/dscservice
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: <b>dscv=rErXGr2oKc8ysUtCQLv845LxUAg8UW6tVTf23i81QTE=; Path=/; Domain=dsc.127-0-0-1.nip.io:8888; Max-Age=60; Secure
Date: Wed, 27 Feb 2019 17:20:38 GMT
Content-Length: 48

{"dscv":"008c2ca4-3ab4-11e9-b418-0242ac110002"}

$ curl -i -H 'Cookie: dscv=rErXGr2oKc8ysUtCQLv845LxUAg8UW6tVTf23i81QTE=' \
  http://localhost:8080/judge/foo?dscv=008c2ca4-3ab4-11e9-b418-0242ac110002 
HTTP/1.1 200 OK
Content-Type: text/plain
X-Dsc-Status: valid
X-Dsc-Ttl: 29
Date: Wed, 27 Feb 2019 17:23:47 GMT
Content-Length: 0

```



## Installation

DSC is distributed as a docker image:

``docker pull jfardello/dsc:latest``

``docker run [ENV_VARS] -p 8888:8888 jfardello/dsc:latest``

## Environment Variables for Configuration

* **HTTP_ADDR:** The host and port. Default: `":8888"`

* **HTTP_CERT_FILE:** Path to cert file. Default: `""`

* **HTTP_KEY_FILE:** Path to key file. Default: `""`

* **HTTP_DRAIN_INTERVAL:** How long application will wait to drain old requests before restarting. Default: `"1s"`

* **DSC_SECRET:** Secret key for hmac'ing the cookie value.

* **DSC_MAX_TIME:** TTL in minutes for the dsc value, the server wil reject uuds older than this value. 

* **DSC_DOMAINS:** A coma separated lists of hostsnames allowed, the first one being the default (ie, no Host header)



