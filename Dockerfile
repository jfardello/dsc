FROM golang:1.12.0-alpine AS builder

RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates
RUN adduser -D -g '' appuser
RUN go get -u github.com/golang/dep/...

# Add project directory to Docker image.
ADD . /go/src/github.com/jfardello/dsc-go

ENV USER appuser
ENV DSC_HTTP_ADDR :8888
ENV DSC_HTTP_DRAIN_INTERVAL 1s

WORKDIR /go/src/github.com/jfardello/dsc-go
RUN dep ensure
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/dsc

FROM alpine
## Fails on ol docker versions
## COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/bin/dsc /go/bin/dsc
USER appuser

EXPOSE 8888



ENTRYPOINT ["/go/bin/dsc"]
