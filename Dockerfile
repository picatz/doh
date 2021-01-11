FROM golang:1.13.15-alpine3.12
RUN apk add -U --no-cache git
RUN mkdir -p /app/core /app/vendor
COPY core /app/core/
COPY vendor /app/vendor/
COPY *.mod *.sum *.go /app/
WORKDIR /app
#RUN go mod download
RUN go build -o /usr/local/bin/doh .
ENTRYPOINT ["/usr/local/bin/doh"]
