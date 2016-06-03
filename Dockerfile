FROM golang:1.6.1-alpine

ENV APP_DIR=/go/src/github.com/eedevops/alpine_issue_collector

COPY . $APP_DIR

WORKDIR $APP_DIR

RUN go build && \
    apk update --no-cache

CMD ["./alpine_issue_collector"]