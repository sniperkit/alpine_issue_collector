FROM golang:1.6.1-alpine

ENV APP_DIR=/go/src/github.com/eedevops/alpine_issue_collector

COPY . $APP_DIR

WORKDIR $APP_DIR

RUN go build && \
    apk update --no-cache && \
    apk add --update openssh && \
    apk add --update git && \
    git config --global user.email "dummy-email@hpe.com" && \
    git config --global user.name "Dummy Git User"

CMD ["./alpine_issue_collector"]