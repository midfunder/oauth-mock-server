FROM golang:1.17-alpine as builder
WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY pkg ./pkg
RUN go build ./cmd/...

FROM golang:1.17-alpine
WORKDIR /opt/auth-mock
COPY --from=0 /workspace/auth-mock .
COPY static ./static

EXPOSE 443
CMD [ "/opt/auth-mock/auth-mock" ]