# syntax=docker/dockerfile:1.19@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6
# Same recipe as fount-mail-edge. Dependencies are downloaded first, and the
# digest that gets measured comes from Build Image.
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY wire/go.mod wire/
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN go mod download
COPY . .
RUN go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o /vault ./cmd/vault

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /vault /vault
EXPOSE 8080
ENTRYPOINT ["/vault"]
