# syntax=docker/dockerfile:1
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/openbekci-relay ./cmd/openbekci-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/openbekci-relay /usr/local/bin/openbekci-relay
ENV RELAY_DB_PATH=/data/relay.db RELAY_LISTEN=:8080
VOLUME /data
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/openbekci-relay", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/openbekci-relay"]
CMD ["serve"]
