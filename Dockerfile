FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/package-firewall ./cmd/package-firewall \
  && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pfw ./cmd/pfw

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl
WORKDIR /app
COPY --from=build /out/package-firewall /usr/local/bin/package-firewall
COPY --from=build /out/pfw /usr/local/bin/pfw
COPY configs/package-firewall.example.yml /app/package-firewall.yml
COPY configs/policy.example.yml /app/policy.example.yml
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["package-firewall"]
CMD ["serve", "--config", "/app/package-firewall.yml"]
