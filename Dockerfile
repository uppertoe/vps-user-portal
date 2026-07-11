# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Pure-Go, statically linked, stripped.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/portal .

# --- runtime stage ---
# distroless/static: no shell, CA certs included (SMTP/Postgres TLS), runs as
# nonroot by default. NOTE: deployments override the uid at compose level
# (user: "1000:1000") so the portal can write the Authelia users directory,
# which is owned by the deploy user on the host.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/portal /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
