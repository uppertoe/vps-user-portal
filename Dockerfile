# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# --- build stage ---
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/portal /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
