# Phase 0 · task 0.7 — distroless, multi-stage build for the API server.
#
# Base images are pinned by digest (supply-chain hygiene, same rule as the CI
# actions). Refresh with: docker buildx imagetools inspect <image>:<tag>
#
# Stage 1 builds a fully static binary (CGO disabled) so it runs on the
# distroless/static base, which ships no libc and no shell.

# golang:1.26-bookworm
FROM golang@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS builder

WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped, reproducible build of the server entrypoint.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/server ./cmd/server

# gcr.io/distroless/static-debian12:nonroot — no shell, no package manager, runs as uid 65532.
FROM gcr.io/distroless/static-debian12@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=builder /out/server /server

# Server listens on :8080 by default (PORT env, internal/config).
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/server"]
