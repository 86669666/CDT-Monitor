# syntax=docker/dockerfile:1.7
#
# Node and Go stages pin BUILDPLATFORM so they run natively; the Go
# compiler cross-compiles with TARGETOS/TARGETARCH. The final scratch
# stage is unpinned so the image platform matches the target, not the
# builder host. Do not add --push here; publishing is a workflow concern.

FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
# TARGETOS and TARGETARCH are injected by BuildKit for each requested target.
# Do not provide defaults here: a default would make every architecture build
# use amd64 and can produce an arm64 image containing an amd64 binary.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=frontend /src/internal/web/dist ./internal/web/dist
RUN mkdir -p /runtime-data && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" \
      -o /cdt-monitor ./cmd/cdt-monitor

FROM --platform=$BUILDPLATFORM alpine:3.21 AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
ARG VERSION=dev
ARG IMAGE_SOURCE=https://github.com/wang4386/CDT-Monitor
LABEL org.opencontainers.image.title="CDT Monitor" \
      org.opencontainers.image.description="阿里云 CDT 流量监控与实例自动化控制台" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="${IMAGE_SOURCE}"
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /cdt-monitor /cdt-monitor
COPY --from=builder --chown=65532:65532 /runtime-data /data
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/cdt-monitor", "healthcheck"]
ENTRYPOINT ["/cdt-monitor"]
CMD ["serve"]
