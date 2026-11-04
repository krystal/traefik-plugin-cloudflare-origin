# Builds on the build platform and cross-compiles, so no emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd/copy-plugin/ ./cmd/copy-plugin/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
  go build -trimpath -ldflags='-s -w' -o /out/copy-plugin ./cmd/copy-plugin

# The plugin files sit at the image root, so an image volume can mount the
# image as the plugin directory without a subPath.
FROM scratch
LABEL org.opencontainers.image.source="https://github.com/krystal/traefik-plugin-cloudflare-origin" \
  org.opencontainers.image.description="Traefik plugin that authenticates Cloudflare-proxied requests and forwards their real client IP" \
  org.opencontainers.image.licenses="MIT"
COPY --from=build /out/copy-plugin /copy-plugin
COPY --chmod=0644 .traefik.yml go.mod cloudflare_origin.go LICENSE /
USER 65532:65532
ENTRYPOINT ["/copy-plugin"]
