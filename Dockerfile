# Lostname's release image (plan v0.1: non-root, read-only root). The binary is the reproducible build from
# tools/build.py (dist/lostname_linux_<arch>), so the image carries the same bytes as the release and SHA256SUMS.
# Alpine for /bin/sh: CI jobs run their script inside the image (deploy/ci). No RUN step, so a multi-arch build needs
# no emulation. Nothing writes inside the image: run it with --read-only and mount a directory for evidence bundles.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG TARGETARCH
COPY dist/lostname_linux_${TARGETARCH} /usr/local/bin/lostname
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/lostname"]
LABEL org.opencontainers.image.title="lostname" \
      org.opencontainers.image.description="Prove you can leave your DNS provider" \
      org.opencontainers.image.source="https://github.com/lostnamehq/lostname" \
      org.opencontainers.image.licenses="EUPL-1.2"
