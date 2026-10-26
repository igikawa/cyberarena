FROM alpine:3.22 AS gvisor
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl zstd
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; checksum=bcbf431b2f9a039f6ab23bfe23986031130c0f149294978cedfd46910901deba0737d8642c848f597ed4b5c72324885db4d75ee86a1f6a90915fbe1f2f2eb915 ;; \
      arm64) arch=aarch64; checksum=60a8239ec21ba1495633dbfa24ab4d43578066fcebef2482f9d0cd1486abbfd3c5c5face1749a31cc62b287a0a44198a0852024c7f2e5683917c7c1c342d0bbe ;; \
      *) echo "Unsupported gVisor architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --proto '=https' --tlsv1.2 \
      "https://storage.googleapis.com/gvisor/releases/release/20261019/${arch}/gvisor.tar.zstd" \
      --output /tmp/gvisor.tar.zstd; \
    echo "$checksum  /tmp/gvisor.tar.zstd" | sha512sum -c -; \
    mkdir -p /gvisor; \
    zstd -d -c /tmp/gvisor.tar.zstd | tar -xf - -C /gvisor

FROM docker:28.5.1-dind
COPY --from=gvisor /gvisor/runsc /usr/local/bin/runsc
COPY --from=gvisor /gvisor/containerd-shim-runsc-v1 /usr/local/bin/containerd-shim-runsc-v1
COPY --from=gvisor /gvisor/gvisor-bin /usr/local/bin/gvisor-bin
