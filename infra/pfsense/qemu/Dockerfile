# pfSense CE runs as a QEMU VM inside this container. Docker Desktop/WSL has no /dev/kvm,
# so QEMU uses software emulation (TCG): slow to boot, fine for lab traffic.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils iproute2 mtools dosfstools socat \
 && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
ENTRYPOINT ["/start.sh"]
