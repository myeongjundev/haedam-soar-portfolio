#!/bin/sh
# Bridge each Docker network interface to a tap device for the guest, then start pfSense.
# The container keeps no address on those networks: only the guest answers there.
set -eu

bridge() { # name docker-assigned-address
  dev=$(ip -o -4 addr show | awk -v p="$2/" 'index($4, p) == 1 {print $2; exit}')
  [ -n "$dev" ] || { echo "no interface with address $2" >&2; exit 1; }
  ip addr flush dev "$dev"
  ip link add "br-$1" type bridge
  ip link set "$dev" master "br-$1"
  ip tuntap add "tap-$1" mode tap
  ip link set "tap-$1" master "br-$1"
  for link in "$dev" "tap-$1" "br-$1"; do ip link set "$link" up; done
}

if ! ip link show br-wan >/dev/null 2>&1; then
  bridge wan "${PF_WAN_BRIDGE_IP:?}"
  bridge lan "${PF_LAN_BRIDGE_IP:?}"
fi

mkdir -p /run/qemu
[ -f /vm/disk.qcow2 ] || qemu-img create -q -f qcow2 /vm/disk.qcow2 8G
# Small FAT disk for moving config.xml in and out of the guest (only while the guest is not using it).
[ -f /vm/xfer.img ] || mkfs.vfat -C -n PFXFER /vm/xfer.img 16384 >/dev/null

boot="-boot order=c"
cdrom=""
if [ ! -f /vm/installed ]; then
  [ -f /iso/pfsense.iso ] || { echo "pfSense ISO is not mounted at /iso/pfsense.iso" >&2; exit 1; }
  cdrom="-cdrom /iso/pfsense.iso"
  boot="-boot order=dc"
fi

# shellcheck disable=SC2086
exec qemu-system-x86_64 -machine pc -cpu max -smp 2 -m "${PF_MEMORY:?}" \
  -drive file=/vm/disk.qcow2,if=virtio,format=qcow2 \
  -drive file=/vm/xfer.img,if=virtio,format=raw \
  $cdrom $boot \
  -netdev tap,id=wan,ifname=tap-wan,script=no,downscript=no -device e1000,netdev=wan,mac=52:54:00:94:00:01 \
  -netdev tap,id=lan,ifname=tap-lan,script=no,downscript=no -device e1000,netdev=lan,mac=52:54:00:94:00:02 \
  -vga std -display none \
  -monitor unix:/run/qemu/monitor.sock,server,nowait \
  -serial unix:/run/qemu/serial.sock,server,nowait
