#!/bin/sh
set -eu
sources=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
curl -fsSL --retry 3 https://github.com/OpenVPN/openvpn/releases/download/v2.6.23/openvpn-2.6.23.tar.gz -o "$work/source.tar.gz"
printf '%s  %s\n' 4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96 "$work/source.tar.gz" | sha256sum -c -
tar -xzf "$work/source.tar.gz" -C "$work"
cd "$work/openvpn-2.6.23"
patch -p1 < "$sources/udp-mask.patch"
cat "$sources/udp-mask.c" >> src/openvpn/socket.c
./configure --disable-lzo --disable-lz4 --disable-pkcs11 --disable-plugin-auth-pam --disable-plugin-down-root --disable-systemd --disable-dco
make -j"${BUILD_JOBS:-2}"
install -D -m 0755 src/openvpn/openvpn "$1"
