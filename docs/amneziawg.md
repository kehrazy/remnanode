# AmneziaWG node

Enable `AMNEZIAWG_ENABLED=true` and mount persistent storage at
`/var/lib/remnanode/amneziawg`. `AMNEZIAWG_STATE_PATH` selects another directory;
`AMNEZIAWG_BINARY` selects another userspace daemon. The container needs
`NET_ADMIN`, `/dev/net/tun`, host networking and host IPv4 forwarding. Allow the
UDP ports configured in the panel. Do not reuse an OpenVPN UDP listener's port.

On a node with multiple IPv4 addresses, set `AMNEZIAWG_BIND_ADDRESS` to the local
address advertised to clients. This binds both server and relay sockets so UDP
responses use that source address. An absent value keeps wildcard binding. The
bundled core includes `docker/amneziawg/bind-address.patch` for this option;
`AMNEZIAWG_BINARY` replacements must also support `WG_BIND_ADDRESS`.

The bundled userspace core and tools are pinned by commit and SHA-256 in
`docker/amneziawg/build.sh`. No kernel module or DKMS installation is required.
OpenVPN and Xray continue to run independently. Existing images can be rolled
back while retaining the AmneziaWG state directory for recovery.

Use `docker-compose.amneziawg.yml` as an override of `docker-compose-prod.yml`,
with the tested image tag in `REMNANODE_IMAGE`. If also using the OpenVPN override,
pass both override files. Image archives and checksums are published in GitHub
releases; no Docker Hub login is required.

The persistent directory contains server keys, device keys, preshared keys,
obfuscation settings and cumulative counters. Back it up privately together with
the panel database. An initialized directory with missing or corrupt state fails
closed instead of silently generating replacement keys.

The node exposes authenticated `/node/amneziawg` management endpoints. Its panel
integration provides server and relay endpoints, per-user devices, expiration,
revocation and shared traffic accounting. See the
[panel guide](https://github.com/kehrazy/remnawave/blob/openvpn/docs/amneziawg.md).
