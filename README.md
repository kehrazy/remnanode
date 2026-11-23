## Remnawave Node

Node for Remnawave Panel.

Learn more about Remnawave Panel [here](https://docs.rw/).

This fork runs panel-managed OpenVPN alongside Xray. Load a tested image archive
from this fork's releases, set `REMNANODE_IMAGE` to its full image tag and provide
the existing `SECRET_KEY` in your local `.env`. Start it with:

```sh
docker compose -f docker-compose-prod.yml -f docker-compose.openvpn.yml up -d
```

Enable `net.ipv4.ip_forward=1` on the host and allow the public OpenVPN ports you
configure in the panel. Persist and back up `./openvpn`: it contains server and
client private keys, account state and traffic counters. OpenVPN is disabled unless
`OPENVPN_ENABLED=true`; existing Xray-only deployments retain their behavior.
See the [panel's OpenVPN guide](https://github.com/kehrazy/remnawave/blob/openvpn/docs/openvpn.md)
for account policy, subscriptions, relays and rollback.

# Contributors

Check [open issues](https://github.com/remnawave/panel/issues) to help the progress of this project.

<p align="center">
Thanks to the all contributors who have helped improve Remnawave:
</p>
<p align="center">
<a href="https://github.com/remnawave/node/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=remnawave/node" />
</a>
</p>
