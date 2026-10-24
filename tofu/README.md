# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>

# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-License-Identifier: Apache-2.0

# tofu/ - the machine-provisioning module kit (FLEET-3, DESIGN §11.5)

One directory per backend. Captain executes `tofu apply` against the
directory `SENTIN8_CAPTAIN_TOFU_DIR` points at (the operator copies or
symlinks one of these, or writes their own against the same contract).

## The module contract

Every backend module MUST:

1. Accept the full variable set (see each `variables.tf`):
   `backend`, `action` (`provision|deprovision`), `trigger_ip`,
   `busy_service`, `target_ip`, `valkey_url`, `catalog_paths`,
   `sentin8_env_file` (`@path` indirection - the content becomes
   `/etc/sentin8/sentin8.env`; never logged), `edge_ip` (set only when
   provisioning the edge machine).
2. On `provision`: deliver a machine with the sentin8 package installed
   (golden image / cloud-init / container image) and captain started
   against the shared Valkey registry (`valkey_url`), then expose
   `output "new_ip"` - the machine's LAN IP.
3. On `deprovision`: destroy the machine holding `target_ip` (captain
   already made the best-effort graceful-leave call before applying).

Rust never SSHes; bring-up is provider-native (user-data, cloud-init,
container entrypoint). Credentials stay in the provider's own env vars.

## Backends

| Dir | Backend | Use for |
|---|---|---|
| `docker/` | `kreuzwerker/docker`, macvlan | dev + test fleets (first-class; `SENTIN8_CAPTAIN_TELEMETRY=cgroup` in the entrypoint) |
| `cloud/` | AWS EC2 + user-data | production cloud reference |
| `hypervisor/` | Proxmox VE clone + cloud-init | on-prem/bare-metal reference |
| (operator-supplied) | MAAS/Tinkerbell/IPMI | `bare-metal` backend - same contract, operator-authored |

## docker prerequisites (one-time, per host)

```bash
docker network create -d macvlan \
  --subnet=192.168.77.0/24 --gateway=192.168.77.1 \
  -o parent=<LAN_IFACE> sentin8-fleet
```

The sentin8 image: build from the packaging deb (see
`sentin8-packaging`) - the base image carries the fleet's binaries +
the `captain-start` entrypoint that sources
`/etc/sentin8/sentin8.env` and execs the same command the
`sentin8-captain.service` unit runs.

## The operator env file

Compose one file per deployment (DSNs, master keys, `SENTIN8_DOMAIN`,
PG OAuth config, edge IP when applicable). Point captain at it:

```
SENTIN8_CAPTAIN_MACHINE_ENV_FILE=/etc/sentin8/machine.env
```

Captain passes its content to the module as the sensitive
`sentin8_env_file` var; the module materializes it as the machine's
`/etc/sentin8/sentin8.env` - the file the systemd unit already sources.

---

**Architecture & Design:** sentin8:tofu and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
