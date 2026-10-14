# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-License-Identifier: Apache-2.0

# ── docker backend — the dev/test fleet backend (FLEET-3, DESIGN §11.5) ──
#
# Provisions one "machine" as a docker container on a macvlan network so
# each container gets its OWN LAN IP (the Valkey registry model keys
# instances by {ip}:{port} — shared-bridge NAT IPs would break the
# one-captain-per-machine lock identity).
#
# The module owns the full machine bring-up (the bootstrap contract):
#   1. run the sentin8 image (built from the packaging deb; see the
#      docker/Dockerfile note in the module README),
#   2. materialize sentin8_env_file's content as /etc/sentin8/sentin8.env,
#   3. start captain connected to the shared Valkey registry
#      (sentin8-captain.service sources the env file; the entrypoint
#      execs it when the env file is present),
#   4. export the container's LAN IP as `new_ip`.
#
# Telemetry: the container entrypoint sets SENTIN8_CAPTAIN_TELEMETRY=cgroup
# (DESIGN §11.6) so saturation signals reflect the container, not the host
# (/proc/stat is not namespaced).

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

# The macvlan network. The operator creates it once per host:
#   docker network create -d macvlan --subnet=<SUBNET> --gateway=<GW> \
#     -o parent=<IFACE> sentin8-fleet
# The module attaches and reads its subnet to derive a static IP per
# container (deterministic new_ip output; DHCP-less macvlan addressing).
data "docker_network" "fleet" {
  name = "sentin8-fleet"
}

locals {
  is_provision = var.action == "provision"
  # Deterministic IP: scan up from the subnet base for an address not
  # claimed by another sentin8-fleet container (the ipam_config of
  # existing containers is the source of truth).
  claimed_ips = [
    for c in data.docker_containers.fleet.containers :
    try(element([for i in c.network_settings_blocks[0].ipam_config : i.ipv4_address], 0), "")
  ]
  # The subnet from the macvlan network (e.g. 192.168.77.0/24) — pick
  # .200+ to avoid the operator's other static allocations.
  subnet_parts = split(".", cidrhost(data.docker_network.fleet.ipam_config[0].subnet, 0))
  base         = "${local.subnet_parts[0]}.${local.subnet_parts[1]}.${local.subnet_parts[2]}"
}

data "docker_containers" "fleet" {
  # All sentin8-fleet containers (the operator names them sentin8-machine-*).
  name = "sentin8-machine-"
}

resource "docker_container" "machine" {
  count = local.is_provision ? 1 : 0

  name  = "sentin8-machine-${replace(timestamp(), "/[:.TZ-]/", "")}"
  image = "sentin8:latest"

  # Static macvlan IP — deterministic, one IP per machine (container).
  networks_advanced {
    name    = data.docker_network.fleet.name
    ipv4_address = "${local.base}.20${count.index + 1}"
  }

  # The operator env contract (§11.5): the env file content becomes
  # /etc/sentin8/sentin8.env inside the machine; the sentin8-captain
  # systemd-style entrypoint sources it before starting captain.
  volumes {
    host_path      = abspath(trimprefix(var.sentin8_env_file, "@"))
    container_path = "/etc/sentin8/sentin8.env"
    read_only      = true
  }

  # Bootstrap contract: captain connects to the shared Valkey registry and
  # composes the same catalog set as the rest of the fleet.
  env = [
    "SENTIN8_BOOTSTRAP=valkey_url=${var.valkey_url}",
    "SENTIN8_CAPTAIN_CATALOG_PATHS=${var.catalog_paths}",
    "SENTIN8_CAPTAIN_TELEMETRY=cgroup",
    "SENTIN8_CAPTAIN_EDGE_IP=${var.edge_ip}",
  ]

  # A container has no systemd; the entrypoint (packaging layer) runs the
  # same command the sentin8-captain.service unit does.
  command = ["captain-start"]

  # Machine identity: the container must run until the deprovision path
  # destroys it (captain inside supervises the fleet's services).
  restart = "unless-stopped"

  labels = {
    "sentin8.fleet/machine"  = "true"
    "sentin8.fleet/trigger"   = var.trigger_ip
    "sentin8.fleet/busy"      = var.busy_service
  }
}

# Deprovision: destroy the container that holds target_ip.
resource "docker_container" "retire" {
  for_each = local.is_provision ? {} : { for c in data.docker_containers.fleet.containers : try(element([for i in c.network_settings_blocks[0].ipam_config : i.ipv4_address], 0), "") => c.name if startswith(c.name, "sentin8-machine-") }

  name  = each.value
  image = "sentin8:latest" # placeholder — destroy-only resource

  # Force-destroy semantics: removing the resource kills the container.
  must_run = false
  force    = true

  # Match the provisioned container's network so the provider can resolve it.
  networks_advanced {
    name = data.docker_network.fleet.name
  }
}