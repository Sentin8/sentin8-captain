# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-License-Identifier: Apache-2.0

# ── hypervisor backend — Proxmox VE reference module (FLEET-3, DESIGN §11.5) ──
#
# Clones the operator's sentin8 VM template (the golden image with the
# packaging deb installed) and drives bring-up via cloud-init: env file,
# edge pin, captain start. new_ip is the VM's first DHCP-lease IP —
# deterministic via the template's cloud-init ipam config or a static
# pool the operator controls.
#
# Credentials: PROXMOX_VE_API_TOKEN etc. (provider env vars) — never stored.

terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.60"
    }
  }
}

provider "proxmox" {}

variable "proxmox_node" {
  description = "Target node for fleet VMs (the operator's cluster layout)."
  type        = string
}

variable "proxmox_template" {
  description = "The sentin8 golden VM template (packaging deb pre-installed; cloud-init ready)."
  type        = string
}

variable "proxmox_storage" {
  description = "Disk storage pool for cloned VMs."
  type        = string
  default     = "local-lvm"
}

variable "proxmox_bridge" {
  description = "Network bridge the VMs attach to (the fleet LAN)."
  type        = string
  default     = "vmbr0"
}

variable "proxmox_ip_pool" {
  description = "The fleet VM subnet (cloud-init derives static IPs; must match the macvlan/host network the operator runs)."
  type        = string
  default     = "192.168.77.0/24"
}

locals {
  is_provision = var.action == "provision"
  # Static addressing from the pool tail — the operator's DHCP/hosts keep
  # the low half; fleet machines take .200+.
  ip           = local.is_provision ? "${trimsuffix(var.proxmox_ip_pool, ".0/24")}.20${count_index()}" : ""
  count_index  = length(proxmox_virtual_environment_vm.fleet)
}

# Deprovision lookup: the VM whose IP is target_ip.
data "proxmox_virtual_environment_vms" "fleet" {
  node_name = var.proxmox_node
}

locals {
  retire_name = local.is_provision ? null : one([
    for vm in try(data.proxmox_virtual_environment_vms.fleet.vms, []) :
    vm.name
    if vm.name != null && startswith(vm.name, "sentin8-machine-") && try(vm.ipv4_addresses[0], "") == var.target_ip
  ])
}

resource "proxmox_virtual_environment_vm" "machine" {
  count = local.is_provision ? 1 : 0

  node_name = var.proxmox_node
  name      = "sentin8-machine-${replace(timestamp(), "/[:.TZ-]/", "")}"
  clone {
    vm_id    = var.proxmox_template
    full     = true
    storage  = var.proxmox_storage
  }

  cpu {
    cores = 4
  }
  memory {
    dedicated = 8192
  }

  network_device {
    bridge = var.proxmox_bridge
  }

  # Cloud-init bring-up (the module contract, §11.5): env file + captain.
  initialization {
    datastore_id = var.proxmox_storage
    dns {
      domain = "sentin8.local"
    }
    ip_config {
      ipv4 {
        address = "${local.ip}/24"
        gateway = "${trimsuffix(var.proxmox_ip_pool, ".0/24")}.1"
      }
    }
    user_account {
      username = "sentin8"
    }
    vendor_data = <<-EOF
      #cloud-config
      runcmd:
        - mkdir -p /etc/sentin8
        - ${var.sentin8_env_file != "" ? "cp /mnt/sentin8/sentin8.env /etc/sentin8/sentin8.env" : "touch /etc/sentin8/sentin8.env"}
        - ${var.edge_ip != "" ? "echo 'SENTIN8_CAPTAIN_EDGE_IP=${var.edge_ip}' >> /etc/sentin8/sentin8.env" : "true"}
        - |
          cat >> /etc/sentin8/sentin8.env <<EOF
          SENTIN8_CAPTAIN_VALKEY_URL=${var.valkey_url}
          SENTIN8_CAPTAIN_CATALOG_PATHS=${var.catalog_paths}
          SENTIN8_CAPTAIN_TELEMETRY=procfs
          EOF
        - set -a; . /etc/sentin8/sentin8.env; set +a
        - systemctl start sentin8-captain
    EOF
  }

  tags = ["sentin8-fleet", "trigger-${var.trigger_ip}"]
}

output "new_ip" {
  description = "The provisioned machine's LAN IP — captain RPUSHes it onto the provision-order list."
  value       = local.is_provision ? proxmox_virtual_environment_vm.machine[0].ipv4_addresses[0] : ""
}