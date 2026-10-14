# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-License-Identifier: Apache-2.0

# ── cloud backend — AWS EC2 reference module (FLEET-3, DESIGN §11.5) ──
#
# The bootstrap contract is identical to every backend: a machine with the
# sentin8 deb installed and captain started against the shared Valkey.
# AWS specifics: user-data bring-up + IMDS-derived private IP as new_ip.
#
# Credentials: the provider's own env vars (AWS_ACCESS_KEY_ID etc.) —
# captain never stores them (secrets-by-reference).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "Region the fleet machines live in (AWS_*-style provider config may override)."
  type        = string
  default     = "eu-central-1"
}

variable "aws_ami" {
  description = "The sentin8 golden AMI — built from the packaging deb (cloud-init installs it at boot otherwise)."
  type        = string
  default     = ""
}

variable "aws_instance_type" {
  description = "Fleet machine size."
  type        = string
  default     = "t3.medium"
}

variable "aws_subnet_id" {
  description = "Subnet the fleet machines attach to (the operator's VPC layout)."
  type        = string
}

locals {
  is_provision = var.action == "provision"
}

# The golden AMI (or a base image + cloud-init install). The user-data
# script is the machine bring-up: install the deb, materialize the env
# file, start captain.
data "aws_ami" "sentin8" {
  count = local.is_provision && var.aws_ami == "" ? 1 : 0
  most_recent = true
  filter {
    name   = "name"
    values = ["sentin8-*"]
  }
  owners = ["self"]
}

resource "aws_instance" "machine" {
  count = local.is_provision ? 1 : 0

  ami           = var.aws_ami != "" ? var.aws_ami : data.aws_ami.sentin8[0].id
  instance_type = var.aws_instance_type
  subnet_id     = var.aws_subnet_id

  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail
    # ── sentin8 machine bring-up (the module contract, §11.5) ──
    mkdir -p /etc/sentin8
    ${var.sentin8_env_file != "" ? "cat > /etc/sentin8/sentin8.env <<'ENVEOF'\n${file(trimprefix(var.sentin8_env_file, "@"))}\nENVEOF" : "touch /etc/sentin8/sentin8.env"}
    ${var.edge_ip != "" ? "echo \"SENTIN8_CAPTAIN_EDGE_IP=${var.edge_ip}\" >> /etc/sentin8/sentin8.env" : ""}
    cat >> /etc/sentin8/sentin8.env <<EOF
    SENTIN8_CAPTAIN_VALKEY_URL=${var.valkey_url}
    SENTIN8_CAPTAIN_CATALOG_PATHS=${var.catalog_paths}
    SENTIN8_CAPTAIN_TELEMETRY=procfs
    EOF
    set -a; . /etc/sentin8/sentin8.env; set +a
    # Install the platform (packaging deb) if the AMI is not golden.
    command -v sentin8-captain >/dev/null 2>&1 || apt-get update && apt-get install -y /usr/share/sentin8/*.deb || true
    # Start captain against the shared registry (the service unit sources
    # the same env file; direct exec covers a non-systemd golden image).
    systemctl start sentin8-captain || sentin8-cli captain start --local-ip=$(hostname -I | awk '{print $1}')
  EOT

  tags = {
    Name               = "sentin8-machine"
    "sentin8:trigger"  = var.trigger_ip
    "sentin8:busy"     = var.busy_service
  }
}

# Deprovision: terminate the instance that holds target_ip.
data "aws_instances" "fleet" {
  count = local.is_provision ? 0 : 1
  filter {
    name   = "tag:sentin8:fleet"
    values = ["true"]
  }
  instance_state_names = ["running", "pending", "stopped"]
}

locals {
  retire_id = local.is_provision ? null : one([
    for i in try(data.aws_instances.fleet[0].instances, []) : i
    if try(tolist([for n in i.private_ip : n])[0], "") == var.target_ip
  ])
}

resource "null_resource" "retire" {
  count = local.is_provision || local.retire_id == null ? 0 : 1
  triggers = {
    instance_id = local.retire_id.id
  }
  provisioner "local-exec" {
    # The graceful-leave call already ran in captain (§11.5); the AWS API
    # termination is the destroy.
    command = "aws ec2 terminate-instances --instance-ids ${local.retire_id.id} --region ${var.aws_region}"
  }
}

output "new_ip" {
  description = "The provisioned machine's private IP — captain RPUSHes it onto the provision-order list."
  value       = local.is_provision ? aws_instance.machine[0].private_ip : ""
}