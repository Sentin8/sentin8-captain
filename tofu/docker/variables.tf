# OpenTofu variables — the machine provision contract (captain DESIGN §11.5).
#
# Captain passes these via `-var` (env-file vars via `-var-file`-style
# `@path` indirection for sentin8_env_file). A module may ignore the ones
# its backend cannot honor, but MUST accept the full set (defaults keep
# tofu init/plan clean).

variable "backend" {
  description = "Which backend this module provisions (docker|cloud|hypervisor|bare-metal). One module dir per backend."
  type        = string
  default     = "docker"
}

variable "action" {
  description = "provision | deprovision — the module creates or destroys the target resource."
  type        = string
}

variable "trigger_ip" {
  description = "The saturated machine that triggered the provision (informational — labels/tagging)."
  type        = string
  default     = ""
}

variable "busy_service" {
  description = "The busy service that triggered the provision (informational — labels)."
  type        = string
  default     = ""
}

variable "target_ip" {
  description = "deprovision target — the machine (container) IP to destroy. Empty for provision."
  type        = string
  default     = ""
}

variable "valkey_url" {
  description = "The shared Valkey registry URL the new machine's captain connects to (the bootstrap contract)."
  type        = string
}

variable "catalog_paths" {
  description = "SENTIN8_CAPTAIN_CATALOG_PATHS for the new machine's captain (service catalog composition)."
  type        = string
  default     = ""
}

variable "sentin8_env_file" {
  description = "Path (@-indirection) whose CONTENT becomes /etc/sentin8/sentin8.env on the new machine — the operator env contract (DSNs, master keys, domain). Never logged (sensitive)."
  type        = string
  default     = ""
}

variable "edge_ip" {
  description = "Set ONLY when provisioning the edge machine — the proxy's pin:edge placement resolves against SENTIN8_CAPTAIN_EDGE_IP inside the machine."
  type        = string
  default     = ""
}

output "new_ip" {
  description = "The provisioned machine's (container's) LAN IP — captain RPUSHes it onto the provision-order list."
  value       = local.is_provision ? docker_container.machine[0].network_data[0].ip_address : ""
}