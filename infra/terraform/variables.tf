variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
}

variable "deploy_key" {
  description = "GitHub deploy key (private) for git pull on server"
  type        = string
  sensitive   = true
  default     = ""
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "cx31"   # 2 vCPU, 8 GB RAM
}

variable "server_image" {
  description = "Server OS image"
  type        = string
  default     = "ubuntu-24.04"
}

variable "location" {
  description = "Hetzner datacenter location"
  type        = string
  default     = "nbg1"   # Nuremberg, Germany (EU)
}

variable "network_zone" {
  description = "Hetzner network zone"
  type        = string
  default     = "eu-central"
}

variable "volume_size_gb" {
  description = "Block storage size in GB"
  type        = number
  default     = 100
}

variable "app_version" {
  description = "Shadow Warden AI application version"
  type        = string
  default     = "6.3"
}

variable "docker_compose_version" {
  description = "Docker Compose version to install"
  type        = string
  default     = "2.28.1"
}

variable "admin_cidrs" {
  description = "CIDR blocks allowed SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
