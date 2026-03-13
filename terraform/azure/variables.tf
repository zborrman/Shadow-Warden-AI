# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — Azure Terraform variables
# ──────────────────────────────────────────────────────────────────────────────

variable "location" {
  description = "Azure region (e.g. eastus, westeurope)."
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Deployment environment (prod | staging | dev)."
  type        = string
  default     = "prod"
}

variable "name_prefix" {
  description = "Prefix for all Azure resource names."
  type        = string
  default     = "shadowwarden"
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group to create."
  type        = string
  default     = ""  # defaults to "${name_prefix}-${environment}-rg"
}

# ── AKS ───────────────────────────────────────────────────────────────────────

variable "kubernetes_version" {
  description = "AKS Kubernetes version."
  type        = string
  default     = "1.30"
}

variable "node_vm_size" {
  description = "VM size for AKS system node pool."
  type        = string
  default     = "Standard_D4s_v3"   # 4 vCPU, 16 GiB — comfortable for ML model
}

variable "node_count_min" {
  description = "Minimum node count (auto-scale)."
  type        = number
  default     = 2
}

variable "node_count_max" {
  description = "Maximum node count (auto-scale)."
  type        = number
  default     = 10
}

variable "node_count_default" {
  description = "Initial node count."
  type        = number
  default     = 2
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vnet_cidr" {
  description = "VNET address space."
  type        = string
  default     = "10.20.0.0/16"
}

variable "aks_subnet_cidr" {
  description = "Subnet CIDR for AKS nodes."
  type        = string
  default     = "10.20.1.0/24"
}

variable "service_cidr" {
  description = "Kubernetes service CIDR (must not overlap with vnet_cidr)."
  type        = string
  default     = "172.16.0.0/16"
}

variable "dns_service_ip" {
  description = "Kubernetes DNS service IP (must be within service_cidr)."
  type        = string
  default     = "172.16.0.10"
}

# ── Azure Marketplace ─────────────────────────────────────────────────────────

variable "acr_sku" {
  description = "Azure Container Registry SKU (Basic | Standard | Premium)."
  type        = string
  default     = "Standard"
}

variable "enable_azure_policy" {
  description = "Enable Azure Policy add-on for AKS compliance."
  type        = bool
  default     = true
}

variable "log_analytics_retention_days" {
  description = "Log Analytics workspace retention (days)."
  type        = number
  default     = 30
}

# ── TLS / Ingress ─────────────────────────────────────────────────────────────

variable "dns_prefix" {
  description = "DNS prefix for the AKS cluster FQDN."
  type        = string
  default     = "shadowwarden"
}

variable "warden_image_tag" {
  description = "Image tag to deploy."
  type        = string
  default     = "1.3.0"
}
