# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — Azure AKS deployment
#
# Topology
# ─────────
#   Resource Group
#     Azure Container Registry (ACR) — image storage
#     Virtual Network + AKS subnet
#     AKS cluster (system node pool, auto-scale 2–10)
#       Workload Identity for Key Vault / Secrets
#       Azure Monitor / Log Analytics integration
#     Azure Key Vault (secrets: ANTHROPIC_API_KEY, WARDEN_API_KEY)
#     Application Gateway Ingress Controller (AGIC) — optional
#
# Azure Marketplace readiness
# ────────────────────────────
#   • Managed Identity for AKS → ACR pull (no shared credentials)
#   • Azure Policy add-on for regulatory compliance posture
#   • Log Analytics workspace for Defender for Containers
#   • Private cluster option (set api_server_authorized_ip_ranges)
#
# Usage
# ─────
#   terraform init
#   terraform plan -var="environment=prod" -var="location=westeurope"
#   terraform apply
# ──────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.50"
    }
  }

  # Recommended: store state in Azure Blob Storage
  # backend "azurerm" {
  #   resource_group_name  = "terraform-state-rg"
  #   storage_account_name = "tfstateshadowwarden"
  #   container_name       = "tfstate"
  #   key                  = "shadow-warden.tfstate"
  # }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  rg_name      = var.resource_group_name != "" ? var.resource_group_name : "${var.name_prefix}-${var.environment}-rg"
  cluster_name = "${var.name_prefix}-${var.environment}-aks"
  acr_name     = replace("${var.name_prefix}${var.environment}acr", "-", "")
  kv_name      = "${var.name_prefix}-${var.environment}-kv"

  common_tags = {
    Project     = "shadow-warden"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = local.rg_name
  location = var.location
  tags     = local.common_tags
}

# ── Log Analytics (required for AKS monitoring + Defender) ───────────────────

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.name_prefix}-${var.environment}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days
  tags                = local.common_tags
}

# ── Virtual Network ───────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "main" {
  name                = "${var.name_prefix}-${var.environment}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_cidr]
  tags                = local.common_tags
}

resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.aks_subnet_cidr]
}

# ── Azure Container Registry ──────────────────────────────────────────────────

resource "azurerm_container_registry" "main" {
  name                = local.acr_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = var.acr_sku
  admin_enabled       = false   # use managed identity for AKS pull

  # Geo-replication for Premium tier (multi-region MSP deployments)
  # georeplications {
  #   location                = "westeurope"
  #   zone_redundancy_enabled = true
  # }

  tags = local.common_tags
}

# ── AKS Cluster ───────────────────────────────────────────────────────────────

resource "azurerm_kubernetes_cluster" "main" {
  name                = local.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.dns_prefix
  kubernetes_version  = var.kubernetes_version

  # System node pool
  default_node_pool {
    name                = "system"
    vm_size             = var.node_vm_size
    os_disk_size_gb     = 100
    os_sku              = "Ubuntu"
    vnet_subnet_id      = azurerm_subnet.aks.id

    auto_scaling_enabled = true
    min_count            = var.node_count_min
    max_count            = var.node_count_max
    node_count           = var.node_count_default

    upgrade_settings {
      drain_timeout_in_minutes      = 30
      max_surge                     = "33%"
      node_soak_duration_in_minutes = 0
    }
  }

  # System-assigned managed identity (used to pull from ACR + integrate Key Vault)
  identity {
    type = "SystemAssigned"
  }

  # Workload identity for pod-level Key Vault access
  workload_identity_enabled = true
  oidc_issuer_enabled       = true

  # Networking
  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    service_cidr      = var.service_cidr
    dns_service_ip    = var.dns_service_ip
  }

  # Monitoring
  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.main.id
    msi_auth_for_monitoring_enabled = true
  }

  # Azure Policy for compliance posture
  dynamic "azure_policy_enabled" {
    for_each = var.enable_azure_policy ? [1] : []
    content {}
  }

  # Key Vault Secrets Provider (CSI driver)
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  # Automatic upgrades
  automatic_upgrade_channel = "patch"

  # Maintenance window — weekends only for prod
  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
    utc_offset  = "+00:00"
    start_time  = "02:00"
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count,
      kubernetes_version,
    ]
  }
}

# ── ACR → AKS role assignment (pull permission) ───────────────────────────────

resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}

# ── Azure Key Vault (secrets storage) ────────────────────────────────────────

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                       = local.kv_name
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = var.environment == "prod"
  enable_rbac_authorization  = true

  tags = local.common_tags
}

# Grant AKS Key Vault Secrets User role (read secrets via CSI driver)
resource "azurerm_role_assignment" "aks_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_kubernetes_cluster.main.key_vault_secrets_provider[0].secret_identity[0].object_id
}

# Grant the deploying principal Key Vault Administrator (to create secrets)
resource "azurerm_role_assignment" "deployer_kv_admin" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Placeholder secrets — populate via `az keyvault secret set` or CI/CD
resource "azurerm_key_vault_secret" "anthropic_api_key" {
  name         = "anthropic-api-key"
  value        = "REPLACE_WITH_REAL_KEY"
  key_vault_id = azurerm_key_vault.main.id
  tags         = { managed_by = "terraform" }

  lifecycle {
    ignore_changes = [value]   # prevent Terraform from overwriting real key on plan
  }

  depends_on = [azurerm_role_assignment.deployer_kv_admin]
}

resource "azurerm_key_vault_secret" "warden_api_key" {
  name         = "warden-api-key"
  value        = "REPLACE_WITH_REAL_KEY"
  key_vault_id = azurerm_key_vault.main.id
  tags         = { managed_by = "terraform" }

  lifecycle {
    ignore_changes = [value]
  }

  depends_on = [azurerm_role_assignment.deployer_kv_admin]
}

# ── Defender for Containers (Azure Marketplace security posture) ──────────────

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}
