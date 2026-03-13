# ──────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — Azure Terraform outputs
# ──────────────────────────────────────────────────────────────────────────────

output "resource_group_name" {
  description = "Azure Resource Group name."
  value       = azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  description = "AKS cluster name."
  value       = azurerm_kubernetes_cluster.main.name
}

output "aks_fqdn" {
  description = "AKS API server FQDN."
  value       = azurerm_kubernetes_cluster.main.fqdn
}

output "acr_login_server" {
  description = "Azure Container Registry login server."
  value       = azurerm_container_registry.main.login_server
}

output "key_vault_uri" {
  description = "Azure Key Vault URI."
  value       = azurerm_key_vault.main.vault_uri
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID for Defender / Azure Monitor."
  value       = azurerm_log_analytics_workspace.main.workspace_id
}

output "kubeconfig_command" {
  description = "Azure CLI command to obtain kubeconfig."
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}"
}

output "helm_deploy_command" {
  description = "Helm command to deploy Shadow Warden onto the AKS cluster."
  value = <<-EOT
    # 1. Get kubeconfig
    az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_kubernetes_cluster.main.name}

    # 2. Create namespace
    kubectl create namespace shadow-warden --dry-run=client -o yaml | kubectl apply -f -

    # 3. Create Key Vault secret store (CSI) for ANTHROPIC_API_KEY
    #    See: helm/shadow-warden/templates/ — SecretProviderClass not included;
    #    configure per your Key Vault CSI driver setup.

    # 4. Deploy with Helm
    helm upgrade --install shadow-warden ./helm/shadow-warden \
      --namespace shadow-warden \
      --set warden.image.repository=${azurerm_container_registry.main.login_server}/shadow-warden/gateway \
      --set warden.image.tag=${var.warden_image_tag} \
      --set global.imageRegistry=${azurerm_container_registry.main.login_server}
  EOT
}

output "acr_push_commands" {
  description = "Commands to build and push the warden image to ACR."
  value = <<-EOT
    # Authenticate to ACR
    az acr login --name ${azurerm_container_registry.main.name}

    # Build and push
    docker build -t ${azurerm_container_registry.main.login_server}/shadow-warden/gateway:${var.warden_image_tag} \
      -f warden/Dockerfile .
    docker push ${azurerm_container_registry.main.login_server}/shadow-warden/gateway:${var.warden_image_tag}
  EOT
}
