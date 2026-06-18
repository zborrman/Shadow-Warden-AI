output "server_ip" {
  description = "Primary server IP address"
  value       = hcloud_server.warden_primary.ipv4_address
}

output "floating_ip" {
  description = "Floating IP (stable public IP)"
  value       = hcloud_floating_ip.warden.ip_address
}

output "private_ip" {
  description = "Private network IP"
  value       = "10.0.1.10"
}

output "volume_id" {
  description = "Block storage volume ID"
  value       = hcloud_volume.warden_data.id
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh root@${hcloud_floating_ip.warden.ip_address}"
}

output "dns_instructions" {
  description = "DNS records to create"
  value = {
    api     = "api.shadow-warden-ai.com → A → ${hcloud_floating_ip.warden.ip_address}"
    dash    = "dash.shadow-warden-ai.com → A → ${hcloud_floating_ip.warden.ip_address}"
    trust   = "trust.shadow-warden-ai.com → A → ${hcloud_floating_ip.warden.ip_address}"
    status  = "status.shadow-warden-ai.com → A → ${hcloud_floating_ip.warden.ip_address}"
  }
}
