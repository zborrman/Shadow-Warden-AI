terraform {
  required_version = ">= 1.6.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.47"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# ── SSH Key ────────────────────────────────────────────────────────────────────
resource "hcloud_ssh_key" "warden" {
  name       = "shadow-warden-deploy"
  public_key = var.ssh_public_key
}

# ── Firewall ───────────────────────────────────────────────────────────────────
resource "hcloud_firewall" "warden" {
  name = "shadow-warden-fw"

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = var.admin_cidrs
  }
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction = "in"
    protocol  = "udp"
    port      = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

# ── Network ────────────────────────────────────────────────────────────────────
resource "hcloud_network" "warden" {
  name     = "shadow-warden-net"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "warden" {
  network_id   = hcloud_network.warden.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = "10.0.1.0/24"
}

# ── Primary VPS ────────────────────────────────────────────────────────────────
resource "hcloud_server" "warden_primary" {
  name        = "shadow-warden-primary"
  server_type = var.server_type
  image       = var.server_image
  location    = var.location
  ssh_keys    = [hcloud_ssh_key.warden.id]
  firewall_ids = [hcloud_firewall.warden.id]

  network {
    network_id = hcloud_network.warden.id
    ip         = "10.0.1.10"
  }

  user_data = templatefile("${path.module}/cloud-init.yml.tpl", {
    docker_compose_version = var.docker_compose_version
    deploy_key             = var.deploy_key
  })

  labels = {
    role    = "warden-primary"
    version = var.app_version
  }
}

# ── Block Storage ──────────────────────────────────────────────────────────────
resource "hcloud_volume" "warden_data" {
  name      = "shadow-warden-data"
  size      = var.volume_size_gb
  server_id = hcloud_server.warden_primary.id
  automount = true
  format    = "ext4"
}

# ── Floating IP ────────────────────────────────────────────────────────────────
resource "hcloud_floating_ip" "warden" {
  type          = "ipv4"
  home_location = var.location
  description   = "Shadow Warden AI primary IP"
}

resource "hcloud_floating_ip_assignment" "warden" {
  floating_ip_id = hcloud_floating_ip.warden.id
  server_id      = hcloud_server.warden_primary.id
}
