#cloud-config
package_update: true
packages:
  - docker.io
  - docker-compose-plugin
  - git
  - curl
  - ufw

runcmd:
  # Docker
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker root

  # Firewall
  - ufw allow 22/tcp
  - ufw allow 80/tcp
  - ufw allow 443/tcp
  - ufw allow 443/udp
  - ufw --force enable

  # Deploy key for git pull
  - mkdir -p /root/.ssh
  - echo "${deploy_key}" > /root/.ssh/id_ed25519
  - chmod 600 /root/.ssh/id_ed25519
  - ssh-keyscan github.com >> /root/.ssh/known_hosts

  # Clone repository
  - git clone git@github.com:zborrman/Shadow-Warden-AI.git /opt/shadow-warden
  - cd /opt/shadow-warden && docker compose pull
  - cd /opt/shadow-warden && docker compose up -d

  # Auto-update cron
  - echo "0 3 * * * root cd /opt/shadow-warden && git pull && docker compose up -d --build" > /etc/cron.d/warden-update
