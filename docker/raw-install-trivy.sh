#!/bin/bash
# Raw installation script for Trivy in Docker container

set -e
echo "Installing Trivy in Docker container..."

# Install dependencies
apt-get update
apt-get install -y --no-install-recommends wget apt-transport-https gnupg ca-certificates

# Add Trivy repository
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb bullseye main" > /etc/apt/sources.list.d/trivy.list

# Set memory constraints for apt
echo "APT::Install-Recommends \"false\";" > /etc/apt/apt.conf.d/99-trivy-no-recommends
echo "APT::Install-Suggests \"false\";" >> /etc/apt/apt.conf.d/99-trivy-no-recommends

# Install Trivy
apt-get update
apt-get install -y --no-install-recommends trivy

# Create configuration directories
mkdir -p /root/.trivy /root/.cache/trivy/db

# Create minimal config file to save memory
cat > /root/.trivy/config.json << 'EOF'
{
  "cache": {
    "dir": "/root/.cache/trivy/db"
  },
  "db": {
    "no-update": true
  },
  "parallel": 1,
  "timeout": 300,
  "skip-files": [
    "node_modules",
    "vendor",
    ".git"
  ],
  "quiet": true
}
EOF

# Create placeholder DB file
touch /root/.cache/trivy/db/trivy.db

# Set environment variables for memory management
echo "export TMPDIR=/tmp" >> /etc/environment
echo "export TRIVY_QUIET=true" >> /etc/environment
echo "export TRIVY_NO_PROGRESS=true" >> /etc/environment
echo "export TRIVY_IGNOREFILE=/root/.trivyignore" >> /etc/environment
touch /root/.trivyignore

# Test if Trivy is working
echo "Testing Trivy installation..."
trivy --version

echo "Trivy installation complete!"