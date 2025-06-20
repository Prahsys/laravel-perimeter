#!/bin/bash
set -e

echo "Starting UFW raw installation..."

# Install UFW
echo "Installing UFW..."
apt-get update
apt-get install -y ufw

# Configure UFW with default rules
echo "Configuring UFW with default rules..."

# Reset UFW to default
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow basic ports
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp

# Copy monitoring script
echo "Installing UFW monitoring tools..."
cp /package/docker/bin/ufw-status /usr/local/bin/ufw-status
chmod +x /usr/local/bin/ufw-status

# Copy systemd service
echo "Configuring UFW systemd service..."
cp /package/docker/systemd/ufw/ufw.service /etc/systemd/system/ufw.service

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable ufw.service
systemctl start ufw.service

# Enable UFW
echo "Enabling UFW..."
ufw --force enable

# Verify installation
echo "Verifying UFW installation..."
if ufw status | grep -q "Status: active"; then
    echo "UFW installed and running successfully"
    ufw status
else
    echo "UFW installation failed. Check logs for details."
    exit 1
fi

echo "UFW raw installation completed successfully."