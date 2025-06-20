#!/bin/bash
set -e

echo "Starting ClamAV raw installation..."

# Create required directories
echo "Creating required directories..."
mkdir -p /var/run/clamav
chmod 755 /var/run/clamav
mkdir -p /var/lib/clamav
chmod 755 /var/lib/clamav
mkdir -p /var/log/clamav
chmod 755 /var/log/clamav

# Install ClamAV
echo "Installing ClamAV packages..."
apt-get update
apt-get install -y clamav clamav-daemon

# Copy configuration files from templates if they exist
echo "Configuring ClamAV..."
if [ -f /package/docker/config/clamav/clamd.conf ]; then
    cp /package/docker/config/clamav/clamd.conf /etc/clamav/clamd.conf
    echo "Copied clamd.conf from template"
fi

if [ -f /package/docker/config/clamav/freshclam.conf ]; then
    cp /package/docker/config/clamav/freshclam.conf /etc/clamav/freshclam.conf
    echo "Copied freshclam.conf from template"
fi

# Copy systemd service files
echo "Setting up systemd services..."
if [ -f /package/docker/systemd/clamav/clamav-daemon.service ]; then
    cp /package/docker/systemd/clamav/clamav-daemon.service /etc/systemd/system/clamav-daemon.service
    echo "Copied clamav-daemon systemd service"
fi

if [ -f /package/docker/systemd/clamav/clamav-freshclam.service ]; then
    cp /package/docker/systemd/clamav/clamav-freshclam.service /etc/systemd/system/clamav-freshclam.service
    echo "Copied clamav-freshclam systemd service"
fi

# Update virus database
echo "Updating virus database (this may take a while)..."
freshclam --quiet || echo "Warning: Initial database update failed, will retry on service start"

# Enable and start services
echo "Enabling and starting ClamAV services..."
systemctl daemon-reload
systemctl enable clamav-daemon
systemctl enable clamav-freshclam
systemctl start clamav-freshclam
systemctl start clamav-daemon

# Create symlinks for binary detection
echo "Creating binary symlinks for easier detection..."
ln -sf /usr/bin/clamdscan /usr/local/bin/clamdscan 2>/dev/null || true
ln -sf /usr/bin/clamscan /usr/local/bin/clamscan 2>/dev/null || true
ln -sf /usr/bin/freshclam /usr/local/bin/freshclam 2>/dev/null || true

# Verify installation
echo "Verifying ClamAV installation..."
if systemctl is-active --quiet clamav-daemon && systemctl is-active --quiet clamav-freshclam; then
    echo "ClamAV installed and running successfully"
    clamdscan --version
else
    echo "ClamAV installation failed or service not running."
    echo "Service status (clamav-daemon):"
    systemctl status clamav-daemon --no-pager
    echo "Service status (clamav-freshclam):"
    systemctl status clamav-freshclam --no-pager
    exit 1
fi

echo "ClamAV raw installation completed successfully."