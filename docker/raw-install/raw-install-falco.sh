#!/bin/bash
set -e

echo "Starting Falco raw installation..."

# Create required directories
echo "Creating required directories..."
mkdir -p /var/run/falco
mkdir -p /var/log/falco
mkdir -p /etc/falco/rules.d
mkdir -p /etc/falco

# Create Falco repository configuration
echo "Configuring Falco repository..."
if [ ! -f /etc/apt/sources.list.d/falcosecurity.list ]; then
    echo "deb [trusted=yes] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
fi

# Install Falco
echo "Installing Falco..."
apt-get update
apt-get install -y falco

# Copy configuration files
echo "Configuring Falco..."
if [ -f /package/docker/config/falco/falco.yaml ]; then
    cp /package/docker/config/falco/falco.yaml /etc/falco/falco.yaml
fi

if [ -f /package/docker/config/falco/falco_rules.local.yaml ]; then
    cp /package/docker/config/falco/falco_rules.local.yaml /etc/falco/falco_rules.local.yaml
fi

if [ -f /package/docker/config/falco/laravel-rules.yaml ]; then
    cp /package/docker/config/falco/laravel-rules.yaml /etc/falco/rules.d/laravel-rules.yaml
fi

# Copy status script
echo "Installing Falco monitoring tools..."
if [ -f /package/docker/bin/falco-status ]; then
    cp /package/docker/bin/falco-status /usr/local/bin/falco-status
    chmod +x /usr/local/bin/falco-status
fi

# Copy systemd service
echo "Setting up systemd service..."
if [ -f /package/docker/systemd/falco/falco.service ]; then
    cp /package/docker/systemd/falco/falco.service /etc/systemd/system/falco.service
fi

# Enable and start Falco
echo "Enabling and starting Falco service..."
systemctl daemon-reload
systemctl enable falco.service
systemctl start falco.service

# Verify installation
echo "Verifying Falco installation..."
if systemctl is-active --quiet falco.service; then
    echo "Falco installed and running successfully"
    if command -v falco-status >/dev/null 2>&1; then
        echo "Status information:"
        falco-status
    fi
else
    echo "Falco installation failed or service not running."
    echo "Service status:"
    systemctl status falco.service --no-pager
    exit 1
fi

echo "Falco raw installation completed successfully."