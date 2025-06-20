#!/bin/bash
set -e

echo "Starting Trivy raw installation..."

# Create required directories
mkdir -p /var/log/trivy
mkdir -p /var/log/trivy/.cache

# Create Trivy repo
echo "Creating Trivy repository configuration..."
echo "deb [trusted=yes] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list

# Install Trivy
echo "Installing Trivy..."
apt-get update
apt-get install -y trivy

# Copy systemd service files
echo "Configuring Trivy systemd services..."
cp /package/docker/systemd/trivy/trivy-db-update.service /etc/systemd/system/trivy-db-update.service
cp /package/docker/systemd/trivy/trivy-db-update.timer /etc/systemd/system/trivy-db-update.timer

# Copy scanning script
echo "Installing Trivy scanning utilities..."
cp /package/docker/bin/scan-vulnerabilities /usr/local/bin/scan-vulnerabilities
chmod +x /usr/local/bin/scan-vulnerabilities

# Enable and start service
echo "Enabling and starting Trivy database update service..."
systemctl daemon-reload
systemctl enable trivy-db-update.timer
systemctl start trivy-db-update.timer

# Initial database download
echo "Downloading vulnerability database (this may take a while)..."
trivy image --download-db-only

# Verify installation
echo "Verifying Trivy installation..."
if command -v trivy >/dev/null 2>&1; then
    echo "Trivy installed successfully"
    trivy --version
else
    echo "Trivy installation failed. Check logs for details."
    exit 1
fi

echo "Trivy raw installation completed successfully."