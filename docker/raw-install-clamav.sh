#!/bin/bash
# Raw installation script for ClamAV in Docker container
# Following the standard Ubuntu/Debian installation steps
# Designed to work with systemd in Docker

set -e
echo "Installing ClamAV in Docker container..."

# Step 1: Update repository
echo "Step 1: Updating package repositories..."
apt-get update

# Step 2: Install ClamAV and ClamAV daemon
echo "Step 2: Installing ClamAV and ClamAV daemon..."
apt-get install -y clamav clamav-daemon

# Step 3: Check installation
echo "Step 3: Verifying ClamAV installation..."
clamscan --version

# Step 4: Stop freshclam service to update virus database
echo "Step 4: Stopping freshclam service..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop clamav-freshclam
else
  # In Docker we might not have systemd
  pkill -f freshclam || true
fi

# Step 5: Update virus definitions
echo "Step 5: Updating virus definitions..."
freshclam

# Step 6: Enable and start freshclam service
echo "Step 6: Enabling and starting freshclam service..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable clamav-freshclam.service || true
  systemctl start clamav-freshclam.service || true
  
  # Also enable and start the clamav-daemon service
  systemctl enable clamav-daemon.service || true
  systemctl start clamav-daemon.service || true
  
  # Check status of services
  echo "ClamAV daemon status:"
  systemctl status clamav-daemon.service || true
  
  echo "ClamAV freshclam status:"
  systemctl status clamav-freshclam.service || true
fi

# Step 7: Create cron.daily script for regular scanning
echo "Step 7: Creating daily scan script..."
mkdir -p /etc/cron.daily
cat > /etc/cron.daily/clamav-scan << 'EOF'
#!/bin/bash
# Restart clamav daemon
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart clamav-daemon
fi

# Stop freshclam service
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop clamav-freshclam
fi

# Update database
freshclam

# Resume freshclam service
if command -v systemctl >/dev/null 2>&1; then
  systemctl start clamav-freshclam
fi

# Scan the home directory
clamscan --infected --recursive /var/www -l /var/log/clamav/clamscan.log
EOF
chmod +x /etc/cron.daily/clamav-scan

# Step 8: Install test files for verification (optional)
echo "Step 8: Testing with EICAR test file..."
mkdir -p /tmp/clamav-test
echo -e "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > /tmp/clamav-test/eicar.txt
echo "Scanning test file..."
clamscan /tmp/clamav-test/eicar.txt
rm -rf /tmp/clamav-test

echo "ClamAV installation completed successfully!"