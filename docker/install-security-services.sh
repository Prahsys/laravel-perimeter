#!/bin/bash
set -e

# Create directories needed for security services
mkdir -p /var/run/clamav
chmod 755 /var/run/clamav
mkdir -p /etc/clamav
mkdir -p /var/lib/clamav
mkdir -p /var/log/clamav
mkdir -p /etc/falco
mkdir -p /etc/falco/rules.d
mkdir -p /usr/bin
mkdir -p /root/.cache/trivy/db
mkdir -p /root/.trivy

# Copy configuration files from the Docker config directory
echo "Copying ClamAV configuration files..."
cp /package/docker/config/clamav/clamd.conf /etc/clamav/clamd.conf
cp /package/docker/config/clamav/freshclam.conf /etc/clamav/freshclam.conf

echo "Copying Falco configuration files..."
cp /package/docker/config/falco/falco.yaml /etc/falco/falco.yaml
cp /package/docker/config/falco/laravel-rules.yaml /etc/falco/rules.d/laravel-rules.yaml

echo "Copying Trivy configuration files..."
cp /package/docker/config/trivy/config.json /root/.trivy/config.json

# Create stub files for ClamAV
echo "Creating ClamAV stub files..."
touch /var/log/clamav/clamav.log
chmod 644 /var/log/clamav/clamav.log
touch /var/lib/clamav/main.cvd
touch /var/lib/clamav/daily.cvd
touch /var/lib/clamav/bytecode.cvd
chmod 755 /var/lib/clamav
chmod 644 /var/lib/clamav/*.cvd

# Create ClamAV binaries
cat > /usr/bin/clamscan << 'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.0.0/stub"
  exit 0
elif [ "$1" = "--help" ]; then
  echo "ClamAV stub scanner - enables perimeter scanning"
  exit 0
else
  echo "Scanning $* ..."
  echo "----------- SCAN SUMMARY -----------"
  echo "Infected files: 0"
  echo "Time: 0.001 sec (0 m 0 s)"
  exit 0
fi
EOF
chmod +x /usr/bin/clamscan

cat > /usr/bin/freshclam << 'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "ClamAV 1.0.0/stub"
  exit 0
elif [ "$1" = "--help" ]; then
  echo "ClamAV stub database updater"
  exit 0
else
  echo "Database updated."
  exit 0
fi
EOF
chmod +x /usr/bin/freshclam

ln -sf /usr/bin/clamscan /usr/bin/clamdscan

# Create Falco binary
echo "Creating Falco stub binary..."
cat > /usr/bin/falco << 'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "falco version 0.41.2 (container stub)"
  exit 0
elif [ "$1" = "--help" ]; then
  echo "Falco stub - enables perimeter security monitoring"
  exit 0
else
  echo "Falco stub - command not supported in container environment"
  exit 0
fi
EOF
chmod +x /usr/bin/falco

# Create Trivy stub
echo "Creating Trivy stub..."
cat > /usr/bin/trivy << 'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Version: 0.63.0 (container stub)"
  exit 0
elif [ "$1" = "--help" ]; then
  echo "Trivy stub - vulnerability scanning"
  exit 0
else
  echo "{\"SchemaVersion\": 2, \"Results\": []}"
  exit 0
fi
EOF
chmod +x /usr/bin/trivy
touch /root/.cache/trivy/db/trivy.db

# Create symlinks
ln -sf /usr/bin/clamdscan /usr/local/bin/clamdscan 2>/dev/null || true
ln -sf /usr/bin/clamscan /usr/local/bin/clamscan 2>/dev/null || true
ln -sf /usr/bin/freshclam /usr/local/bin/freshclam 2>/dev/null || true
ln -sf /usr/bin/falco /usr/local/bin/falco 2>/dev/null || true
ln -sf /usr/bin/trivy /usr/local/bin/trivy 2>/dev/null || true

# Setup environment variables
echo "export TMPDIR=/tmp" >> /etc/environment
echo "export TRIVY_QUIET=true" >> /etc/environment

echo "Security service stubs installed successfully"