#!/bin/bash
set -e

# Configuration parameters (these could be supplied as environment variables)
BANTIME=${BANTIME:-3600}
FINDTIME=${FINDTIME:-600}
MAXRETRY=${MAXRETRY:-5}
AUTH_LOG_PATH=${AUTH_LOG_PATH:-/var/log/auth/auth.log}

echo "Starting Fail2ban raw installation..."

# Install Fail2ban
apt-get update
apt-get install -y fail2ban

# Create required directories
mkdir -p /var/log/fail2ban
mkdir -p /var/log/auth
mkdir -p /var/run/fail2ban

# Create auth.log symlink if it doesn't exist
if [ ! -e /var/log/auth.log ]; then
    touch /var/log/auth/auth.log
    ln -sf /var/log/auth/auth.log /var/log/auth.log
fi

# Add sample log entry if auth.log is empty
if [ ! -s /var/log/auth/auth.log ]; then
    echo "$(date) localhost sshd[12345]: Failed password for invalid user baduser from 192.168.1.100 port 12345 ssh2" >> /var/log/auth/auth.log
fi

# Configure Fail2ban with improved configuration
echo "Configuring Fail2ban..."

# Create action.d directory if it doesn't exist
mkdir -p /etc/fail2ban/action.d

# Copy configuration files from our template directory
cp /package/docker/config/fail2ban/dummy.conf /etc/fail2ban/action.d/dummy.conf

# Process jail.local template with parameters
cat /package/docker/config/fail2ban/jail.local | \
    sed "s/bantime = 3600/bantime = $BANTIME/" | \
    sed "s/findtime = 600/findtime = $FINDTIME/" | \
    sed "s/maxretry = 5/maxretry = $MAXRETRY/" | \
    sed "s|logpath = /var/log/auth/auth.log|logpath = $AUTH_LOG_PATH|" \
    > /etc/fail2ban/jail.local

# Copy PHP-FPM filter
cp /package/docker/config/fail2ban/php-fpm.conf /etc/fail2ban/filter.d/php-fpm.conf

# Create banned.log file
touch /var/log/fail2ban/banned.log
chmod 644 /var/log/fail2ban/banned.log

# Copy monitoring script
cp /package/docker/bin/fail2ban-status /usr/local/bin/fail2ban-status
chmod +x /usr/local/bin/fail2ban-status

# Copy systemd service
cp /package/docker/systemd/fail2ban/fail2ban.service /etc/systemd/system/fail2ban.service

# Reload systemd to recognize new service file
systemctl daemon-reload

# Enable and start Fail2ban
systemctl enable fail2ban.service
systemctl start fail2ban.service

# Verify installation
echo "Verifying Fail2ban installation..."
if systemctl is-active --quiet fail2ban; then
    echo "Fail2ban installed and running successfully"
    echo "Status information:"
    fail2ban-client status
    echo "Run 'fail2ban-status --help' to see status options"
else
    echo "Fail2ban installation failed. Check logs for details."
    exit 1
fi

echo "Fail2ban raw installation completed successfully."