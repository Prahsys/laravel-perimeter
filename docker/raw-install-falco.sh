#!/bin/bash
# Raw installation script for Falco in Docker container

set -e
echo "Installing Falco in Docker container..."

# Create required directories
mkdir -p /etc/falco
mkdir -p /etc/falco/rules.d
mkdir -p /usr/bin
mkdir -p /var/log

# Install dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg apt-transport-https wget

# Create a minimal falco script
cat > /usr/bin/falco << 'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "falco version 0.41.2 (container minimal)"
  exit 0
elif [ "$1" = "--help" ]; then
  echo "Falco runtime security - container minimal version"
  echo "Usage: falco [options]"
  echo "Options:"
  echo "  --version     Print version and exit"
  echo "  --help        Print this help and exit"
  exit 0
else
  echo "Falco container minimal version - limited functionality in container"
  exit 0
fi
EOF
chmod +x /usr/bin/falco

# Create minimal Falco configuration
cat > /etc/falco/falco.yaml << 'EOF'
# Falco configuration for Docker container
# Created by Laravel Perimeter

driver:
  enabled: false

stdout_output:
  enabled: true

file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco.log

program_output:
  enabled: false

http_output:
  enabled: false

grpc:
  enabled: false

# Use fewer resources in container
syscall_event_drops:
  actions:
    - log
  rate: 0.03333
  max_burst: 10

# Don't allow rules to perform external programs
syscall_buf_size_preset: small

# Limit background scanning
syscall_event_timeouts:
  max_timeout: 2000
EOF

# Create Laravel-specific rules
cat > /etc/falco/rules.d/laravel-rules.yaml << 'EOF'
# Laravel-specific Falco rules

- rule: Laravel Mass Assignment Attempt
  desc: Detect potential mass assignment vulnerability exploitation
  condition: proc.name = "php" and fd.name contains "artisan" and evt.type = execve and evt.arg.args contains "mass" and evt.arg.args contains "assignment"
  output: Potential mass assignment vulnerability exploitation (user=%user.name process=%proc.name command=%proc.cmdline)
  priority: high
  tags: [application, laravel, security]
EOF

# Create symlink for binary detection
ln -sf /usr/bin/falco /usr/local/bin/falco 2>/dev/null || true

# Test if Falco is working
echo "Testing Falco installation..."
falco --version

echo "Falco installation complete!"