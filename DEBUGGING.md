# Debugging Guide

This guide provides information on debugging both PHP code and security services in the Docker environment.

## Debugging Security Services

The Docker environment uses systemd to manage security services like ClamAV, Falco, Fail2ban, Trivy and UFW. Here's how to debug these services:

### 1. Checking Service Status

To check if a service is running properly:

```bash
# Check all systemd services
docker-compose exec app systemctl list-units --type=service

# Check status of specific services
docker-compose exec app systemctl status fail2ban
docker-compose exec app systemctl status falco-modern-bpf
docker-compose exec app systemctl status clamav-daemon
docker-compose exec app systemctl status ufw

# Check if a process is running
docker-compose exec app ps aux | grep clamd
docker-compose exec app ps aux | grep fail2ban
docker-compose exec app ps aux | grep falco
```

### 2. Viewing Service Logs

To view the logs of a service:

```bash
# View systemd journal logs for services
docker-compose exec app journalctl -u fail2ban
docker-compose exec app journalctl -u falco-modern-bpf
docker-compose exec app journalctl -u clamav-daemon
docker-compose exec app journalctl -u ufw

# Follow logs in real-time
docker-compose exec app journalctl -f -u falco-modern-bpf

# View service-specific log files
docker-compose exec app cat /var/log/clamav/freshclam.log
docker-compose exec app cat /var/log/fail2ban/fail2ban.log
docker-compose exec app cat /var/log/falco/falco.log
docker-compose exec app cat /var/log/trivy/trivy.log

# View last entries with timestamps
docker-compose exec app journalctl -u fail2ban --no-pager -n 20
```

### 3. Debugging Service Startup Issues

If a service fails to start:

```bash
# Check systemd logs for failed services
docker-compose exec app systemctl --failed

# Check specific service status with detailed information
docker-compose exec app systemctl status fail2ban -l
docker-compose exec app systemctl status falco-modern-bpf -l
docker-compose exec app systemctl status clamav-daemon -l

# Check service logs during startup
docker-compose exec app journalctl -u fail2ban -b

# Check for configuration errors (example for Fail2ban)
docker-compose exec app fail2ban-client -t
```

### 4. Restarting Services

To restart a service:

```bash
# Restart a service using systemd
docker-compose exec app systemctl restart fail2ban
docker-compose exec app systemctl restart falco-modern-bpf
docker-compose exec app systemctl restart clamav-daemon
docker-compose exec app systemctl restart ufw

# Stop and then start a service
docker-compose exec app systemctl stop fail2ban
docker-compose exec app systemctl start fail2ban
```

### 5. Checking Service Configuration

To inspect service configurations:

```bash
# Check systemd service definitions
docker-compose exec app systemctl cat fail2ban.service
docker-compose exec app systemctl cat falco-modern-bpf.service
docker-compose exec app systemctl cat clamav-daemon.service

# Check security tool configurations
docker-compose exec app cat /etc/clamav/clamd.conf
docker-compose exec app cat /etc/fail2ban/jail.local
docker-compose exec app cat /etc/falco/falco_rules.local.yaml
docker-compose exec app cat /etc/ufw/ufw.conf

# List service dependencies
docker-compose exec app systemctl list-dependencies fail2ban.service
```

### 6. Using Service-Specific Status Tools

Each security service has its own status commands:

```bash
# Fail2ban status
docker-compose exec app fail2ban-status
docker-compose exec app fail2ban-status --json

# Falco status
docker-compose exec app falco-status
docker-compose exec app falco-status --events
docker-compose exec app falco-status --rules

# Trivy scanning status
docker-compose exec app scan-vulnerabilities --help

# UFW status
docker-compose exec app ufw-status
docker-compose exec app ufw-status --json
```

## Debugging PHP with PhpStorm

The Docker environment for this package includes Xdebug, which allows you to debug PHP code using PhpStorm.

## Setting Up PhpStorm for Debugging

You'll need to manually configure PhpStorm with the following settings:

### 1. Configure Xdebug Settings

1. Go to **Preferences/Settings** → **PHP** → **Debug**
   - Set Debug port to `9003` (default for Xdebug 3)
   - Check "Can accept external connections"
   - Make sure Xdebug is selected as the debugger

### 2. Create a Server Configuration

1. Go to **Preferences/Settings** → **PHP** → **Servers**
   - Click the `+` icon to add a new server
   - Set Name to `prahsys-laravel-perimeter` (must match the value in PHP_IDE_CONFIG)
   - Set Host to `localhost` 
   - Set Port to `8000`
   - Check "Use path mappings"
   - Set up path mappings:
     - Map your local project root directory to `/package` in the container
     - Map your local vendor directory to `/var/www/laravel-app/vendor/prahsys/perimeter/vendor`

> **Important**: The server name MUST match the value set in PHP_IDE_CONFIG in docker-compose.yml

It should look something like this (adjust paths for your system):

```
Server Name: prahsys-laravel-perimeter
Host: localhost
Port: 8000
Debugger: Xdebug
Use path mappings: ✓

Path mappings:
/Users/stephen/Herd/prahsys-gateway/packages/prahsys-laravel-perimeter → /package
/Users/stephen/Herd/prahsys-gateway/packages/prahsys-laravel-perimeter/vendor → /var/www/laravel-app/vendor/prahsys/perimeter/vendor
```

**Why this configuration works**:
- The Docker container is configured with Xdebug that connects back to your host machine
- The server name in PhpStorm must match the `PHP_IDE_CONFIG` environment variable for PhpStorm to recognize the connection
- Path mappings tell PhpStorm how to translate file paths between your local system and the Docker container
- When a breakpoint is hit, PhpStorm uses these mappings to show you the right file

### 3. Create a PHP Remote Debug Configuration

1. Go to **Run** → **Edit Configurations**
2. Click the `+` icon and select **PHP Remote Debug**
3. Set Name to `Perimeter Debug`
4. Set Server to the server you created above (`prahsys-laravel-perimeter`)
5. Set IDE key to `PHPSTORM`
6. Click "OK" to save the configuration

## Start Debugging

1. **Start the Docker environment**:
   ```bash
   docker-compose up -d
   ```

2. **Set Breakpoints** in your PHP code where you want execution to pause

3. **Start Listening for Debug Connections**:
   - Click the "Start Listening for PHP Debug Connections" button (telephone icon) in the toolbar
   - Or, select the "Perimeter Debug" run configuration and click the Debug button

4. **Run Commands with Debugging**:
   Run your PHP commands normally - Xdebug is always enabled in the Docker container:
   
   ```bash
   # Any artisan command
   docker-compose exec app php artisan perimeter:audit
   
   # Or any PHP script
   docker-compose exec app php your-script.php
   ```

5. **Debug Session Starts**:
   - When your code hits a breakpoint, PhpStorm will switch to debug mode
   - You can inspect variables, step through code, and evaluate expressions
   - Use the debug controls to continue, step over, or step into functions

## Troubleshooting

If you're having issues with debugging:

1. **Verify Xdebug is installed and working**:
   ```bash
   # Check if Xdebug is installed
   docker-compose exec app php -i | grep xdebug
   
   # Verify the container can reach your host machine
   docker-compose exec app ping host.docker.internal
   
   # Check the Xdebug log for connection attempts
   docker-compose exec app cat /var/log/xdebug.log
   ```

2. **Validate your PhpStorm configuration**:
   - Make sure the "Start Listening for PHP Debug Connections" button is active (green phone icon)
   - Double-check your server name and path mappings in PhpStorm
   - Ensure no firewall is blocking the debug connection on port 9003

3. **Common Issues and Solutions**:
   
   - **Breakpoints Not Triggering**: 
     - Ensure path mappings are correct
     - Check if the file you're debugging is being loaded
     - Verify breakpoints have a red dot (not a hollow circle)
   
   - **Connection Refused**: 
     - Check that PhpStorm is listening for connections
     - Try restarting PhpStorm
     - Make sure no other service is using port 9003
   
   - **"Cannot Find Files" or "Source not found"**: 
     - Your path mappings are likely incorrect
     - Ensure the local path → container path mapping is correctly configured
   
   - **Performance Issues**: 
     - Xdebug slows down PHP execution
     - This is normal and expected during debugging sessions

4. **Rebuild the Docker image if needed**:
   ```bash
   # If you've made changes to the Dockerfile
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```