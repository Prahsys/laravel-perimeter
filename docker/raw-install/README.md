# Raw Installation Scripts

These scripts are **reference implementations** for installing and configuring the security components used by Laravel Perimeter.

## Important Usage Notes

1. **DO NOT call these scripts directly from Laravel Perimeter service installers.**
2. These scripts should be used to establish the working procedure for installing a component, then that procedure should be replicated in the PHP service code.
3. The raw-install scripts are primarily used for testing and development, especially in Docker environments.

## Purpose

- Provide clear, working examples of how to install each security component
- Establish baseline configuration with working defaults
- Centralize external configuration files
- Document the steps needed for proper installation

## Integration with Service Classes

The proper approach for the Laravel Perimeter package:

1. Study these scripts to understand the installation process
2. Implement the same procedures in the corresponding PHP service class's `install()` method
3. Use the service class to handle installation, not these shell scripts

Example (recommended approach):

```php
// In ClamAVService.php
public function install(array $options = []): bool
{
    // Install packages
    $this->executeCommand('apt-get update');
    $this->executeCommand('apt-get install -y clamav clamav-daemon');
    
    // Create directories
    $this->executeCommand('mkdir -p /var/run/clamav');
    
    // Configure files
    $this->modifyConfigFile('/etc/clamav/clamd.conf', [
        's/^#TCPSocket/TCPSocket/',
        's/^#Foreground/Foreground/'
    ]);
    
    // Copy configuration files from our templates
    // ...
    
    return true;
}
```

## Available Scripts

- `raw-install-clamav.sh`: Anti-virus installation
- `raw-install-fail2ban.sh`: Intrusion prevention installation
- `raw-install-falco.sh`: Runtime security monitoring installation
- `raw-install-trivy.sh`: Vulnerability scanner installation
- `raw-install-ufw.sh`: Firewall installation

Each script provides a complete, working installation of its respective component, configured to work properly in container environments.