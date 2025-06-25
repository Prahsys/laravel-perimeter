<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\FirewallServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Parsers\UfwOutputParser;
use Symfony\Component\Process\Process;

class UfwService extends AbstractSecurityService implements FirewallServiceInterface
{
    /**
     * Create a new UFW service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        //
    }

    /**
     * Check if the service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Check if the service is installed on the system.
     */
    public function isInstalled(): bool
    {
        // Check if ufw command is available
        $process = new Process(['which', 'ufw']);
        $process->run();

        if ($process->isSuccessful()) {
            return true;
        }

        // Check in common locations
        $ufwPaths = [
            '/usr/sbin/ufw',
            '/sbin/ufw',
            '/bin/ufw',
            '/usr/bin/ufw',
        ];

        foreach ($ufwPaths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the service is properly configured.
     */
    public function isConfigured(): bool
    {
        if (! $this->isInstalled()) {
            return false;
        }

        // Check if UFW configuration exists by looking at config files
        // This avoids requiring root privileges for status checks
        $configPaths = [
            '/etc/ufw/ufw.conf',
            '/lib/ufw/ufw-init',
            '/etc/default/ufw',
        ];

        $hasConfig = false;
        foreach ($configPaths as $path) {
            if (file_exists($path) && is_readable($path)) {
                $hasConfig = true;
                break;
            }
        }

        if (! $hasConfig) {
            return false;
        }

        // Check if UFW is enabled by reading the configuration file
        $ufwConfPath = '/etc/ufw/ufw.conf';
        if (file_exists($ufwConfPath) && is_readable($ufwConfPath)) {
            $content = file_get_contents($ufwConfPath);

            // Look for ENABLED=yes in the config file
            if (preg_match('/ENABLED\s*=\s*yes/i', $content)) {
                return true;
            }
        }

        // Fallback: try to run ufw status if we have sufficient privileges
        // but don't fail if we can't (this maintains backward compatibility)
        try {
            $process = new Process(['ufw', 'status']);
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();

                return strpos($output, 'Status: active') !== false;
            }
        } catch (\Exception $e) {
            // If we can't run the command, that's okay - we'll rely on file-based checks
            Log::debug('Cannot run ufw status command, using file-based configuration check: '.$e->getMessage());
        }

        // If we have config files but UFW is not enabled, consider it configured but inactive
        // This distinguishes between "not installed" and "installed but disabled"
        return $hasConfig;
    }

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool
    {
        Log::info('Installing UFW with minimal configuration');

        // Check if already installed and not forcing reinstall
        if ($this->isInstalled() && ! ($options['force'] ?? false)) {
            Log::info('UFW is already installed');

            // If already installed but not enabled, enable it
            if (! $this->isConfigured() && ($options['start'] ?? true)) {
                try {
                    return $this->enable();
                } catch (\Exception $e) {
                    Log::warning('Failed to enable UFW (non-critical): '.$e->getMessage());

                    return true; // Still consider installation successful
                }
            }

            return true;
        }

        // Store force flag if provided
        if ($options['force'] ?? false) {
            $this->config['force'] = true;
        }

        // Critical step: Install UFW package
        try {
            Log::info('Installing UFW package');
            $process = new Process(['apt-get', 'update']);
            $process->setTimeout(300);
            $process->run();

            $process = new Process(['apt-get', 'install', '-y', 'ufw']);
            $process->setTimeout(300);
            $process->run();

            if (! $process->isSuccessful()) {
                Log::error('Failed to install UFW package - this is a critical failure: '.$process->getErrorOutput());

                return false;
            }
        } catch (\Exception $e) {
            Log::error('Critical failure installing UFW package: '.$e->getMessage());

            return false;
        }

        // Optional steps: Don't fail installation if these have issues
        try {
            // Configure UFW with default rules
            Log::info('Configuring UFW with default rules');

            // Reset UFW to default
            $process = new Process(['ufw', '--force', 'reset']);
            $process->run();

            // Set default policies
            $process = new Process(['ufw', 'default', 'deny', 'incoming']);
            $process->run();

            $process = new Process(['ufw', 'default', 'allow', 'outgoing']);
            $process->run();

            // Allow basic ports
            $this->allowPort('ssh');
            $this->allowPort('80/tcp');
            $this->allowPort('443/tcp');
        } catch (\Exception $e) {
            Log::warning('Failed to configure UFW rules (non-critical): '.$e->getMessage());
        }

        try {
            // Copy monitoring script
            $this->copyMonitoringScript();
        } catch (\Exception $e) {
            Log::warning('Failed to copy monitoring script (non-critical): '.$e->getMessage());
        }

        try {
            // Copy systemd service
            $this->copySystemdService();
        } catch (\Exception $e) {
            Log::warning('Failed to copy systemd service (non-critical): '.$e->getMessage());
        }

        try {
            // Enable and start service
            Log::info('Enabling and starting UFW service');
            $process = new Process(['systemctl', 'daemon-reload']);
            $process->run();

            $process = new Process(['systemctl', 'enable', 'ufw.service']);
            $process->run();

            $process = new Process(['systemctl', 'start', 'ufw.service']);
            $process->run();
        } catch (\Exception $e) {
            Log::warning('Failed to enable/start systemd service (non-critical): '.$e->getMessage());
        }

        // Optional: Enable UFW if specified
        if ($options['start'] ?? true) {
            try {
                $this->enable();
            } catch (\Exception $e) {
                Log::warning('Failed to enable UFW (non-critical): '.$e->getMessage());
            }
        }

        // Final verification: Check if UFW is actually installed
        if ($this->isInstalled()) {
            Log::info('UFW installation completed successfully');

            return true;
        } else {
            Log::error('UFW installation verification failed - package not detected');

            return false;
        }
    }

    /**
     * Allow a specific port in UFW
     */
    protected function allowPort(string $port): void
    {
        Log::info("Allowing port: $port");
        $process = new Process(['ufw', 'allow', $port]);
        $process->run();
    }

    /**
     * Copy monitoring script
     */
    protected function copyMonitoringScript(): void
    {
        Log::info('Copying UFW monitoring script');

        // Find script in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/bin',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/bin'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/bin'),
        ];

        // Copy script if it exists in template locations
        foreach ($locations as $location) {
            if (file_exists($location.'/ufw-status')) {
                Log::info("Copying UFW status script from $location");
                copy($location.'/ufw-status', '/usr/local/bin/ufw-status');
                chmod('/usr/local/bin/ufw-status', 0755);
                break;
            }
        }
    }

    /**
     * Copy systemd service file
     */
    protected function copySystemdService(): void
    {
        Log::info('Copying UFW systemd service file');

        // Find service file in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/systemd/ufw',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/systemd/ufw'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/systemd/ufw'),
        ];

        // Copy service file if it exists in template locations
        foreach ($locations as $location) {
            if (file_exists($location.'/ufw.service')) {
                Log::info("Copying UFW service from $location");
                copy($location.'/ufw.service', '/etc/systemd/system/ufw.service');
                break;
            }
        }
    }

    /**
     * Enable UFW without default rules.
     */
    protected function enable(): bool
    {
        try {
            // Enable UFW with system defaults
            $process = new Process(['ufw', '--force', 'enable']);
            $process->run();

            if (! $process->isSuccessful()) {
                Log::error('Failed to enable UFW: '.$process->getErrorOutput());

                return false;
            }

            Log::info('UFW enabled successfully');

            return true;
        } catch (\Exception $e) {
            Log::error('Error enabling UFW: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Add default rules to UFW.
     */
    protected function addDefaultRules(): void
    {
        // No default rules are added - we let the user explicitly configure ports
        Log::info('No default UFW rules added - users must add rules explicitly');
    }

    /**
     * Start monitoring with the service.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool
    {
        // UFW monitoring is always on when enabled
        if (! $this->isEnabled() || ! $this->isConfigured()) {
            return false;
        }

        return true;
    }

    /**
     * Stop monitoring with the service.
     */
    public function stopMonitoring(): bool
    {
        // UFW doesn't have a concept of stopping monitoring without disabling
        return true;
    }

    /**
     * Get recent security events from the service.
     */
    public function getRecentEvents(int $limit = 10): array
    {
        if (! $this->isEnabled() || ! $this->isConfigured()) {
            return [];
        }

        // Get events from UFW log
        $logPath = $this->config['log_path'] ?? '/var/log/ufw.log';

        if (! file_exists($logPath) || ! is_readable($logPath)) {
            Log::warning('UFW log file not found or not readable: '.$logPath);

            return [];
        }

        $process = new Process(['bash', '-c', 'tail -n '.($limit * 3).' '.escapeshellarg($logPath)]);
        $process->run();

        if (! $process->isSuccessful()) {
            Log::warning('Failed to read UFW log: '.$process->getErrorOutput());

            return [];
        }

        $output = $process->getOutput();

        return UfwOutputParser::parseLogEvents($output, $limit);
    }

    /**
     * Check for port access issues based on configured expected/public/restricted ports.
     *
     * @return array Port check results with any issues found
     */
    public function checkPorts(): array
    {
        // Get port configuration
        $expectedPorts = $this->config['expected_ports'] ?? [];
        $publicPorts = $this->config['public_ports'] ?? [];
        $restrictedPortsConfig = $this->config['restricted_ports'] ?? [];

        // Convert to arrays if they're not already
        if (! is_array($expectedPorts)) {
            $expectedPorts = explode('|', $expectedPorts);
        }
        if (! is_array($publicPorts)) {
            $publicPorts = explode('|', $publicPorts);
        }
        if (! is_array($restrictedPortsConfig)) {
            $restrictedPortsConfig = explode('|', $restrictedPortsConfig);
        }

        // Filter out empty values
        $expectedPorts = array_filter($expectedPorts);
        $publicPorts = array_filter($publicPorts);
        $restrictedPortsConfig = array_filter($restrictedPortsConfig);

        // Check port accessibility
        $accessiblePorts = [];     // Ports open to external connections
        $restrictedPorts = [];     // Ports only open to localhost/internal
        $unexpectedPorts = [];     // Ports not in any expected list
        $missingPublicPorts = [];  // Public ports that should be open but aren't
        $exposedPrivatePorts = []; // Restricted ports that shouldn't be publicly accessible

        // Check for open ports
        $cmd = "ss -tuln | grep LISTEN | awk '{print \$5}' | sed 's/.*://' | sort -u";
        $process = new Process(['bash', '-c', $cmd]);
        $process->run();

        if ($process->isSuccessful()) {
            $openPorts = array_filter(explode("\n", trim($process->getOutput())));

            foreach ($openPorts as $port) {
                // Check if port is listening only on localhost or externally
                $cmd = "ss -tuln | grep \":$port\" | grep -v '127.0.0.1\\|::1'";
                $process = new Process(['bash', '-c', $cmd]);
                $process->run();

                $isExternallyAccessible = $process->isSuccessful() && ! empty(trim($process->getOutput()));

                if ($isExternallyAccessible) {
                    $accessiblePorts[] = $port;

                    // Check if this should be a restricted port
                    if (in_array($port, $restrictedPortsConfig)) {
                        $exposedPrivatePorts[] = $port;
                    }

                    // Check if this is an unexpected port
                    if (! empty($expectedPorts) && ! in_array($port, $expectedPorts)) {
                        $unexpectedPorts[] = $port;
                    }
                } else {
                    $restrictedPorts[] = $port;

                    // Check if this should be a public port
                    if (in_array($port, $publicPorts)) {
                        $missingPublicPorts[] = $port;
                    }
                }
            }
        }

        // Check if any public ports are missing entirely (only if public ports are configured)
        if (! empty($publicPorts)) {
            foreach ($publicPorts as $port) {
                if (! in_array($port, $accessiblePorts) && ! in_array($port, $restrictedPorts)) {
                    $missingPublicPorts[] = $port;
                }
            }
        }

        // Analyze port status
        $portIssues = [];

        // Check for ports that should be public but aren't
        if (! empty($publicPorts)) {
            foreach ($missingPublicPorts as $port) {
                $portIssues[] = "Port $port should be externally accessible but appears to be restricted or not listening";
            }
        }

        // Check for unexpected open ports
        if (! empty($expectedPorts)) {
            foreach ($unexpectedPorts as $port) {
                $portIssues[] = "Port $port is externally accessible but not in the expected ports list";
            }
        }

        // Check for private ports that are exposed
        if (! empty($restrictedPortsConfig)) {
            foreach ($exposedPrivatePorts as $port) {
                $portIssues[] = "Port $port should be restricted but is externally accessible";
            }
        }

        return [
            'issues' => $portIssues,
            'accessible_ports' => $accessiblePorts,
            'restricted_ports' => $restrictedPorts,
            'unexpected_ports' => $unexpectedPorts,
            'missing_public_ports' => $missingPublicPorts,
            'exposed_private_ports' => $exposedPrivatePorts,
            'expected_ports_config' => $expectedPorts,
            'public_ports_config' => $publicPorts,
            'restricted_ports_config' => $restrictedPortsConfig,
        ];
    }

    /**
     * Get the current UFW status.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $enabled = $this->isEnabled();
        $installed = $this->isInstalled();
        $configured = $this->isConfigured();
        $running = $configured;

        $rules = [];
        $defaultPolicy = 'unknown';
        $message = '';

        // Determine running status by checking config file first
        $running = $this->isUfwActiveViaConfig();

        if (! $enabled) {
            $message = 'UFW is disabled in Perimeter configuration';
        } elseif (! $installed) {
            $message = 'UFW is not installed on the system';
        } elseif (! $configured) {
            $message = 'UFW is installed but configuration files are not accessible';
        } else {
            // Try to get detailed status from UFW if we have privileges
            $statusResult = $this->getUfwStatusSafely();

            if ($statusResult['success']) {
                $ufwStatus = UfwOutputParser::parseStatusOutput($statusResult['output']);
                $rules = $ufwStatus['rules'] ?? [];
                $defaultPolicy = $ufwStatus['default_policy'] ?? 'unknown';
                $running = $ufwStatus['active'] ?? $running; // Use command result if available

                // Create descriptive message
                if ($running) {
                    $message = 'UFW is active and configured properly';
                    if (empty($rules)) {
                        $message .= ' but no specific rules are defined';
                    } else {
                        $message .= ' with '.count($rules).' rule(s) defined';
                    }
                } else {
                    $message = 'UFW is installed but not active';
                }
            } else {
                // Fallback to file-based status when we can't run commands
                if ($running) {
                    $message = 'UFW is configured and enabled (based on configuration files)';
                } else {
                    $message = 'UFW is installed but not active';
                }

                // Add note about permission limitation
                if (strpos($statusResult['error'], 'root') !== false) {
                    $message .= '. Run as root for detailed status.';
                }
            }
        }

        $expectedPorts = $this->config['expected_ports'] ?? [];
        $publicPorts = $this->config['public_ports'] ?? [];
        $restrictedPorts = $this->config['restricted_ports'] ?? [];

        // Build details array with firewall-specific information
        $details = [
            'rules' => $rules,
            'default_policy' => $defaultPolicy,
            'expected_ports' => $expectedPorts,
            'public_ports' => $publicPorts,
            'restricted_ports' => $restrictedPorts,
        ];

        // UFW can be functional even when not actively enabled (firewall is optional)
        // Consider it functional if installed and package is enabled
        $functional = $enabled && $installed;

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'ufw',
            enabled: $enabled,
            installed: $installed,
            configured: $configured,
            running: $running,
            message: $message,
            details: $details,
            functional: $functional
        );
    }

    /**
     * Reset UFW to default configuration.
     */
    public function reset(): bool
    {
        if (! $this->isInstalled()) {
            return false;
        }

        $process = new Process(['ufw', '--force', 'reset']);
        $process->run();

        if (! $process->isSuccessful()) {
            Log::error('Failed to reset UFW: '.$process->getErrorOutput());

            return false;
        }

        Log::info('UFW reset successfully');

        // Enable UFW with no default rules
        return $this->enable();
    }

    /**
     * Get the current configuration.
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Set the configuration.
     */
    public function setConfig(array $config): void
    {
        $this->config = $config;
    }

    /**
     * Run service-specific audit checks.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @return array Array of SecurityEventData objects
     */
    protected function performServiceSpecificAuditChecks($output = null): array
    {
        // Build the issues array using SecurityEventData
        $issues = [];
        $firewallActive = $this->isInstalled() && $this->isConfigured();

        if (! $firewallActive) {
            $issues[] = new SecurityEventData(
                timestamp: now(),
                type: 'firewall',
                severity: 'high',
                description: 'No active firewall detected',
                location: 'system',
                user: null,
                details: [
                    'firewall_active' => false,
                    'recommendation' => 'Enable UFW using "ufw enable" or use the installer',
                ]
            );
        }

        // If we have an output and the firewall is active, show more details
        if ($output && $firewallActive) {
            // For MVP, just show a simple status message
            $output->writeln('  ⚪ Firewall is active and running');

            // Get basic port info for externally accessible ports
            $process = new Process(['bash', '-c', "ss -tuln | grep LISTEN | awk '{print \$5}' | sed 's/.*://' | sort -u"]);
            $process->run();

            if ($process->isSuccessful() && ! empty(trim($process->getOutput()))) {
                $openPorts = array_filter(explode("\n", trim($process->getOutput())));
                if (! empty($openPorts)) {
                    $output->writeln('  ⚪ Open ports: '.implode(', ', $openPorts));
                }
            }
        }

        return $issues;
    }

    /**
     * Check if UFW is active by reading configuration files (non-privileged)
     */
    protected function isUfwActiveViaConfig(): bool
    {
        $ufwConfPath = '/etc/ufw/ufw.conf';
        if (file_exists($ufwConfPath) && is_readable($ufwConfPath)) {
            $content = file_get_contents($ufwConfPath);

            return preg_match('/ENABLED\s*=\s*yes/i', $content) === 1;
        }

        return false;
    }

    /**
     * Safely get UFW status without requiring root privileges
     */
    protected function getUfwStatusSafely(): array
    {
        try {
            $process = new Process(['ufw', 'status', 'verbose']);
            $process->run();

            if ($process->isSuccessful()) {
                return [
                    'success' => true,
                    'output' => $process->getOutput(),
                    'error' => null,
                ];
            } else {
                return [
                    'success' => false,
                    'output' => '',
                    'error' => $process->getErrorOutput(),
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'output' => '',
                'error' => $e->getMessage(),
            ];
        }
    }
}
