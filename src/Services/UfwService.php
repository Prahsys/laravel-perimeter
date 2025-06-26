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
            // Set up sudo permissions for UFW status commands
            $this->setupSudoPermissions();
        } catch (\Exception $e) {
            Log::warning('Failed to setup sudo permissions (non-critical): '.$e->getMessage());
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
     * Check for port access issues based on configured public/restricted ports.
     *
     * @return array Port check results with any issues found
     */
    public function checkPorts(): array
    {
        // Get port configuration
        $publicPorts = $this->config['public_ports'] ?? [];
        $restrictedPorts = $this->config['restricted_ports'] ?? [];

        // Convert to arrays if they're not already
        if (! is_array($publicPorts)) {
            $publicPorts = explode('|', $publicPorts);
        }
        if (! is_array($restrictedPorts)) {
            $restrictedPorts = explode('|', $restrictedPorts);
        }

        // Filter out empty values
        $publicPorts = array_filter($publicPorts);
        $restrictedPorts = array_filter($restrictedPorts);

        // Get UFW rules for analysis
        $statusResult = $this->getUfwStatusSafely();
        $ufwRules = [];
        
        if ($statusResult['success']) {
            $ufwStatus = UfwOutputParser::parseStatusOutput($statusResult['output']);
            $ufwRules = $ufwStatus['rules'] ?? [];
        }

        $portIssues = [];

        // Check that only public ports allow all traffic
        foreach ($publicPorts as $port) {
            $hasPublicRule = false;
            foreach ($ufwRules as $rule) {
                $rulePort = preg_replace('/\/.*$/', '', $rule['port']);
                if ($rulePort === $port && strtolower($rule['action']) === 'allow') {
                    if (in_array(strtolower($rule['source']), ['anywhere', 'anywhere (v6)'])) {
                        $hasPublicRule = true;
                        break;
                    }
                }
            }
            
            if (!$hasPublicRule) {
                $portIssues[] = "Public port $port should allow all traffic but has no UFW rule allowing 'Anywhere'";
            }
        }

        // Check that restricted ports are not fully open
        foreach ($restrictedPorts as $port) {
            $hasOpenRule = false;
            foreach ($ufwRules as $rule) {
                $rulePort = preg_replace('/\/.*$/', '', $rule['port']);
                if ($rulePort === $port && strtolower($rule['action']) === 'allow') {
                    if (in_array(strtolower($rule['source']), ['anywhere', 'anywhere (v6)'])) {
                        $hasOpenRule = true;
                        break;
                    }
                }
            }
            
            if ($hasOpenRule) {
                $portIssues[] = "Restricted port $port should not allow all traffic but has UFW rule allowing 'Anywhere'";
            }
        }

        return [
            'issues' => $portIssues,
            'public_ports_config' => $publicPorts,
            'restricted_ports_config' => $restrictedPorts,
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

        $publicPorts = $this->config['public_ports'] ?? [];
        $restrictedPorts = $this->config['restricted_ports'] ?? [];

        // Build details array with firewall-specific information
        $details = [
            'rules' => $rules,
            'default_policy' => $defaultPolicy,
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
     * @param  \Prahsys\Perimeter\Services\ArtifactManager|null  $artifactManager  Optional artifact manager for saving audit data
     * @return array Array of SecurityEventData objects
     */
    protected function performServiceSpecificAuditChecks($output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): array
    {
        // Build the issues array using SecurityEventData
        $issues = [];
        $firewallActive = $this->isInstalled() && $this->isConfigured();
        
        // Save UFW status and configuration as artifacts if manager is available
        if ($artifactManager && $firewallActive) {
            $this->saveUfwArtifacts($artifactManager);
        }

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

            // Check for port configuration issues
            $portCheck = $this->checkPorts();
            
            // Add any port issues to the security issues
            foreach ($portCheck['issues'] as $issue) {
                $issues[] = new SecurityEventData(
                    timestamp: now(),
                    type: 'firewall',
                    severity: 'medium',
                    description: $issue,
                    location: 'ufw-rules',
                    user: null,
                    details: [
                        'public_ports_config' => $portCheck['public_ports_config'],
                        'restricted_ports_config' => $portCheck['restricted_ports_config'],
                    ]
                );
            }

            // Get and categorize ports
            $portStatus = $this->categorizePortsByAccess();
            
            if (!empty($portStatus['public'])) {
                $publicDescriptions = $this->getPortDescriptions($portStatus['public']);
                $output->writeln('  ⚪ Public services: '.implode(', ', $publicDescriptions));
            }
            
            if (!empty($portStatus['restricted'])) {
                $restrictedDescriptions = $this->getPortDescriptions($portStatus['restricted']);
                $output->writeln('  ⚪ Restricted services: '.implode(', ', $restrictedDescriptions));
            }
            
            if (!empty($portStatus['closed'])) {
                $closedDescriptions = $this->getPortDescriptions($portStatus['closed']);
                $output->writeln('  ⚪ Closed services: '.implode(', ', $closedDescriptions));
            }
            
            // Show port configuration issues if any
            if (!empty($portCheck['issues'])) {
                $output->writeln('  ⚠️  Port configuration issues:');
                foreach ($portCheck['issues'] as $issue) {
                    $output->writeln('    - ' . $issue);
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
     * Safely get UFW status using sudo (configured during installation)
     */
    protected function getUfwStatusSafely(): array
    {
        try {
            // Try sudo first (should work if sudoers is configured properly)
            $process = new Process(['sudo', '-n', 'ufw', 'status', 'verbose']);
            $process->run();

            if ($process->isSuccessful()) {
                return [
                    'success' => true,
                    'output' => $process->getOutput(),
                    'error' => null,
                ];
            }

            // Fallback: try direct command (might work in some environments)
            $process = new Process(['ufw', 'status', 'verbose']);
            $process->run();

            if ($process->isSuccessful()) {
                return [
                    'success' => true,
                    'output' => $process->getOutput(),
                    'error' => null,
                ];
            }

            return [
                'success' => false,
                'output' => '',
                'error' => $process->getErrorOutput() ?: 'UFW requires root privileges. Run perimeter:install to configure sudo access.',
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'output' => '',
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Categorize ports by their UFW access rules
     */
    protected function categorizePortsByAccess(): array
    {
        $categorized = [
            'public' => [],      // ufw allow [port] (allow all)
            'restricted' => [],  // ufw allow from [ip] to any port [port] (allow specific IPs)
            'closed' => []       // ufw deny [port] or no rules (deny all) but listening
        ];

        // Get UFW status with rules
        $statusResult = $this->getUfwStatusSafely();
        $ufwRules = [];
        
        if ($statusResult['success']) {
            $ufwStatus = UfwOutputParser::parseStatusOutput($statusResult['output']);
            $ufwRules = $ufwStatus['rules'] ?? [];
        }

        // Get all listening ports
        $process = new Process(['bash', '-c', "ss -tuln | grep LISTEN | awk '{print \$5}' | sed 's/.*://' | sort -u"]);
        $process->run();
        
        $listeningPorts = [];
        if ($process->isSuccessful() && !empty(trim($process->getOutput()))) {
            $listeningPorts = array_filter(explode("\n", trim($process->getOutput())));
            $listeningPorts = array_map('trim', $listeningPorts);
        }

        // First, categorize UFW rules regardless of whether they're listening
        foreach ($ufwRules as $rule) {
            if (strtolower($rule['action']) === 'allow') {
                // Extract port number from rule (e.g., "22/tcp" -> "22")
                $rulePort = preg_replace('/\/.*$/', '', $rule['port']);
                
                // Check if source is "Anywhere" (public) or specific IP (restricted)
                if (in_array(strtolower($rule['source']), ['anywhere', 'anywhere (v6)'])) {
                    if (!in_array($rulePort, $categorized['public'])) {
                        $categorized['public'][] = $rulePort;
                    }
                } else {
                    if (!in_array($rulePort, $categorized['restricted'])) {
                        $categorized['restricted'][] = $rulePort;
                    }
                }
            }
        }

        // Then, add any listening ports that don't have UFW rules to closed
        foreach ($listeningPorts as $port) {
            $port = trim($port);
            
            // Check if this port is already categorized by UFW rules
            $isAlreadyCategorized = in_array($port, $categorized['public']) || 
                                   in_array($port, $categorized['restricted']);
            
            if (!$isAlreadyCategorized) {
                $categorized['closed'][] = $port;
            }
        }

        return $categorized;
    }

    /**
     * Get descriptive names for common ports
     */
    protected function getPortDescriptions(array $ports): array
    {
        $commonPorts = [
            '22' => 'SSH',
            '53' => 'DNS',
            '80' => 'HTTP',
            '443' => 'HTTPS',
            '3306' => 'MySQL',
            '5432' => 'PostgreSQL',
            '6379' => 'Redis',
            '11211' => 'Memcached',
            '8080' => 'HTTP-Alt',
            '8443' => 'HTTPS-Alt',
            '8461' => 'Custom-App',
            '8765' => 'Custom-App',
            '25' => 'SMTP',
            '110' => 'POP3',
            '143' => 'IMAP',
            '993' => 'IMAPS',
            '995' => 'POP3S',
            '21' => 'FTP',
            '23' => 'Telnet',
            '587' => 'SMTP-MSA',
            '465' => 'SMTPS',
            '993' => 'IMAPS',
            '995' => 'POP3S',
            '9000' => 'PHP-FPM',
            '3000' => 'Dev-Server',
            '5000' => 'Dev-Server',
            '8000' => 'Dev-Server',
        ];

        $descriptions = [];
        foreach ($ports as $port) {
            $port = trim($port);
            if (isset($commonPorts[$port])) {
                $descriptions[] = $port . ' (' . $commonPorts[$port] . ')';
            } else {
                $descriptions[] = $port;
            }
        }

        return $descriptions;
    }

    /**
     * Set up sudo permissions for UFW status commands
     */
    protected function setupSudoPermissions(): void
    {
        Log::info('Setting up sudo permissions for UFW status commands');

        // Detect the web user (common users: www-data, apache, nginx, forge)
        $webUser = $this->detectWebUser();
        
        if (!$webUser) {
            Log::warning('Could not detect web user, skipping sudo setup');
            return;
        }

        Log::info("Setting up UFW sudo permissions for user: {$webUser}");

        // Create sudoers rule content
        $sudoersContent = "# Laravel Perimeter UFW permissions\n";
        $sudoersContent .= "# Allow {$webUser} to run UFW status commands without password\n";
        $sudoersContent .= "{$webUser} ALL=(root) NOPASSWD: /usr/sbin/ufw status, /usr/sbin/ufw status verbose, /usr/sbin/ufw status numbered\n";
        $sudoersContent .= "{$webUser} ALL=(root) NOPASSWD: /sbin/ufw status, /sbin/ufw status verbose, /sbin/ufw status numbered\n";
        $sudoersContent .= "{$webUser} ALL=(root) NOPASSWD: /usr/bin/ufw status, /usr/bin/ufw status verbose, /usr/bin/ufw status numbered\n";

        $sudoersFile = '/etc/sudoers.d/laravel-perimeter-ufw';

        // Write the sudoers file
        file_put_contents($sudoersFile, $sudoersContent);
        
        // Set proper permissions
        chmod($sudoersFile, 0440);

        // Validate the sudoers file
        $process = new Process(['visudo', '-c', '-f', $sudoersFile]);
        $process->run();

        if (!$process->isSuccessful()) {
            Log::error('Invalid sudoers file syntax, removing file');
            unlink($sudoersFile);
            throw new \Exception('Failed to create valid sudoers file');
        }

        Log::info('Sudo permissions configured successfully');
    }

    /**
     * Detect the web user for sudo permissions
     */
    protected function detectWebUser(): ?string
    {
        $commonWebUsers = ['www-data', 'apache', 'nginx', 'forge'];
        
        foreach ($commonWebUsers as $user) {
            $process = new Process(['id', $user]);
            $process->run();
            
            if ($process->isSuccessful()) {
                return $user;
            }
        }

        // Try to detect from the current process
        $currentUser = posix_getpwuid(posix_geteuid())['name'] ?? null;
        
        if ($currentUser && $currentUser !== 'root') {
            return $currentUser;
        }

        return null;
    }

    /**
     * Save UFW artifacts for audit trail
     */
    protected function saveUfwArtifacts(\Prahsys\Perimeter\Services\ArtifactManager $artifactManager): void
    {
        try {
            // Save UFW status output
            $statusResult = $this->getUfwStatusSafely();
            if ($statusResult['success']) {
                $artifactManager->saveArtifact('ufw', 'status', $statusResult['output']);
            }
        } catch (\Exception $e) {
            // Skip if can't get UFW status
        }
    }
}
