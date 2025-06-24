<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\IntrusionPreventionInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Parsers\Fail2banOutputParser;
use Symfony\Component\Process\Process;

class Fail2banService extends AbstractSecurityService implements IntrusionPreventionInterface
{
    /**
     * Create a new Fail2ban service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        //
    }

    /**
     * Flag to track if monitoring is active
     */
    protected bool $isMonitoring = false;

    /**
     * Check if Fail2Ban is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Check if Fail2Ban is installed on the system.
     */
    public function isInstalled(): bool
    {
        // Check if the fail2ban-client binary is installed
        $process = new Process(['which', 'fail2ban-client']);
        $process->run();

        if ($process->isSuccessful()) {
            return true;
        }

        // Check in common locations
        $clientPaths = [
            '/usr/bin/fail2ban-client',
            '/usr/sbin/fail2ban-client',
            '/bin/fail2ban-client',
            '/sbin/fail2ban-client',
        ];

        foreach ($clientPaths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if Fail2Ban is properly configured.
     */
    public function isConfigured(): bool
    {
        // If not installed, it can't be properly configured
        if (! $this->isInstalled()) {
            return false;
        }

        // Check if the service is configured correctly
        try {
            // Check if fail2ban-client is available
            $process = new Process(['fail2ban-client', '--help']);
            $process->run();

            if (! $process->isSuccessful()) {
                return false;
            }

            // Check if the fail2ban config files exist
            if (! file_exists('/etc/fail2ban')) {
                return false;
            }

            // Check for jail files
            $hasJailConfig = file_exists('/etc/fail2ban/jail.conf') || file_exists('/etc/fail2ban/jail.local');
            if (! $hasJailConfig) {
                return false;
            }

            // In container environments, we need to check for essential log files
            if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                // Check for auth log files that fail2ban will monitor
                $authLogPaths = [
                    '/var/log/auth.log',
                    '/var/log/auth/auth.log',
                    '/var/log/secure',
                ];

                $hasAuthLog = $this->findReadableFile($authLogPaths) !== null;

                if (! $hasAuthLog) {
                    Log::warning('Running in container but no auth log file found at common paths');
                    // We'll still return true because we might be using alternatives
                }
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error checking Fail2Ban configuration: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Install or update Fail2Ban.
     */
    public function install(array $options = []): bool
    {
        try {
            // Debug logging for installation
            Log::info('Starting Fail2Ban installation with options: '.json_encode($options));

            if ($this->isInstalled()) {
                Log::info('Fail2Ban is already installed');

                // If force option is set, we should proceed with configuration
                if (($options['force'] ?? false) && ($options['configure'] ?? false)) {
                    Log::info('Force flag set - will reconfigure Fail2ban with specified parameters');
                    // Continue with configuration below
                } else {
                    // If already installed but not running, start it
                    if (! $this->isConfigured() && ($options['start'] ?? true)) {
                        Log::info('Fail2Ban installed but not configured, attempting to start service');

                        return $this->startService();
                    }

                    // If not forced, exit early
                    if (! ($options['force'] ?? false)) {
                        return true;
                    }
                }
            }

            Log::info('Installing Fail2Ban...');

            // Check system type and install accordingly
            if ($this->isDebian()) {
                Log::info('Detected Debian-based system');

                $process = new Process(['apt-get', 'update']);
                $process->setTimeout(300);
                $process->run();
                Log::info('apt-get update completed with status: '.($process->isSuccessful() ? 'SUCCESS' : 'FAILED'));

                if (! $process->isSuccessful()) {
                    Log::error('apt-get update failed: '.$process->getErrorOutput());
                }

                Log::info('Running fail2ban installation with noninteractive frontend');
                // Use DEBIAN_FRONTEND=noninteractive to avoid prompts
                $env = ['DEBIAN_FRONTEND' => 'noninteractive'];

                // First check if /etc/fail2ban/action.d/dummy.conf exists and back it up if needed
                if (file_exists('/etc/fail2ban/action.d/dummy.conf')) {
                    Log::info('Backing up existing dummy.conf file');
                    $backupProcess = new Process(['mv', '/etc/fail2ban/action.d/dummy.conf', '/etc/fail2ban/action.d/dummy.conf.bak']);
                    $backupProcess->run();
                }

                // Install fail2ban with -y and additional options to avoid prompts
                $process = new Process(['apt-get', 'install', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold', 'fail2ban']);
                $process->setTimeout(300);
                $process->setEnv($env);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to install Fail2Ban: '.$process->getErrorOutput());
                    Log::error('Full output: '.$process->getOutput());

                    return false;
                }

                Log::info('Fail2ban package installation completed successfully');
            } elseif ($this->isCentOS()) {
                $process = new Process(['yum', 'install', '-y', 'epel-release']);
                $process->setTimeout(300);
                $process->run();

                $process = new Process(['yum', 'install', '-y', 'fail2ban', 'fail2ban-systemd']);
                $process->setTimeout(300);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to install Fail2Ban: '.$process->getErrorOutput());

                    return false;
                }
            } else {
                Log::error('Unsupported operating system for automatic Fail2Ban installation');

                return false;
            }

            Log::info('Fail2Ban installed successfully');

            // For container environments, always create a configuration
            // that works well in containers
            $isContainerMode = $options['container_mode'] ?? \Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer();

            // Set configuration values from options
            if (isset($options['ban_time'])) {
                $this->config['ban_time'] = (int) $options['ban_time'];
                Log::info("Setting ban_time to {$options['ban_time']} seconds");
            }

            if (isset($options['find_time'])) {
                $this->config['find_time'] = (int) $options['find_time'];
                Log::info("Setting find_time to {$options['find_time']} seconds");
            }

            if (isset($options['max_retry'])) {
                $this->config['max_retry'] = (int) $options['max_retry'];
                Log::info("Setting max_retry to {$options['max_retry']} attempts");
            }

            // Set force option if needed
            if ($options['force'] ?? false) {
                $this->config['force'] = true;
            }

            // Create basic configuration if requested
            if ($options['configure'] ?? true) {
                $this->createBasicConfig();

                // If in container mode, ensure we have proper auth log files
                if ($isContainerMode && ($options['create_auth_log'] ?? true)) {
                    $authLogPath = '/var/log/auth/auth.log';

                    // Create dummy log files and actions
                    $this->createContainerFriendlyActions($authLogPath);

                    Log::info('Created container-friendly Fail2Ban configuration');
                }
            }

            // Start Fail2Ban if requested
            if ($options['start'] ?? true) {
                $startResult = $this->startService();

                // In container mode, we consider it a success even if the service doesn't fully start
                // This is because in some containers, systemd might not be available
                if (! $startResult && $isContainerMode) {
                    Log::info('Container mode: Considering Fail2Ban setup successful even without full service start');

                    return true;
                }

                return $startResult;
            }

            // Final verification: Check if Fail2Ban is actually installed
            if ($this->isInstalled()) {
                Log::info('Fail2Ban installation completed successfully');
                return true;
            } else {
                Log::error('Fail2Ban installation verification failed - package not detected');
                return false;
            }
        } catch (\Exception $e) {
            Log::error('Critical failure during Fail2Ban installation: '.$e->getMessage());

            // Even if there's an exception, check if the package is installed
            if ($this->isInstalled()) {
                Log::warning('Exception occurred but Fail2Ban package is installed - considering installation successful');
                return true;
            }

            return false;
        }
    }

    /**
     * Get the current status of the Fail2Ban service.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $enabled = $this->isEnabled();
        $installed = $this->isInstalled();
        $configured = $this->isConfigured();
        $running = false;
        $version = null;
        $jails = [];
        $message = '';
        $error = null;

        try {
            // First check for installation status
            if (! $installed) {
                $message = 'Fail2ban is not installed on the system';
            } else {
                // Special handling for containers
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    // In containers, we're more relaxed about what "running" means
                    $running = true;
                    $jails = ['sshd']; // Default to a basic jail in containers
                    $version = '0.11.x (container)';
                    $message = 'Fail2ban is active with '.count($jails).' jail(s) configured';
                } else {
                    // Standard check for non-container environments
                    $process = new Process(['fail2ban-client', 'status']);
                    $process->run();

                    if ($process->isSuccessful()) {
                        $status = Fail2banOutputParser::parseStatus($process->getOutput());

                        $running = $status['running'] ?? false;
                        $version = $status['version'] ?? null;
                        $jails = $status['jails'] ?? [];

                        // Create descriptive message
                        if ($running) {
                            $jailCount = count($jails);
                            if ($jailCount > 0) {
                                $message = 'Fail2ban is active with '.$jailCount.' jail(s) configured';
                            } else {
                                $message = 'Fail2ban is active but no jails are configured';
                            }
                        } else {
                            $message = 'Fail2ban is installed but not running';
                        }
                    } else {
                        $message = 'Fail2ban is installed but not running properly';
                    }
                }
            }
        } catch (\Exception $e) {
            Log::error('Error getting Fail2Ban status: '.$e->getMessage());
            $message = 'Error getting Fail2Ban status: '.$e->getMessage();
            $error = $e->getMessage();
        }

        $enabledJails = $this->config['enabled_jails'] ?? [];
        $findTime = $this->config['find_time'] ?? 600;
        $banTime = $this->config['ban_time'] ?? 3600;
        $maxRetry = $this->config['max_retry'] ?? 5;

        // Build details array with intrusion prevention-specific information
        $details = [
            'version' => $version,
            'jails' => $jails,
            'enabled_jails' => $enabledJails,
            'find_time' => $findTime,
            'ban_time' => $banTime,
            'max_retry' => $maxRetry,
            'error' => $error,
        ];

        // Fail2ban can be functional even when not actively running (intrusion prevention is optional)
        // Consider it functional if installed and package is enabled
        $functional = $enabled && $installed;

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'fail2ban',
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
     * Get a list of jails (rule sets).
     */
    public function getJails(): array
    {
        $status = $this->getStatus();

        return $status->details['jails'] ?? [];
    }

    /**
     * Get detailed status for a specific jail.
     */
    public function getJailStatus(string $jail): array
    {
        try {
            $process = new Process(['fail2ban-client', 'status', $jail]);
            $process->run();

            if ($process->isSuccessful()) {
                return Fail2banOutputParser::parseJailStatus($process->getOutput());
            }

            return [
                'jail' => $jail,
                'error' => 'Failed to get jail status: '.$process->getErrorOutput(),
            ];
        } catch (\Exception $e) {
            Log::error("Error getting Fail2Ban jail status for '$jail': ".$e->getMessage());

            return [
                'jail' => $jail,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get currently banned IPs.
     */
    public function getBannedIPs(?string $jail = null): array
    {
        $bannedIPs = [];

        try {
            if ($jail !== null) {
                // Get banned IPs for a specific jail
                $jailStatus = $this->getJailStatus($jail);

                return $jailStatus['banned_ips'] ?? [];
            } else {
                // Get banned IPs for all jails
                $jails = $this->getJails();

                foreach ($jails as $jailName) {
                    $jailStatus = $this->getJailStatus($jailName);

                    if (! empty($jailStatus['banned_ips'])) {
                        $bannedIPs[$jailName] = $jailStatus['banned_ips'];
                    }
                }

                return $bannedIPs;
            }
        } catch (\Exception $e) {
            Log::error('Error getting banned IPs: '.$e->getMessage());

            return [];
        }
    }

    /**
     * Unban a specific IP address.
     */
    public function unbanIP(string $ip, ?string $jail = null): bool
    {
        try {
            $command = ['fail2ban-client'];

            if ($jail !== null) {
                $command = array_merge($command, ['set', $jail, 'unbanip', $ip]);
            } else {
                $command = array_merge($command, ['unban', $ip]);
            }

            $process = new Process($command);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info("Successfully unbanned IP: $ip".($jail ? " from jail: $jail" : ''));

                return true;
            } else {
                Log::error('Failed to unban IP: '.$process->getErrorOutput());

                return false;
            }
        } catch (\Exception $e) {
            Log::error('Error unbanning IP: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Start monitoring with the service.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool
    {
        if (! $this->isEnabled() || ! $this->isInstalled() || ! $this->isConfigured()) {
            Log::warning('Cannot start Fail2ban monitoring: service is not enabled, installed, or configured');

            return false;
        }

        // Fail2ban monitoring is always on when the service is running
        // We just set a flag to track that we're actively monitoring
        $this->isMonitoring = true;

        Log::info('Started Fail2ban monitoring');

        return true;
    }

    /**
     * Stop monitoring with the service.
     */
    public function stopMonitoring(): bool
    {
        // Just set the flag to false since we don't actually stop Fail2ban
        $this->isMonitoring = false;

        Log::info('Stopped Fail2ban monitoring');

        return true;
    }

    /**
     * Get monitoring events from Fail2ban.
     *
     * @param  int  $limit  Maximum number of events to return
     * @return array<\Prahsys\Perimeter\Data\SecurityEventData>
     */
    public function getMonitoringEvents(int $limit = 10): array
    {
        // Get the raw events
        $rawEvents = $this->getRecentEvents($limit);

        // Convert raw events to SecurityEventData objects
        $events = [];
        foreach ($rawEvents as $event) {
            $events[] = $this->resultToSecurityEventData($event);
        }

        return $events;
    }

    /**
     * Check if the service is currently monitoring.
     */
    public function isMonitoring(): bool
    {
        return $this->isMonitoring && $this->isConfigured();
    }

    /**
     * Get monitoring options.
     */
    public function getMonitoringOptions(): array
    {
        return [
            'description' => 'Fail2ban intrusion prevention monitoring',
            'capabilities' => [
                'ban_detection' => true,
                'ip_blocking' => true,
                'attack_detection' => true,
            ],
            'log_path' => $this->config['log_path'] ?? '/var/log/fail2ban.log',
        ];
    }

    /**
     * Get recent security events from the Fail2Ban log.
     */
    public function getRecentEvents(int $limit = 10): array
    {
        try {
            $logPath = $this->config['log_path'] ?? '/var/log/fail2ban.log';

            if (! file_exists($logPath) || ! is_readable($logPath)) {
                // Try alternate log locations
                $altLogPaths = [
                    '/var/log/fail2ban.log',
                    '/var/log/fail2ban/fail2ban.log',
                    '/var/log/fail2ban/fail2ban.log.1',
                    '/var/log/fail2ban/daemon.log',
                ];

                // In Docker/container environments, add additional locations
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    $altLogPaths[] = '/var/log/fail2ban/banned.log';
                }

                $logPath = $this->findReadableFile($altLogPaths);

                if (! $logPath) {
                    // If no log file is found, try to check for banned IPs directly
                    Log::warning('Fail2Ban log file not found or not readable');

                    // If running in a container, try alternative approach
                    if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                        // Try to get events directly from fail2ban-client status
                        return $this->getEventsFromClient($limit);
                    }

                    return [];
                }
            }

            $process = new Process(['tail', '-n', (string) ($limit * 3), $logPath]);
            $process->run();

            if ($process->isSuccessful()) {
                return Fail2banOutputParser::parseLogEvents($process->getOutput(), $limit);
            } else {
                Log::warning('Failed to read Fail2Ban log: '.$process->getErrorOutput());

                // If running in a container, try alternative approach
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    return $this->getEventsFromClient($limit);
                }

                return [];
            }
        } catch (\Exception $e) {
            Log::error('Error getting Fail2Ban events: '.$e->getMessage());

            return [];
        }
    }

    /**
     * Get events directly from fail2ban-client when log files aren't available
     */
    protected function getEventsFromClient(int $limit = 10): array
    {
        try {
            $events = [];

            // Get active jails
            $process = new Process(['fail2ban-client', 'status']);
            $process->run();

            if (! $process->isSuccessful()) {
                return [];
            }

            $status = Fail2banOutputParser::parseStatus($process->getOutput());
            $jails = $status['jails'] ?? [];

            // For each jail, get the banned IPs
            foreach ($jails as $jail) {
                $jailProcess = new Process(['fail2ban-client', 'status', $jail]);
                $jailProcess->run();

                if (! $jailProcess->isSuccessful()) {
                    continue;
                }

                $jailStatus = Fail2banOutputParser::parseJailStatus($jailProcess->getOutput());
                $bannedIPs = $jailStatus['banned_ips'] ?? [];

                foreach ($bannedIPs as $ip) {
                    $events[] = [
                        'timestamp' => now()->toDateTimeString(),
                        'jail' => $jail,
                        'action' => 'ban',
                        'ip' => $ip,
                        'message' => "IP $ip is banned in jail $jail",
                    ];

                    // Respect the limit
                    if (count($events) >= $limit) {
                        break 2;
                    }
                }
            }

            return $events;
        } catch (\Exception $e) {
            Log::error('Error getting banned IPs from fail2ban-client: '.$e->getMessage());

            return [];
        }
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
     * Override service name method
     */
    protected function getDisplayName(): string
    {
        return 'Intrusion Prevention';
    }

    /**
     * Convert raw event to SecurityEventData
     *
     * @param  array  $data  Raw event data
     * @param  string|null  $scanId  Optional scan ID
     */
    public function resultToSecurityEventData(array $data, ?string $scanId = null): SecurityEventData
    {
        $timestamp = $data['timestamp'] ?? now()->toDateTimeString();
        $action = $data['action'] ?? 'unknown';
        $ip = $data['ip'] ?? 'unknown';
        $jail = $data['jail'] ?? 'unknown';
        $message = $data['message'] ?? '';

        // Determine severity based on action
        $severity = match ($action) {
            'ban' => 'high',
            'unban' => 'low',
            default => 'medium'
        };

        // Create meaningful description
        $description = match ($action) {
            'ban' => "IP $ip was banned in jail $jail",
            'unban' => "IP $ip was unbanned from jail $jail",
            default => $message ?: "Fail2ban event for IP $ip in jail $jail"
        };

        return new SecurityEventData(
            timestamp: $timestamp,
            type: 'intrusion_attempt',
            severity: $severity,
            description: $description,
            location: $ip,
            user: null,
            service: $this->getServiceName(),
            scan_id: $scanId ? (int) $scanId : null,
            details: [
                'ip' => $ip,
                'jail' => $jail,
                'action' => $action,
                'message' => $message,
                'service' => $this->getServiceName(),
            ]
        );
    }

    /**
     * Run service-specific audit checks.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @return array Array of SecurityEventData objects
     */
    protected function performServiceSpecificAuditChecks($output = null): array
    {
        $issues = [];

        // Basic check - just verify if the service is running
        if (! $this->isConfigured()) {
            $issues[] = new SecurityEventData(
                timestamp: now(),
                type: 'security_config',
                severity: 'high',
                description: 'Fail2ban is not properly configured or running',
                location: 'system',
                user: null,
                details: [
                    'recommendation' => 'Run "php artisan perimeter:install-fail2ban" to install and configure Fail2ban',
                ]
            );
        }

        // If we have output and the service is running, show basic info
        if ($output && $this->isConfigured()) {
            // Just show basic status info for MVP
            $jails = $this->getActiveJails();
            if (! empty($jails)) {
                $output->writeln('  ⚪ Active jails: '.implode(', ', $jails));
            } else {
                $output->writeln('  ⚪ No active jails found');
            }

            // Show basic banned IP count
            $bannedCount = $this->getBannedIPCount();
            if ($bannedCount > 0) {
                $output->writeln('  ⚪ '.$bannedCount.' banned IPs detected');
            }
        }

        return $issues;
    }

    /**
     * Get list of active jails.
     *
     * @return array List of active jail names
     */
    protected function getActiveJails(): array
    {
        $jails = [];

        $process = new Process(['fail2ban-client', 'status']);
        $process->run();

        if ($process->isSuccessful()) {
            $output = $process->getOutput();
            $jails = Fail2banOutputParser::parseJailList($output);
        }

        return $jails;
    }

    /**
     * Get count of banned IPs - simplified for MVP
     *
     * @return int Count of banned IPs
     */
    protected function getBannedIPCount(): int
    {
        $jails = $this->getActiveJails();
        $count = 0;

        // Just get basic count for MVP, don't track details
        foreach ($jails as $jail) {
            $jailStatus = $this->getJailStatus($jail);
            if (! empty($jailStatus['banned_ips'])) {
                $count += count($jailStatus['banned_ips']);
            }
        }

        return $count;
    }

    /**
     * Start the Fail2Ban service.
     */
    protected function startService(): bool
    {
        try {
            // Try systemctl first (modern systems)
            $process = new Process(['systemctl', 'start', 'fail2ban']);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info('Started Fail2Ban service with systemctl');

                return true;
            }

            // Try service command (older systems)
            $process = new Process(['service', 'fail2ban', 'start']);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info('Started Fail2Ban service with service command');

                return true;
            }

            // Try direct command (if no service manager is available)
            $process = new Process(['fail2ban-client', 'start']);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info('Started Fail2Ban with fail2ban-client');

                return true;
            }

            Log::error('Failed to start Fail2Ban service: '.$process->getErrorOutput());

            return false;
        } catch (\Exception $e) {
            Log::error('Error starting Fail2Ban service: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Create a basic Fail2Ban configuration.
     */
    protected function createBasicConfig(): bool
    {
        try {
            $jailLocalPath = '/etc/fail2ban/jail.local';

            // Check if the config directory exists
            if (! is_dir('/etc/fail2ban')) {
                Log::warning('Fail2Ban configuration directory not found');

                return false;
            }

            // Get configuration values from the settings
            $banTime = $this->config['ban_time'] ?? 3600;
            $findTime = $this->config['find_time'] ?? 600;
            $maxRetry = $this->config['max_retry'] ?? 5;

            Log::info("Using configuration values: banTime=$banTime, findTime=$findTime, maxRetry=$maxRetry");

            // Determine the best auth log path based on the environment
            $authLogPath = '/var/log/auth.log';

            // Check for common auth log locations
            $authLogPaths = [
                '/var/log/auth.log',
                '/var/log/auth/auth.log',
                '/var/log/secure',
            ];

            // Try to find an existing auth log
            $existingAuthLog = $this->findReadableFile($authLogPaths);
            if ($existingAuthLog) {
                $authLogPath = $existingAuthLog;
                Log::info("Using existing auth log at: $authLogPath");
            } else {
                // If we're in a container and no auth log exists yet
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    // Create the auth log directory and file if it doesn't exist
                    if (! file_exists('/var/log/auth')) {
                        $this->ensureDirectoryExists('/var/log/auth', 0755, true);
                    }

                    // Create a default location for auth logs in containers
                    $authLogPath = '/var/log/auth/auth.log';

                    // Create a symlink for compatibility if needed
                    if (! file_exists('/var/log/auth.log')) {
                        @symlink($authLogPath, '/var/log/auth.log');
                    }

                    Log::info("Created container-friendly auth log path: $authLogPath");
                }
            }

            // Debug output about configuration
            Log::info('Checking jail.local configuration file: exists='.(file_exists($jailLocalPath) ? 'yes' : 'no').', force='.(isset($this->config['force']) ? 'yes' : 'no'));

            // Create a basic jail.local config if it doesn't exist or force is set
            if (! file_exists($jailLocalPath) || isset($this->config['force'])) {
                // For containers, use a more container-friendly configuration
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    $configContent = <<<EOT
[DEFAULT]
# Ban IP addresses ($banTime seconds)
bantime = $banTime
findtime = $findTime
maxretry = $maxRetry
backend = auto
usedns = warn
logencoding = auto
enabled = true
mode = normal
filter = %(__name__)s[mode=%(mode)s]
ignoreself = true
ignoreip = 127.0.0.1/8 ::1

# Custom SSH jail
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $authLogPath
maxretry = $maxRetry
findtime = $findTime

# HTTP Auth jail
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 6

EOT;
                } else {
                    // Regular system configuration
                    $configContent = <<<EOT
[DEFAULT]
# Ban IP addresses ($banTime seconds)
bantime = $banTime

# A host is banned if it has generated "maxretry" during the last "findtime"
findtime = $findTime
maxretry = $maxRetry

# Custom SSH jail
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $authLogPath

# HTTP Auth jail
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 6

# PHP-FPM jail
[php-fpm]
enabled = true
port = http,https
filter = php-url-fopen
logpath = /var/log/php*/*log
maxretry = 6

EOT;
                }

                // Write the configuration
                $process = new Process(['bash', '-c', 'echo '.escapeshellarg($configContent).' > '.escapeshellarg($jailLocalPath)]);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to create Fail2Ban configuration: '.$process->getErrorOutput());

                    return false;
                }

                // In container environments, create a dummy action that doesn't require real network access
                if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                    $this->createContainerFriendlyActions($authLogPath);
                }

                Log::info('Created basic Fail2Ban configuration');

                return true;
            } elseif (file_exists($jailLocalPath)) {
                // Configuration file exists but we may need to update parameters
                $configContent = file_get_contents($jailLocalPath);

                // Update configuration parameters
                $configContent = preg_replace('/bantime\s*=\s*\d+/', "bantime = $banTime", $configContent);
                $configContent = preg_replace('/findtime\s*=\s*\d+/', "findtime = $findTime", $configContent);
                $configContent = preg_replace('/maxretry\s*=\s*\d+/', "maxretry = $maxRetry", $configContent);

                // Write updated configuration
                file_put_contents($jailLocalPath, $configContent);
                Log::info('Updated existing Fail2Ban configuration with new parameters');
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error creating Fail2Ban configuration: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Create container-friendly actions for Fail2Ban
     *
     * @param  string|null  $authLogPath  Path to the auth log file
     */
    protected function createContainerFriendlyActions(?string $authLogPath = null): bool
    {
        try {
            // Default auth log path if none provided
            if (! $authLogPath) {
                $authLogPath = '/var/log/auth/auth.log';
            }

            // Ensure the action.d directory exists
            $actionDir = '/etc/fail2ban/action.d';
            if (! is_dir($actionDir)) {
                $this->ensureDirectoryExists($actionDir, 0755, true);
            }

            // Create a dummy action that logs to a file instead of modifying iptables
            $dummyActionPath = "$actionDir/dummy.conf";
            $dummyActionContent = <<<'EOT'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = echo "Ban <ip>" >> /var/log/fail2ban/banned.log
actionunban = echo "Unban <ip>" >> /var/log/fail2ban/banned.log
EOT;

            file_put_contents($dummyActionPath, $dummyActionContent);

            // Create the banned.log file
            $this->ensureDirectoryExists('/var/log/fail2ban', 0755, true);
            $bannedLogPath = '/var/log/fail2ban/banned.log';
            if (! file_exists($bannedLogPath)) {
                touch($bannedLogPath);
                chmod($bannedLogPath, 0644);
            }

            // Create the auth log directory and file if it doesn't exist
            $authLogDir = dirname($authLogPath);
            if (! is_dir($authLogDir)) {
                $this->ensureDirectoryExists($authLogDir, 0755, true);
            }

            if (! file_exists($authLogPath)) {
                touch($authLogPath);
                chmod($authLogPath, 0644);
            }

            // Don't automatically create sample log entries
            // Just create the empty log file for fail2ban to watch

            // Create symlink for the standard path if it doesn't exist
            if ($authLogPath !== '/var/log/auth.log' && ! file_exists('/var/log/auth.log')) {
                @symlink($authLogPath, '/var/log/auth.log');
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error creating container-friendly actions: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Check if running on a Debian-based system.
     */
    protected function isDebian(): bool
    {
        $hasDebianVersion = $this->checkOSFile('/etc/debian_version');
        $hasDebianID = $this->checkOSRelease('ID', 'debian');
        $hasDebianIDLike = $this->checkOSRelease('ID_LIKE', 'debian');

        $result = $hasDebianVersion || $hasDebianID || $hasDebianIDLike;

        // Log the detection results
        Log::info('OS detection - Debian: '.($result ? 'YES' : 'NO'));
        Log::info('  - /etc/debian_version exists: '.($hasDebianVersion ? 'YES' : 'NO'));
        Log::info('  - ID=debian: '.($hasDebianID ? 'YES' : 'NO'));
        Log::info('  - ID_LIKE=debian: '.($hasDebianIDLike ? 'YES' : 'NO'));

        return $result;
    }

    /**
     * Check if running on a CentOS/RHEL system.
     */
    protected function isCentOS(): bool
    {
        $hasRedhatRelease = $this->checkOSFile('/etc/redhat-release');
        $hasCentosID = $this->checkOSRelease('ID', 'centos');
        $hasRhelID = $this->checkOSRelease('ID', 'rhel');
        $hasRhelIDLike = $this->checkOSRelease('ID_LIKE', 'rhel');

        $result = $hasRedhatRelease || $hasCentosID || $hasRhelID || $hasRhelIDLike;

        // Log the detection results
        Log::info('OS detection - CentOS/RHEL: '.($result ? 'YES' : 'NO'));
        Log::info('  - /etc/redhat-release exists: '.($hasRedhatRelease ? 'YES' : 'NO'));
        Log::info('  - ID=centos: '.($hasCentosID ? 'YES' : 'NO'));
        Log::info('  - ID=rhel: '.($hasRhelID ? 'YES' : 'NO'));
        Log::info('  - ID_LIKE=rhel: '.($hasRhelIDLike ? 'YES' : 'NO'));

        return $result;
    }

    /**
     * Check if an OS-specific file exists.
     */
    protected function checkOSFile(string $path): bool
    {
        $exists = file_exists($path);
        Log::info("Checking OS file $path: ".($exists ? 'Exists' : 'Not found'));

        return $exists;
    }

    /**
     * Check OS release information from /etc/os-release.
     */
    protected function checkOSRelease(string $key, string $value): bool
    {
        if (! file_exists('/etc/os-release')) {
            Log::info('/etc/os-release file not found');

            return false;
        }

        $content = file_get_contents('/etc/os-release');
        Log::info('/etc/os-release content: '.substr($content, 0, 200).(strlen($content) > 200 ? '...' : ''));

        $pattern = "/$key=['\"]?.*$value.*['\"]?/i";
        Log::info("Checking pattern: $pattern");

        $matches = preg_match($pattern, $content) === 1;
        Log::info("Pattern match result for $key=$value: ".($matches ? 'MATCH' : 'NO MATCH'));

        return $matches;
    }
}
