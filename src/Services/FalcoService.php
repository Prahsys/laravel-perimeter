<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\MonitorServiceInterface;
use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Parsers\FalcoOutputParser;

class FalcoService extends AbstractSecurityService implements MonitorServiceInterface, SecurityMonitoringServiceInterface
{
    /**
     * Create a new Falco service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        //
    }

    /**
     * Cached instance of BackgroundProcessManager
     */
    protected ?BackgroundProcessManager $processManager = null;

    /**
     * Get or create the process manager instance
     */
    protected function getProcessManager(): BackgroundProcessManager
    {
        if ($this->processManager === null) {
            $this->processManager = new BackgroundProcessManager;

            // Set up event handlers for real-time event processing
            $this->processManager->on('falco', 'output', function ($output) {
                $this->processRealTimeOutput($output);
            });
        }

        return $this->processManager;
    }

    /**
     * Process real-time output from Falco
     */
    protected function processRealTimeOutput(string $output): void
    {
        // Skip empty lines
        if (empty(trim($output))) {
            return;
        }

        try {
            // Check if it's JSON output
            if (str_starts_with(trim($output), '{')) {
                $data = json_decode($output, true);

                // If valid JSON, it's a security event
                if (json_last_error() === JSON_ERROR_NONE && isset($data['rule'])) {
                    $eventData = FalcoOutputParser::parseJsonEvent($output);

                    if ($eventData) {
                        // Convert to SecurityEventData
                        $securityEvent = $this->resultToSecurityEventData($eventData);

                        // Emit event
                        event('perimeter.security.event', $securityEvent);

                        // Store for later retrieval
                        $this->storeEvent($securityEvent);
                    }
                }
            } else {
                // Try to parse as regular text output
                $events = FalcoOutputParser::parseTextEvents($output);

                foreach ($events as $eventData) {
                    // Convert to SecurityEventData
                    $securityEvent = $this->resultToSecurityEventData($eventData);

                    // Emit event
                    event('perimeter.security.event', $securityEvent);

                    // Store for later retrieval
                    $this->storeEvent($securityEvent);
                }
            }
        } catch (\Exception $e) {
            Log::warning('Error processing Falco output: '.$e->getMessage(), [
                'output' => $output,
            ]);
        }
    }

    /**
     * Recent events storage
     */
    protected array $recentEvents = [];

    /**
     * Store a security event for later retrieval
     */
    protected function storeEvent(SecurityEventData $event): void
    {
        // Add to the front of the array (newest first)
        array_unshift($this->recentEvents, $event);

        // Keep only the most recent 100 events
        if (count($this->recentEvents) > 100) {
            array_pop($this->recentEvents);
        }
    }

    /**
     * Start real-time monitoring.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        try {
            // Check if Falco is installed and configured
            if (! $this->isInstalled()) {
                Log::error('Failed to start Falco monitoring: Falco is not installed');

                return false;
            }

            // Create command to start Falco with proper configuration
            $command = $this->getFalcoBinaryPath();

            if (empty($command)) {
                Log::error('Failed to start Falco monitoring: Falco binary not found');

                return false;
            }

            // Build the Falco command with appropriate options
            $commandArgs = [];

            // Add config file if specified
            if (! empty($this->config['config_file']) && file_exists($this->config['config_file'])) {
                $commandArgs[] = '-c';
                $commandArgs[] = $this->config['config_file'];
            }

            // Add rules path if specified and exists
            if (! empty($this->config['rules_path']) && file_exists($this->config['rules_path'])) {
                $commandArgs[] = '-r';
                $commandArgs[] = $this->config['rules_path'];
            }

            // Add option to write to the log file specified in config
            if (! empty($this->config['log_path'])) {
                // Ensure the directory exists
                $logDir = dirname($this->config['log_path']);
                if (! file_exists($logDir)) {
                    mkdir($logDir, 0755, true);
                }

                $commandArgs[] = '-o';
                $commandArgs[] = 'file_output.enabled=true';
                $commandArgs[] = '-o';
                $commandArgs[] = 'file_output.filename='.$this->config['log_path'];
            }

            // Add JSON output format for easier parsing
            $commandArgs[] = '-o';
            $commandArgs[] = 'json_output=true';

            // Always use streaming mode for real-time event processing

            // Get the process manager
            $processManager = $this->getProcessManager();

            // Build the full command array
            $fullCommandArray = array_merge([$command], $commandArgs);

            // Start the process with streaming enabled
            $options = [
                'stream_output' => true,
            ];

            // Start the process and get the PID
            $pid = $processManager->start($fullCommandArray, 'falco', $options);

            if ($pid) {
                Log::info('Started Falco monitoring', [
                    'pid' => $pid,
                    'duration' => $duration,
                ]);

                // If duration is set, schedule termination
                if ($duration !== null) {
                    $processManager->scheduleTermination('falco', $duration);
                }

                return true;
            } else {
                Log::error('Failed to start Falco monitoring');

                return false;
            }
        } catch (\Exception $e) {
            Log::error('Failed to start Falco monitoring: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return false;
        }
    }

    /**
     * Stop monitoring.
     */
    public function stopMonitoring(): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        try {
            // Use the BackgroundProcessManager to stop the Falco process
            $processManager = new BackgroundProcessManager;

            // Try to stop by the named process first
            $result = $processManager->stop('falco');

            if ($result) {
                Log::info('Stopped Falco monitoring process');

                return true;
            }

            // Fallback: try to find and kill the process by name using pkill
            $process = new \Symfony\Component\Process\Process(['pkill', '-f', 'falco']);
            $process->run();

            Log::info('Attempted to stop all Falco monitoring processes');

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to stop Falco monitoring: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return false;
        }
    }

    /**
     * Schedule the termination of a monitoring process after a specified duration.
     *
     * @deprecated Use BackgroundProcessManager::scheduleTermination instead
     *
     * @param  int|null  $pid  Process ID to terminate
     * @param  int  $duration  Duration in seconds before termination
     */
    protected function scheduleTermination(?int $pid, int $duration): void
    {
        // Create a BackgroundProcessManager instance and use it for scheduling termination
        $processManager = new BackgroundProcessManager;
        $processManager->scheduleTermination($pid, $duration);
    }

    /**
     * Get the path to the Falco binary.
     */
    protected function getFalcoBinaryPath(): ?string
    {
        // Check for custom binary path in config
        if (! empty($this->config['binary_path']) && file_exists($this->config['binary_path'])) {
            return $this->config['binary_path'];
        }

        // Check if falco is in PATH
        $process = new \Symfony\Component\Process\Process(['which', 'falco']);
        $process->run();

        if ($process->isSuccessful()) {
            return trim($process->getOutput());
        }

        // Check common locations
        $falcoPaths = [
            '/usr/bin/falco',
            '/usr/local/bin/falco',
            '/opt/falco/bin/falco',
            '/bin/falco',
        ];

        foreach ($falcoPaths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Check if a specific rule is enabled.
     */
    public function isRuleEnabled(string $rule): bool
    {
        if (! $this->isEnabled()) {
            return false;
        }

        return $this->config['custom_rules'][$rule] ?? false;
    }

    /**
     * Get recent behavioral events.
     *
     * @deprecated Use getMonitoringEvents() instead
     */
    public function getRecentEvents(int $limit = 10): array
    {
        return $this->getRawEvents($limit);
    }

    /**
     * Get raw events from Falco logs or journal
     *
     * @param  int  $limit  Maximum number of events to return
     */
    protected function getRawEvents(int $limit = 10): array
    {
        if (! $this->isEnabled() || ! $this->isConfigured()) {
            return [];
        }

        try {
            $events = [];
            $logPath = $this->config['log_path'] ?? '/var/log/falco.log';

            // First try to read from the log file
            if (file_exists($logPath) && is_readable($logPath)) {
                // Read the last N lines of the log file (reverse order)
                $logCommand = sprintf('tail -n %d %s', $limit * 3, escapeshellarg($logPath));
                $process = new \Symfony\Component\Process\Process(explode(' ', $logCommand));
                $process->setTimeout(30);
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();

                    // Check if the log is in JSON format
                    if (str_starts_with(trim($output), '{') || str_contains($output, '"output":"') || str_contains($output, '"rule":"')) {
                        $events = FalcoOutputParser::parseJsonEvents($output);
                    } else {
                        // Fall back to text parsing
                        $events = FalcoOutputParser::parseTextEvents($output);
                    }

                    if (! empty($events)) {
                        // Apply severity filter if configured
                        if (! empty($this->config['severity_filter'])) {
                            $events = $this->filterEventsBySeverity($events, $this->config['severity_filter']);
                        }

                        // Limit results
                        return array_slice($events, 0, $limit);
                    }
                } else {
                    Log::warning('Failed to read Falco log file: '.$process->getErrorOutput());
                }
            } else {
                Log::info('Falco log file not found or not readable: '.$logPath);
            }

            // If log file method didn't work, try using the journal for systemd environments
            if (empty($events) && $this->isSystemdAvailable()) {
                $journalCmd = sprintf('journalctl -u falco -n %d -o json', $limit * 3);
                $process = new \Symfony\Component\Process\Process(explode(' ', $journalCmd));
                $process->setTimeout(30);
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();
                    $events = $this->parseJournalOutput($output);

                    if (! empty($events)) {
                        // Apply severity filter if configured
                        if (! empty($this->config['severity_filter'])) {
                            $events = $this->filterEventsBySeverity($events, $this->config['severity_filter']);
                        }

                        // Limit results
                        return array_slice($events, 0, $limit);
                    }
                }
            }

            // Try to query Falco gRPC API if configured
            if (empty($events) && ! empty($this->config['grpc_endpoint'])) {
                // Note: A proper gRPC implementation would be more complex and require a gRPC client
                // For now, we'll use a simple socket connection if it's localhost
                if (str_starts_with($this->config['grpc_endpoint'], 'localhost:') ||
                    str_starts_with($this->config['grpc_endpoint'], '127.0.0.1:')) {

                    $port = (int) explode(':', $this->config['grpc_endpoint'])[1];
                    $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 1);

                    if ($socket) {
                        Log::info('Falco gRPC endpoint is reachable, but direct gRPC queries are not implemented');
                        fclose($socket);
                    }
                }
            }

            // If no events were found, return empty array
            if (empty($events)) {
                Log::info('No Falco events found in logs or via API');

                return [];
            }

            return $events;
        } catch (\Exception $e) {
            Log::error('Failed to get Falco events: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return [];
        }
    }

    /**
     * Get monitoring events in standardized SecurityEventData format
     *
     * @param  int  $limit  Maximum number of events to return
     * @return array<SecurityEventData>
     */
    public function getMonitoringEvents(int $limit = 10): array
    {
        // If we have in-memory events from streaming, use those first
        if (! empty($this->recentEvents)) {
            // Return the requested number of events (or all if fewer than limit)
            return array_slice($this->recentEvents, 0, $limit);
        }

        // Fall back to reading from logs if no in-memory events
        $rawEvents = $this->getRawEvents($limit);

        $securityEvents = [];
        foreach ($rawEvents as $event) {
            $securityEvents[] = $this->resultToSecurityEventData($event);
        }

        return $securityEvents;
    }

    /**
     * Get monitoring options for this service
     */
    public function getMonitoringOptions(): array
    {
        return [
            'service' => 'falco',
            'description' => 'Runtime security monitoring',
            'supports_realtime' => true,
            'log_path' => $this->config['log_path'] ?? '/var/log/falco.log',
            'severity_filter' => $this->config['severity_filter'] ?? 'warning',
            'event_types' => ['behavioral', 'system', 'security'],
        ];
    }

    /**
     * Parse Falco logs into structured event data.
     */
    protected function parseFalcoLogs(string $logContent, int $limit): array
    {
        // Detect if the log is in JSON format
        $trimmedContent = trim($logContent);

        if (str_starts_with($trimmedContent, '{') || str_contains($logContent, '"output":"') || str_contains($logContent, '"rule":"')) {
            $events = FalcoOutputParser::parseJsonEvents($logContent);
        } else {
            $events = FalcoOutputParser::parseTextEvents($logContent);
        }

        // Limit the number of events returned
        return array_slice($events, 0, $limit);
    }

    /**
     * Filter events based on minimum severity level.
     */
    protected function filterEventsBySeverity(array $events, string $minSeverity): array
    {
        $severityLevels = [
            'emergency' => 0,
            'alert' => 1,
            'critical' => 2,
            'error' => 3,
            'warning' => 4,
            'notice' => 5,
            'info' => 6,
            'debug' => 7,
        ];

        $minLevel = $severityLevels[strtolower($minSeverity)] ?? 4; // Default to warning

        return array_filter($events, function ($event) use ($severityLevels, $minLevel) {
            $eventLevel = $severityLevels[strtolower($event['priority'] ?? 'info')] ?? 6;

            return $eventLevel <= $minLevel;
        });
    }

    /**
     * Parse journal output for Falco events.
     */
    protected function parseJournalOutput(string $output): array
    {
        $events = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }

            try {
                $entry = json_decode($line, true);

                if (json_last_error() === JSON_ERROR_NONE && isset($entry['MESSAGE'])) {
                    $message = $entry['MESSAGE'];

                    // Check if this is a Falco message
                    if (str_contains($message, 'Falco') ||
                        str_contains($message, 'Rule') ||
                        preg_match('/(Emergency|Alert|Critical|Error|Warning|Notice|Info|Debug)/', $message)) {

                        // Try to parse as JSON first
                        $falcoEvent = null;
                        if (str_starts_with(trim($message), '{')) {
                            try {
                                $falcoEvent = json_decode($message, true);
                            } catch (\Exception $e) {
                                // Not JSON, continue to text parsing
                            }
                        }

                        if ($falcoEvent === null) {
                            // Parse as text
                            $parsed = FalcoOutputParser::parseTextEvents($message);
                            if (! empty($parsed)) {
                                $falcoEvent = $parsed[0];
                            }
                        }

                        if ($falcoEvent) {
                            // Add timestamp from journal if event doesn't have one
                            if (! isset($falcoEvent['timestamp']) && isset($entry['__REALTIME_TIMESTAMP'])) {
                                $timestamp = (int) ($entry['__REALTIME_TIMESTAMP'] / 1000000); // Convert to seconds
                                $falcoEvent['timestamp'] = date('c', $timestamp);
                            }

                            $events[] = $falcoEvent;
                        }
                    }
                }
            } catch (\Exception $e) {
                // Skip problematic entries
                continue;
            }
        }

        return $events;
    }

    /**
     * Check if systemd is available.
     */
    protected function isSystemdAvailable(): bool
    {
        // Check for journalctl command
        $process = new \Symfony\Component\Process\Process(['which', 'journalctl']);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Check if Falco service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Check if Falco is installed on the system.
     */
    public function isInstalled(): bool
    {
        // In container environments, we need a more flexible detection method

        // First, check if Falco binary exists and responds
        $process = new \Symfony\Component\Process\Process(['falco', '--version']);
        $process->setTimeout(5);
        $process->run();

        if ($process->isSuccessful()) {
            return true;
        }

        // Check in common locations if the command is not in PATH
        $falcoPaths = [
            '/usr/bin/falco',
            '/usr/local/bin/falco',
            '/opt/falco/bin/falco',
            '/bin/falco',
        ];

        foreach ($falcoPaths as $path) {
            if (file_exists($path) && is_executable($path)) {
                $process = new \Symfony\Component\Process\Process([$path, '--version']);
                $process->setTimeout(5);
                $process->run();

                if ($process->isSuccessful()) {
                    return true;
                }
            }
        }

        // If we're in a container, also check if the binary exists but might not be fully functional
        if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
            foreach ($falcoPaths as $path) {
                if (file_exists($path) && is_executable($path)) {
                    // In containers, just having the binary might be enough
                    return true;
                }
            }
        }

        // Last resort: check if the Falco service exists (systemd)
        if (file_exists('/etc/systemd/system/falco.service') ||
            file_exists('/lib/systemd/system/falco.service')) {
            return true;
        }

        return false;
    }

    /**
     * Check if we're running in a container environment.
     *
     * Note: Use Perimeter::isRunningInContainer() instead for consistency
     */
    public function isRunningInContainer(): bool
    {
        // Use the Perimeter facade for consistent container detection
        return \Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer();
    }

    /**
     * Check if Falco is properly configured.
     */
    public function isConfigured(): bool
    {
        // If not installed, it can't be properly configured
        if (! $this->isInstalled()) {
            return false;
        }

        // Check if Falco help works - this doesn't require a running service
        $process = new \Symfony\Component\Process\Process(['falco', '--help']);
        $process->setTimeout(5);
        $process->run();

        if (! $process->isSuccessful()) {
            // Try with full path if 'falco' command failed
            $falcoPaths = [
                '/usr/bin/falco',
                '/usr/local/bin/falco',
                '/opt/falco/bin/falco',
                '/bin/falco',
            ];

            $helpSucceeded = false;
            foreach ($falcoPaths as $path) {
                if (file_exists($path)) {
                    $process = new \Symfony\Component\Process\Process([$path, '--help']);
                    $process->setTimeout(5);
                    $process->run();
                    if ($process->isSuccessful()) {
                        $helpSucceeded = true;
                        break;
                    }
                }
            }

            if (! $helpSucceeded) {
                // If help command fails with all paths, check if service exists
                if (! (file_exists('/etc/systemd/system/falco.service') ||
                    file_exists('/lib/systemd/system/falco.service'))) {
                    // If no service exists either, then it's not configured
                    Log::warning('Falco help command failed and no service found');

                    return false;
                }
            }
        }

        // Check for common Falco configuration files
        $configFiles = [
            '/etc/falco/falco.yaml',
            '/etc/falco/falco_rules.yaml',
            '/etc/falco/falco_rules.local.yaml',
            '/etc/falco/k8s_audit_rules.yaml',
            '/etc/falco/config.d/driver.yaml', // Created by falcoctl
        ];

        $configExists = false;
        foreach ($configFiles as $configFile) {
            if (file_exists($configFile)) {
                $configExists = true;
                break;
            }
        }

        // If no config files exist, check for systemd service
        if (! $configExists) {
            if (file_exists('/etc/systemd/system/falco.service') ||
                file_exists('/lib/systemd/system/falco.service')) {
                Log::info('No Falco config files found but service exists');

                return true;
            }

            // If no service exists, log the missing config
            Log::warning('Falco configuration files not found in expected locations');

            return false;
        }

        // At this point we know Falco is installed and configured
        return true;
    }

    /**
     * Check if the service is currently monitoring.
     */
    public function isMonitoring(): bool
    {
        try {
            // Check if there's a PID file for a background process
            $pidFile = sys_get_temp_dir().'/perimeter_falco.pid';

            if (file_exists($pidFile)) {
                $pid = (int) file_get_contents($pidFile);

                if ($pid > 0) {
                    // Check if process is still running
                    $checkProcess = new \Symfony\Component\Process\Process(['ps', '-p', $pid]);
                    $checkProcess->run();

                    return $checkProcess->isSuccessful();
                }
            }

            // If no PID file, check if Falco is running via multiple methods
            
            // Method 1: Check modern eBPF service FIRST (PRIORITY CHECK - we know this is running)
            $process = new \Symfony\Component\Process\Process(['systemctl', 'is-active', 'falco-modern-bpf.service']);
            $process->run();
            
            // Check output content regardless of exit code (systemctl sometimes returns non-zero but still outputs 'active')
            $output = trim($process->getOutput());
            if ($output === 'active') {
                return true;
            }

            // Method 2: Check standard falco service
            $process = new \Symfony\Component\Process\Process(['systemctl', 'is-active', 'falco.service']);
            $process->run();
            
            $output = trim($process->getOutput());
            if ($output === 'active') {
                return true;
            }

            // Method 3: Check pgrep for falco process
            $process = new \Symfony\Component\Process\Process(['pgrep', 'falco']);
            $process->run();

            if ($process->isSuccessful()) {
                return true;
            }
            
            // Fallback: Check if any falco process is running via ps
            $process = new \Symfony\Component\Process\Process(['ps', 'aux']);
            $process->run();
            if ($process->isSuccessful() && strpos($process->getOutput(), 'falco') !== false) {
                return true;
            }

            // For container environments, we need additional checks
            if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                // Check if the log file exists and is being written to
                $logPath = $this->config['log_path'] ?? '/var/log/falco/falco.log';

                if (file_exists($logPath)) {
                    // If the log file was modified in the last 10 minutes, consider it running
                    $lastModified = filemtime($logPath);
                    $tenMinutesAgo = time() - 600;

                    if ($lastModified >= $tenMinutesAgo) {
                        return true;
                    }
                }

                // As a fallback for containers, just check if the binary works
                $versionProcess = new \Symfony\Component\Process\Process(['falco', '--version']);
                $versionProcess->run();

                if ($versionProcess->isSuccessful()) {
                    // In containers, if the binary works, we'll consider it "monitoring capable"
                    // This is less strict for container environments
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Error checking if Falco is monitoring: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Get the current status of the service.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $enabled = $this->isEnabled();
        $installed = $this->isInstalled();
        $configured = $this->isConfigured();
        $running = $this->isMonitoring();

        // Get version if installed
        $version = null;
        if ($installed) {
            try {
                $process = new \Symfony\Component\Process\Process(['falco', '--version']);
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();
                    // Extract version from output
                    if (preg_match('/(\d+\.\d+\.\d+)/', $output, $matches)) {
                        $version = $matches[1];
                    }
                }
            } catch (\Exception $e) {
                Log::warning('Error getting Falco version: '.$e->getMessage());
            }
        }

        // Get custom rules configuration
        $rules = [];
        if (! empty($this->config['custom_rules'])) {
            $rules = $this->config['custom_rules'];
        }

        // Create message
        $message = '';
        if (! $enabled) {
            $message = 'Falco monitoring is disabled in configuration.';
        } elseif (! $installed) {
            $message = 'Falco is not installed on the system.';
        } elseif (! $configured) {
            $message = 'Falco is installed but not properly configured.';
        } elseif (! $running) {
            $message = 'Falco is installed and configured but not currently monitoring.';
        } else {
            $message = 'Falco is active and monitoring for suspicious activities.';
        }

        // Get recent events (limited to a few to avoid performance issues)
        $recentEvents = [];
        if ($enabled && $installed && $configured) {
            $recentEvents = $this->getRecentEvents(3);
        }

        // Build details array with monitor-specific information
        $details = [
            'version' => $version,
            'rules' => $rules,
            'recent_events' => $recentEvents,
        ];

        // Falco can be functional even when not actively monitoring (runtime security is optional)
        // Consider it functional if installed, configured and systemd service is running
        $functional = null;
        if ($enabled && $installed && $configured) {
            // Check if systemd service is running even if isMonitoring() returns false
            $process = new \Symfony\Component\Process\Process(['systemctl', 'is-active', 'falco-modern-bpf.service']);
            $process->run();
            $systemdActive = trim($process->getOutput()) === 'active';
            
            if (!$systemdActive) {
                // Also check standard falco service
                $process = new \Symfony\Component\Process\Process(['systemctl', 'is-active', 'falco.service']);
                $process->run();
                $systemdActive = trim($process->getOutput()) === 'active';
            }
            
            $functional = $systemdActive;
        }

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'falco',
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
     * Get sample events for testing purposes only.
     * This method should NOT be used in production code.
     */
    protected function getSampleEvents(int $limit): array
    {
        // This method exists only for testing purposes
        // In production code, we now return an empty array instead
        // to prevent false positives

        $events = [
            [
                'rule' => 'laravel_suspicious_file_write',
                'priority' => 'critical',
                'description' => '[TEST ONLY] Suspicious file write detected in system directory',
                'process' => 'php',
                'user' => 'www-data',
                'timestamp' => now()->subMinutes(5)->toIso8601String(),
                'details' => [
                    'path' => '/etc/passwd',
                    'command' => 'php artisan tinker',
                    'sample_data' => true,
                ],
            ],
            [
                'rule' => 'privilege_escalation',
                'priority' => 'emergency',
                'description' => '[TEST ONLY] Privilege escalation attempt detected',
                'process' => 'sudo',
                'user' => 'www-data',
                'timestamp' => now()->subMinutes(20)->toIso8601String(),
                'details' => [
                    'command' => 'sudo su -',
                    'sample_data' => true,
                ],
            ],
        ];

        // Return a subset of events
        return array_slice($events, 0, min($limit, count($events)));
    }

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool
    {
        Log::info('Installing Falco with minimal configuration');

        // Check if already installed and not forcing reinstall
        if ($this->isInstalled() && ! ($options['force'] ?? false)) {
            Log::info('Falco is already installed. Use --force to reinstall.');
            return true;
        }

        // Store force flag if provided
        if ($options['force'] ?? false) {
            $this->config['force'] = true;
        }

        // Critical step: Install Falco repository and package
        try {
            if (! $this->installPackages()) {
                Log::error('Failed to install Falco packages - this is a critical failure');
                return false;
            }
        } catch (\Exception $e) {
            Log::error('Critical failure installing Falco packages: '.$e->getMessage());
            return false;
        }

        // Optional steps: Don't fail installation if these have issues
        try {
            $this->createRequiredDirectories();
        } catch (\Exception $e) {
            Log::warning('Failed to create directories (non-critical): '.$e->getMessage());
        }

        try {
            $this->copyConfigurationFiles();
        } catch (\Exception $e) {
            Log::warning('Failed to copy configuration files (non-critical): '.$e->getMessage());
        }

        try {
            $this->copySystemdService();
        } catch (\Exception $e) {
            Log::warning('Failed to copy systemd service (non-critical): '.$e->getMessage());
        }

        // Optional: Start service if requested
        if ($options['start'] ?? true) {
            try {
                $this->startService();
            } catch (\Exception $e) {
                Log::warning('Failed to start service (non-critical): '.$e->getMessage());
            }
        }

        // Final verification: Check if Falco is actually installed
        if ($this->isInstalled()) {
            Log::info('Falco installation completed successfully');
            return true;
        } else {
            Log::error('Falco installation verification failed - package not detected');
            return false;
        }
    }

    /**
     * Create directory with parents if it doesn't exist
     */
    protected function mkdir_p(string $dir, int $mode = 0755): void
    {
        if (! is_dir($dir)) {
            mkdir($dir, $mode, true);
            chmod($dir, $mode);
        }
    }

    /**
     * Copy configuration files from templates
     */
    protected function copyConfigurationFiles(): void
    {
        Log::info('Copying Falco configuration files');

        // Find template files in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/config/falco',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/config/falco'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/config/falco'),
        ];

        // Copy each configuration file if it exists in template locations
        foreach ($locations as $location) {
            if (file_exists($location.'/falco.yaml')) {
                Log::info("Copying falco.yaml from $location");
                copy($location.'/falco.yaml', '/etc/falco/falco.yaml');
            }

            if (file_exists($location.'/falco_rules.local.yaml')) {
                Log::info("Copying falco_rules.local.yaml from $location");
                copy($location.'/falco_rules.local.yaml', '/etc/falco/falco_rules.local.yaml');
            }

            if (file_exists($location.'/laravel-rules.yaml')) {
                Log::info("Copying laravel-rules.yaml from $location");
                copy($location.'/laravel-rules.yaml', '/etc/falco/rules.d/laravel-rules.yaml');
            }

            // If we found and copied files, break out of the loop
            if (file_exists('/etc/falco/falco.yaml') ||
                file_exists('/etc/falco/falco_rules.local.yaml') ||
                file_exists('/etc/falco/rules.d/laravel-rules.yaml')) {
                break;
            }
        }
    }

    /**
     * Copy systemd service file
     */
    protected function copySystemdService(): void
    {
        Log::info('Copying Falco systemd service file');

        // Find template files in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/systemd/falco',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/systemd/falco'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/systemd/falco'),
        ];

        // Copy systemd service file if it exists in template locations
        foreach ($locations as $location) {
            if (file_exists($location.'/falco.service')) {
                Log::info("Copying falco.service from $location");
                copy($location.'/falco.service', '/etc/systemd/system/falco.service');
                break;
            }
        }
    }

    /**
     * Update configuration from options.
     */
    protected function updateConfigFromOptions(array $options): void
    {
        // Update configuration with provided options
        if (isset($options['web_dir'])) {
            $this->config['web_dir'] = $options['web_dir'];
        }

        if (isset($options['log_path'])) {
            $this->config['log_path'] = $options['log_path'];
        }

        if (isset($options['rules_dir'])) {
            $this->config['rules_dir'] = $options['rules_dir'];
        }

        if (isset($options['config_dir'])) {
            $this->config['config_dir'] = $options['config_dir'];
        }

        if (isset($options['service_name'])) {
            $this->config['service_name'] = $options['service_name'];
        }

        if (isset($options['restart_sec'])) {
            $this->config['restart_sec'] = $options['restart_sec'];
        }

        // Set force flag if provided
        if (isset($options['force'])) {
            $this->config['force'] = $options['force'];
        }
    }

    /**
     * Install Falco packages.
     */
    protected function installPackages(): bool
    {
        try {
            // Configure Falco repository if needed
            if (! file_exists('/etc/apt/sources.list.d/falcosecurity.list')) {
                Log::info('Configuring Falco repository');
                $repoProcess = new \Symfony\Component\Process\Process([
                    'bash', '-c',
                    'echo "deb [trusted=yes] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list',
                ]);
                $repoProcess->run();

                if (! $repoProcess->isSuccessful()) {
                    Log::error('Failed to configure Falco repository: '.$repoProcess->getErrorOutput());

                    return false;
                }
            }

            // Update package lists
            Log::info('Updating package lists');
            $updateProcess = new \Symfony\Component\Process\Process(['apt-get', 'update']);
            $updateProcess->setTimeout(300);
            $updateProcess->run();

            // Install Falco package
            Log::info('Installing Falco package');
            $env = ['DEBIAN_FRONTEND' => 'noninteractive'];
            $installProcess = new \Symfony\Component\Process\Process(['apt-get', 'install', '-y', 'falco']);
            $installProcess->setTimeout(600);
            $installProcess->setEnv($env);
            $installProcess->run();

            if (! $installProcess->isSuccessful()) {
                Log::error('Failed to install Falco package: '.$installProcess->getErrorOutput());

                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error installing Falco packages: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Create required directories for Falco.
     */
    protected function createRequiredDirectories(): void
    {
        $logPath = $this->config['log_path'] ?? '/var/log/falco';
        $rulesDir = $this->config['rules_dir'] ?? '/etc/falco/rules.d';
        $configDir = $this->config['config_dir'] ?? '/etc/falco';

        // Create directories with appropriate permissions
        $directories = [
            '/var/run/falco' => 0755,
            $logPath => 0755,
            $rulesDir => 0755,
            $configDir => 0755,
        ];

        foreach ($directories as $dir => $permissions) {
            if (! \Illuminate\Support\Facades\File::isDirectory($dir)) {
                Log::info("Creating directory: $dir");
                \Illuminate\Support\Facades\File::makeDirectory($dir, $permissions, true, true);
            }
        }
    }

    /**
     * Create or update Falco configuration.
     */
    protected function createConfiguration(): void
    {
        Log::info('Creating/updating Falco configuration');

        $webDir = $this->config['web_dir'] ?? '/var/www';
        $logPath = $this->config['log_path'] ?? '/var/log/falco';
        $rulesDir = $this->config['rules_dir'] ?? '/etc/falco/rules.d';
        $configDir = $this->config['config_dir'] ?? '/etc/falco';

        // Determine paths for configuration files
        $falcoConfigPath = "$configDir/falco.yaml";
        $falcoRulesPath = "$configDir/falco_rules.local.yaml";
        $laravelRulesPath = "$rulesDir/laravel-rules.yaml";

        // Create or update main Falco configuration
        $this->createFalcoConfig($falcoConfigPath, $logPath);

        // Create or update Falco rules
        $this->createFalcoRules($falcoRulesPath, $webDir);

        // Create or update Laravel-specific rules
        $this->createLaravelRules($laravelRulesPath);
    }

    /**
     * Create Falco main configuration file.
     */
    protected function createFalcoConfig(string $configPath, string $logPath): void
    {
        $forceRecreate = $this->config['force'] ?? false;

        // If file doesn't exist or force flag is set, create new configuration
        if (! file_exists($configPath) || $forceRecreate) {
            Log::info("Creating Falco configuration file: $configPath");

            // Get configuration from docker/config if available
            $dockerConfigPath = '/package/docker/config/falco/falco.yaml';
            if (file_exists($dockerConfigPath)) {
                // Copy and customize configuration
                $configContent = file_get_contents($dockerConfigPath);
                // Update log file path
                $configContent = preg_replace(
                    '/filename: .*$/',
                    "filename: $logPath/falco.log",
                    $configContent
                );

                file_put_contents($configPath, $configContent);
            } else {
                // Create default configuration
                $configContent = "# Falco configuration created by Perimeter\n\n";
                $configContent .= "driver:\n  enabled: false\n\n";
                $configContent .= "stdout_output:\n  enabled: true\n\n";
                $configContent .= "file_output:\n  enabled: true\n";
                $configContent .= "  keep_alive: true\n";
                $configContent .= "  filename: $logPath/falco.log\n";

                file_put_contents($configPath, $configContent);
            }
        }
    }

    /**
     * Create Falco rules file.
     */
    protected function createFalcoRules(string $rulesPath, string $webDir): void
    {
        $forceRecreate = $this->config['force'] ?? false;

        // If file doesn't exist or force flag is set, create new rules file
        if (! file_exists($rulesPath) || $forceRecreate) {
            Log::info("Creating Falco rules file: $rulesPath");

            // Get rules from docker/config if available
            $dockerRulesPath = '/package/docker/config/falco/falco_rules.local.yaml';
            if (file_exists($dockerRulesPath)) {
                // Copy and customize rules
                $rulesContent = file_get_contents($dockerRulesPath);
                // Update web directory in rules
                $rulesContent = str_replace('/var/www', $webDir, $rulesContent);

                file_put_contents($rulesPath, $rulesContent);
            } else {
                // Create default rules
                $rulesContent = "# Falco custom rules created by Perimeter\n\n";
                $rulesContent .= "- rule: Detect PHP Webshell\n";
                $rulesContent .= "  desc: Detect potential PHP webshell execution\n";
                $rulesContent .= "  condition: >\n";
                $rulesContent .= "    spawned_process and\n";
                $rulesContent .= "    proc.name = \"php\" and\n";
                $rulesContent .= "    (proc.cmdline contains \"exec\" or\n";
                $rulesContent .= "     proc.cmdline contains \"shell_exec\" or\n";
                $rulesContent .= "     proc.cmdline contains \"system\" or\n";
                $rulesContent .= "     proc.cmdline contains \"passthru\" or\n";
                $rulesContent .= "     proc.cmdline contains \"eval\")\n";
                $rulesContent .= "  output: >\n";
                $rulesContent .= "    Potential PHP webshell execution (user=%user.name command=%proc.cmdline file=%proc.cwd/%proc.name)\n";
                $rulesContent .= "  priority: WARNING\n";
                $rulesContent .= "  tags: [process, mitre_execution]\n";

                file_put_contents($rulesPath, $rulesContent);
            }
        }
    }

    /**
     * Create Laravel-specific rules.
     */
    protected function createLaravelRules(string $rulesPath): void
    {
        $forceRecreate = $this->config['force'] ?? false;

        // If file doesn't exist or force flag is set, create new rules file
        if (! file_exists($rulesPath) || $forceRecreate) {
            Log::info("Creating Laravel rules file: $rulesPath");

            // Get rules from docker/config if available
            $dockerRulesPath = '/package/docker/config/falco/laravel-rules.yaml';
            if (file_exists($dockerRulesPath)) {
                // Copy Laravel-specific rules
                $rulesContent = file_get_contents($dockerRulesPath);
                file_put_contents($rulesPath, $rulesContent);
            } else {
                // Create default Laravel rules
                $rulesContent = "# Laravel-specific Falco rules\n\n";
                $rulesContent .= "- rule: Laravel Mass Assignment Attempt\n";
                $rulesContent .= "  desc: Detect potential mass assignment vulnerability exploitation\n";
                $rulesContent .= "  condition: proc.name = \"php\" and fd.name contains \"artisan\" and evt.type = execve and evt.arg.args contains \"mass\" and evt.arg.args contains \"assignment\"\n";
                $rulesContent .= "  output: Potential mass assignment vulnerability exploitation (user=%user.name process=%proc.name command=%proc.cmdline)\n";
                $rulesContent .= "  priority: high\n";
                $rulesContent .= "  tags: [application, laravel, security]\n";

                file_put_contents($rulesPath, $rulesContent);
            }
        }
    }

    /**
     * Setup systemd service for Falco.
     */
    protected function setupSystemdService(): void
    {
        $serviceName = $this->config['service_name'] ?? 'falco.service';
        $configDir = $this->config['config_dir'] ?? '/etc/falco';
        $rulesDir = $this->config['rules_dir'] ?? '/etc/falco/rules.d';
        $restartSec = $this->config['restart_sec'] ?? '10s';

        // Determine paths for systemd service files
        $serviceFilePath = "/etc/systemd/system/$serviceName";

        // Get the systemd service file from docker config
        $dockerServicePath = '/package/docker/systemd/falco/falco.service';
        if (file_exists($dockerServicePath)) {
            Log::info("Creating systemd service file: $serviceFilePath");

            // Copy and customize service file
            $serviceContent = file_get_contents($dockerServicePath);

            // Update RestartSec in service file
            $serviceContent = preg_replace(
                '/RestartSec=\d+s/',
                "RestartSec=$restartSec",
                $serviceContent
            );

            // Update ExecStart with configuration and rules paths
            $execStart = "/usr/bin/falco --pidfile=/var/run/falco.pid -c $configDir/falco.yaml -r $rulesDir/laravel-rules.yaml";
            $serviceContent = preg_replace(
                '/ExecStart=.*$/',
                "ExecStart=$execStart",
                $serviceContent
            );

            file_put_contents($serviceFilePath, $serviceContent);
        } else {
            // Create a basic service file
            Log::info("Creating basic systemd service file: $serviceFilePath");
            $serviceContent = "[Unit]\n";
            $serviceContent .= "Description=Falco - Cloud Native Runtime Security\n";
            $serviceContent .= "After=network.target\n\n";
            $serviceContent .= "[Service]\n";
            $serviceContent .= "Type=simple\n";
            $serviceContent .= "ExecStart=/usr/bin/falco --pidfile=/var/run/falco.pid -c $configDir/falco.yaml -r $rulesDir/laravel-rules.yaml\n";
            $serviceContent .= "Restart=on-failure\n";
            $serviceContent .= "RestartSec=$restartSec\n";
            $serviceContent .= "TimeoutStopSec=30s\n";
            $serviceContent .= "StartLimitInterval=0\n";
            $serviceContent .= "LimitNPROC=infinity\n";
            $serviceContent .= "LimitCORE=infinity\n\n";
            $serviceContent .= "[Install]\n";
            $serviceContent .= "WantedBy=multi-user.target\n";

            file_put_contents($serviceFilePath, $serviceContent);
        }
    }

    /**
     * Start the Falco service.
     */
    protected function startService(): bool
    {
        try {
            $serviceName = $this->config['service_name'] ?? 'falco.service';

            // Reload systemd to pick up new service files
            Log::info('Reloading systemd daemon');
            $reloadProcess = new \Symfony\Component\Process\Process(['systemctl', 'daemon-reload']);
            $reloadProcess->run();

            // Enable the Falco service
            Log::info("Enabling $serviceName");
            $enableProcess = new \Symfony\Component\Process\Process(['systemctl', 'enable', $serviceName]);
            $enableProcess->run();

            // Check if systemd service exists and try to start it
            Log::info("Starting $serviceName");
            $startProcess = new \Symfony\Component\Process\Process(['systemctl', 'start', $serviceName]);
            $startProcess->run();

            if ($startProcess->isSuccessful()) {
                Log::info("Successfully started $serviceName via systemd");
                return true;
            } else {
                Log::warning("Failed to start $serviceName via systemd: ".$startProcess->getErrorOutput());
                
                // Fallback: try to start Falco directly for container/driver compatibility
                Log::info('Attempting to start Falco directly as fallback');
                return $this->startFalcoDirect();
            }
        } catch (\Exception $e) {
            Log::error('Error starting Falco service: '.$e->getMessage());
            return false;
        }
    }

    /**
     * Start Falco directly without systemd (fallback for environments with driver issues)
     */
    protected function startFalcoDirect(): bool
    {
        try {
            // Try to start Falco with userspace driver for maximum compatibility
            $configPath = '/etc/falco/falco.yaml';
            $command = [
                'falco',
                '--config', $configPath,
                '--option', 'engine.kind=modern_ebpf',  // Use eBPF if available
                '--daemon'
            ];

            $process = new \Symfony\Component\Process\Process($command);
            $process->setTimeout(30);
            $process->start();

            // Give Falco time to start
            sleep(2);

            // Check if it's actually running
            if ($this->isMonitoring()) {
                Log::info('Falco started successfully in direct mode');
                return true;
            } else {
                Log::warning('Falco failed to start in direct mode');
                return false;
            }
        } catch (\Exception $e) {
            Log::error('Error starting Falco directly: '.$e->getMessage());
            return false;
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
     * Convert a behavioral analysis result to a SecurityEventData instance.
     *
     * @param  array  $data  Behavioral analysis result data
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData
    {
        $timestamp = $data['timestamp'] ?? now();
        $severity = strtolower($data['priority'] ?? $data['severity'] ?? 'critical');
        $description = $data['description'] ?? 'Suspicious behavior detected';
        $process = $data['process'] ?? null;
        $user = $data['user'] ?? null;
        $scanId = $data['scan_id'] ?? null;

        $details = array_merge($data, [
            'rule' => $data['rule'] ?? null,
            'process' => $process,
        ]);

        // Remove fields that will be used in the main properties
        unset($details['timestamp'], $details['severity'], $details['priority'],
            $details['description'], $details['location'], $details['user'],
            $details['service'], $details['scan_id']);

        return new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: $timestamp,
            type: 'behavioral',
            severity: $severity,
            description: $description,
            location: $process ? "process:{$process}" : null,
            user: $user,
            service: $this->getServiceName(),
            scan_id: $scanId,
            details: $details
        );
    }
}
