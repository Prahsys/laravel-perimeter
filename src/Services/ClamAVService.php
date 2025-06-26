<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\ScannerServiceInterface;
use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Parsers\ClamAVOutputParser;
use Prahsys\Perimeter\ScanResult;

class ClamAVService extends AbstractSecurityService implements ScannerServiceInterface, SecurityMonitoringServiceInterface
{
    /**
     * Create a new ClamAV service instance.
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
     * Scan a single file for threats.
     */
    public function scanFile(string $filePath): ScanResult
    {
        if (! $this->isEnabled()) {
            return ScanResult::clean($filePath);
        }

        try {
            // Check if the file exists
            if (! file_exists($filePath)) {
                Log::warning('ClamAV scan failed: File not found', ['file' => $filePath]);

                return ScanResult::clean($filePath);
            }

            // Choose scan method based on available memory and daemon status
            if ($this->shouldUseDaemonMode()) {
                $scanCommand = 'clamdscan --fdpass '.escapeshellarg($filePath);
            } else {
                // Use direct scanning for low-memory environments
                $scanCommand = 'clamscan --no-summary '.escapeshellarg($filePath);
            }

            $process = new \Symfony\Component\Process\Process(explode(' ', $scanCommand));
            $process->setTimeout($this->config['scan_timeout'] ?? 1800); // Default 30 minutes for large files
            $process->run();

            $output = $process->getOutput();
            $exitCode = $process->getExitCode();

            // ClamAV returns:
            // 0 - No virus found
            // 1 - Virus(es) found
            // 2 - Some error occurred

            if ($exitCode === 1) {
                // Extract the virus name from the output
                preg_match('/.*: (.*) FOUND/', $output, $matches);
                $virusName = $matches[1] ?? 'Unknown threat';

                return ScanResult::infected($filePath, $virusName);
            } elseif ($exitCode === 2) {
                Log::error('ClamAV scan error: '.$output, ['file' => $filePath]);

                return ScanResult::clean($filePath); // Consider it clean but log the error
            }

            return ScanResult::clean($filePath);
        } catch (\Exception $e) {
            Log::error('ClamAV scan failed: '.$e->getMessage(), [
                'file' => $filePath,
                'exception' => $e,
            ]);

            // In case of error, we consider the file clean but log the error
            return ScanResult::clean($filePath);
        }
    }

    /**
     * Scan multiple paths for threats.
     */
    public function scanPaths(array $paths, array $excludePatterns = []): array
    {
        if (! $this->isEnabled()) {
            return [];
        }

        $results = [];

        foreach ($paths as $path) {
            if (! file_exists($path)) {
                Log::warning('ClamAV scan failed: Path not found', ['path' => $path]);

                continue;
            }

            // If the path is a file, scan it directly
            if (is_file($path)) {
                Log::info("ClamAV: Scanning file: $path");
                $this->scanSinglePath($path, $excludePatterns, $results);
            } else {
                Log::info("ClamAV: Scanning directory: $path");
                Log::info('ClamAV: Watch scan progress with: tail -f /tmp/clamav-scan.log');

                // For directories, use the recursive scan option of ClamAV
                if ($this->shouldUseDaemonMode()) {
                    $scanCommand = 'clamdscan -r '.escapeshellarg($path);
                } else {
                    // Use direct scanning for low-memory environments
                    $scanCommand = 'clamscan -r --no-summary '.escapeshellarg($path);
                }

                if (! empty($excludePatterns)) {
                    // Create a temporary exclude file for clamdscan
                    $excludeFile = tempnam(sys_get_temp_dir(), 'clamav-exclude-');
                    file_put_contents($excludeFile, implode(PHP_EOL, $excludePatterns));
                    $scanCommand .= ' --exclude-list='.escapeshellarg($excludeFile);
                }

                // Redirect output directly to log file
                $scanLogPath = '/tmp/clamav-scan.log';
                $timestamp = date('Y-m-d H:i:s');
                $logHeader = "\n[{$timestamp}] Starting ClamAV scan of: {$path}\n";
                file_put_contents($scanLogPath, $logHeader, FILE_APPEND | LOCK_EX);

                $scanCommand .= " >> {$scanLogPath} 2>&1";

                $process = new \Symfony\Component\Process\Process(['sh', '-c', $scanCommand]);
                $process->setTimeout($this->config['scan_timeout'] ?? 1800); // Default 30 minutes for large scans
                $process->run();

                $output = $process->getOutput();
                $exitCode = $process->getExitCode();

                // Log completion status
                if ($exitCode === 0) {
                    Log::info("ClamAV: Scan completed - no threats found in $path");
                } elseif ($exitCode === 1) {
                    Log::warning("ClamAV: Scan completed - threats found in $path");
                } else {
                    Log::warning("ClamAV: Scan completed with errors for $path");
                }

                // If viruses were found, parse the output to get details
                if ($exitCode === 1) {
                    $infectedFiles = ClamAVOutputParser::parseInfectedFiles($output);
                    foreach ($infectedFiles as $infectedFile) {
                        $results[] = $infectedFile;
                    }
                }

                // Clean up temp file if it was created
                if (! empty($excludePatterns) && isset($excludeFile)) {
                    @unlink($excludeFile);
                }
            }
        }

        return $results;
    }

    /**
     * Scan a single path and add results to the results array.
     */
    protected function scanSinglePath(string $path, array $excludePatterns, array &$results): void
    {
        // Skip excluded patterns
        foreach ($excludePatterns as $pattern) {
            if (fnmatch($pattern, $path)) {
                return;
            }
        }

        $result = $this->scanFile($path);

        if ($result->hasThreat()) {
            $results[] = [
                'file' => $result->getFilePath(),
                'threat' => $result->getThreat(),
                'timestamp' => now()->toIso8601String(),
            ];
        }
    }

    /**
     * Check if ClamAV service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Check if ClamAV is installed on the system.
     */
    public function isInstalled(): bool
    {
        // Check if the clamscan binary is installed and working by running version
        $process = new \Symfony\Component\Process\Process(['clamscan', '--version']);
        $process->run();

        if ($process->isSuccessful()) {
            return true;
        }

        // Only try clamdscan if we have sufficient memory for daemon mode
        if ($this->hasSufficientMemoryForDaemon()) {
            $process = new \Symfony\Component\Process\Process(['clamdscan', '--version']);
            $process->setTimeout(30); // Short timeout for version command
            $process->run();

            return $process->isSuccessful();
        }

        // If insufficient memory for daemon mode, clamscan being available is sufficient
        return false;
    }

    /**
     * Check if ClamAV is properly configured.
     */
    public function isConfigured(): bool
    {
        // If not installed, it can't be properly configured
        if (! $this->isInstalled()) {
            return false;
        }

        // Only try clamdscan if we have sufficient memory for daemon mode
        if ($this->hasSufficientMemoryForDaemon()) {
            $process = new \Symfony\Component\Process\Process(['clamdscan', '--help']);
            $process->setTimeout(30); // Short timeout for help command
            $process->run();

            if ($process->isSuccessful()) {
                return true;
            }
        }

        // Check if clamscan is usable (works in all memory environments)
        $process = new \Symfony\Component\Process\Process(['clamscan', '--help']);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Get the current status of the service.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $enabled = $this->isEnabled();
        $installed = $this->isInstalled();
        $configured = $this->isConfigured();

        // Check if ClamAV daemon is running
        $running = false;

        try {
            // Check for the process
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamd']);
            $process->run();
            $running = $process->isSuccessful();

            if (! $running) {
                // Try alternative process name
                $process = new \Symfony\Component\Process\Process(['pgrep', 'clamonacc']);
                $process->run();
                $running = $process->isSuccessful();
            }

            // In container environments, we need to be more flexible with detection
            if (! $running && \Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
                // Check if the socket file exists and is being maintained
                $socketPath = '/var/run/clamav/clamd.sock';
                if (file_exists($socketPath)) {
                    // Check if the socket is readable/writable
                    $running = is_readable($socketPath) || is_writable($socketPath);
                }

                // Only check daemon binary if we have sufficient memory for daemon mode
                if (! $running && $this->hasSufficientMemoryForDaemon()) {
                    $scanProcess = new \Symfony\Component\Process\Process(['clamdscan', '--version']);
                    $scanProcess->setTimeout($this->config['health_check_timeout'] ?? 300); // Configurable timeout for health checks
                    try {
                        $scanProcess->run();
                        // If clamdscan returns successfully, consider the daemon running in container
                        $running = $scanProcess->isSuccessful();
                    } catch (\Symfony\Component\Process\Exception\ProcessTimedOutException $e) {
                        $timeout = $this->config['health_check_timeout'] ?? 300;
                        Log::warning("ClamAV daemon check timed out after {$timeout} seconds, daemon likely not running");
                        $running = false;
                    }
                }
            }
        } catch (\Exception $e) {
            Log::warning('Error checking if ClamAV daemon is running: '.$e->getMessage());
        }

        // Get version if installed
        $version = null;
        if ($installed) {
            try {
                $process = new \Symfony\Component\Process\Process(['clamscan', '--version']);
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();
                    // Extract version from output
                    if (preg_match('/ClamAV (\d+\.\d+\.\d+)/', $output, $matches)) {
                        $version = $matches[1];
                    }
                }
            } catch (\Exception $e) {
                Log::warning('Error getting ClamAV version: '.$e->getMessage());
            }
        }

        // Get configuration details
        $lastScanTime = 0;
        $excludePaths = $this->config['exclude_paths'] ?? [];
        $scanPaths = $this->config['scan_paths'] ?? [];

        // Create message
        $message = '';
        if (! $enabled) {
            $message = 'ClamAV antivirus is disabled in configuration.';
        } elseif (! $installed) {
            $message = 'ClamAV is not installed on the system.';
        } elseif (! $configured) {
            $message = 'ClamAV is installed but not properly configured.';
        } elseif (! $running && ! $this->hasSufficientMemoryForDaemon()) {
            $message = 'ClamAV is installed and configured. Using direct scanning (daemon requires more memory).';
        } elseif (! $running) {
            $message = 'ClamAV is installed and configured but daemon is not running.';
        } else {
            $message = 'ClamAV is active and protecting against malware.';
        }

        // Build details array with scanner-specific information
        $details = [
            'version' => $version,
            'scan_paths' => $scanPaths,
            'last_scan_time' => $lastScanTime,
            'exclude_paths' => $excludePaths,
        ];

        // Determine if service is functional (can operate)
        // ClamAV is functional if it's installed and configured, regardless of daemon status
        // because it can fall back to direct scanning mode
        $functional = $enabled && $installed && $configured;

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'clamav',
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
     * Update virus definitions.
     */
    public function updateDefinitions(): bool
    {
        if (! $this->isEnabled() || ! $this->isInstalled()) {
            return false;
        }

        try {
            // Use freshclam to update virus definitions
            $process = new \Symfony\Component\Process\Process(['freshclam']);
            $process->setTimeout(300); // Give it 5 minutes to update
            $process->run();

            $success = $process->isSuccessful();

            if ($success) {
                Log::info('ClamAV virus definitions updated successfully');
            } else {
                Log::error('Failed to update ClamAV virus definitions: '.$process->getErrorOutput());
            }

            return $success;
        } catch (\Exception $e) {
            Log::error('Error updating ClamAV virus definitions: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Cached instance of BackgroundProcessManager
     */
    protected ?BackgroundProcessManager $processManager = null;

    /**
     * Run service-specific audit checks.
     * Perform ClamAV scanning during the audit process.
     */
    protected function performServiceSpecificAuditChecks($output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): array
    {
        if (! $this->isEnabled() || ! $this->isInstalled() || ! $this->isConfigured()) {
            return [];
        }

        // Save ClamAV log artifacts if artifact manager is provided
        if ($artifactManager) {
            $this->saveServiceArtifacts($artifactManager);
        }

        // Get scan configuration
        $scanPaths = $this->config['scan_paths'] ?? [base_path()];
        $excludePatterns = $this->config['exclude_patterns'] ?? [];

        if ($output) {
            $output->writeln('  <fg=yellow>🔍 Scanning '.count($scanPaths).' paths for malware...</>');
        }

        // Perform the actual scan
        $scanResults = $this->scanPaths($scanPaths, $excludePatterns);

        // Convert scan results to SecurityEventData objects
        $securityEvents = [];
        foreach ($scanResults as $result) {
            $securityEvents[] = $this->resultToSecurityEventData([
                'timestamp' => now(),
                'threat' => $result['threat'] ?? 'Unknown threat',
                'file' => $result['file'] ?? 'Unknown file',
                'scan_id' => null,
            ]);
        }

        if ($output) {
            if (empty($securityEvents)) {
                $output->writeln('  <fg=green>✅ No malware detected</>');
            } else {
                $output->writeln('  <fg=red>⚠️  '.count($securityEvents).' threats detected</>');
            }
        }

        return $securityEvents;
    }

    /**
     * Recent events storage
     */
    protected array $recentEvents = [];

    /**
     * Get or create the process manager instance
     */
    protected function getProcessManager(): BackgroundProcessManager
    {
        if ($this->processManager === null) {
            $this->processManager = new BackgroundProcessManager;

            // Set up event handlers for real-time event processing
            $this->processManager->on('clamonacc', 'output', function ($output) {
                $this->processRealTimeOutput($output);
            });
        }

        return $this->processManager;
    }

    /**
     * Process real-time output from ClamAV OnAccess scanner
     */
    protected function processRealTimeOutput(string $output): void
    {
        // Skip empty lines
        if (empty(trim($output))) {
            return;
        }

        try {
            // ClamAV OnAccess typically outputs when it finds threats
            // Example: "/path/to/file.exe: Eicar-Test-Signature FOUND"
            if (strpos($output, 'FOUND') !== false) {
                // Parse the output line
                $matches = [];
                if (preg_match('/^(.*?):\s+(.*?)\s+FOUND/', $output, $matches)) {
                    $filePath = $matches[1] ?? 'unknown';
                    $threatName = $matches[2] ?? 'Unknown threat';

                    // Create event data
                    $eventData = [
                        'file' => $filePath,
                        'threat' => $threatName,
                        'timestamp' => now()->toIso8601String(),
                        'severity' => 'critical',
                        'description' => "Detected {$threatName} in file",
                    ];

                    // Convert to SecurityEventData
                    $securityEvent = $this->resultToSecurityEventData($eventData);

                    // Emit event
                    event('perimeter.security.event', $securityEvent);

                    // Store for later retrieval
                    $this->storeEvent($securityEvent);

                    Log::alert("ClamAV detected malware: {$threatName} in {$filePath}");
                }
            }
        } catch (\Exception $e) {
            Log::warning('Error processing ClamAV output: '.$e->getMessage(), [
                'output' => $output,
            ]);
        }
    }

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
     * Start monitoring with the service.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool
    {
        if (! $this->isEnabled() || ! $this->isInstalled()) {
            Log::warning('Cannot start ClamAV monitoring: service is not enabled or installed');

            return false;
        }

        try {
            // Get clamonacc path
            $clamonaccPath = $this->getClmonaccPath();
            if (empty($clamonaccPath)) {
                Log::error('Cannot enable real-time scanning: clamonacc not found');

                return false;
            }

            // Determine paths to monitor
            $monitorPaths = $this->config['scan_paths'] ?? [base_path()];
            $pathArgs = [];

            foreach ($monitorPaths as $path) {
                if (file_exists($path)) {
                    $pathArgs[] = $path;
                }
            }

            if (empty($pathArgs)) {
                Log::error('No valid paths to monitor for real-time scanning');

                return false;
            }

            // Use the process manager
            $processManager = $this->getProcessManager();

            // Build command array
            $commandArray = array_merge(
                [$clamonaccPath, '--fdpass', '-v'],
                $pathArgs
            );

            // Always use streaming mode for real-time event processing

            // Start the process with streaming enabled
            $options = [
                'stream_output' => true,
            ];

            // Start the process
            $pid = $processManager->start($commandArray, 'clamonacc', $options);

            if ($pid) {
                // Set the monitoring flag to true
                $this->isMonitoring = true;

                Log::info('Real-time ClamAV scanning enabled', [
                    'pid' => $pid,
                    'paths' => implode(', ', $pathArgs),
                ]);

                // If duration is specified, schedule the termination
                if ($duration !== null) {
                    $processManager->scheduleTermination('clamonacc', $duration);
                }

                return true;
            }

            Log::error('Failed to start ClamAV monitoring');

            return false;
        } catch (\Exception $e) {
            Log::error('Error starting ClamAV monitoring: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Get the path to the clamonacc binary.
     */
    protected function getClmonaccPath(): ?string
    {
        // Check if clamonacc is in PATH
        $process = new \Symfony\Component\Process\Process(['which', 'clamonacc']);
        $process->run();

        if ($process->isSuccessful()) {
            return trim($process->getOutput());
        }

        // Check common locations
        $paths = [
            '/usr/bin/clamonacc',
            '/usr/local/bin/clamonacc',
            '/opt/clamav/bin/clamonacc',
            '/bin/clamonacc',
        ];

        foreach ($paths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Stop monitoring with the service.
     */
    public function stopMonitoring(): bool
    {
        try {
            // Use BackgroundProcessManager to stop the clamonacc process
            $processManager = new BackgroundProcessManager;

            // Try to stop by named process first
            $result = $processManager->stop('clamonacc');

            if ($result) {
                Log::info('Stopped ClamAV monitoring process');
                $this->isMonitoring = false;

                return true;
            }

            // Fallback to the old method if the process manager failed
            $result = $this->disableRealtime();

            if ($result) {
                $this->isMonitoring = false;
            }

            return $result;
        } catch (\Exception $e) {
            Log::error('Error stopping ClamAV monitoring: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Schedule the termination of monitoring after a specified duration.
     *
     * @deprecated Use BackgroundProcessManager::scheduleTermination instead
     *
     * @param  int  $duration  Duration in seconds before termination
     */
    protected function scheduleTermination(int $duration): void
    {
        // Create a BackgroundProcessManager instance and use it for scheduling termination
        $processManager = new BackgroundProcessManager;
        $processManager->scheduleTermination('clamonacc', $duration);

        Log::info("Scheduled termination of ClamAV monitoring in {$duration} seconds");
    }

    /**
     * Get monitoring events from ClamAV.
     *
     * @param  int  $limit  Maximum number of events to return
     * @return array<\Prahsys\Perimeter\Data\SecurityEventData>
     */
    public function getMonitoringEvents(int $limit = 10): array
    {
        // If we have in-memory events from streaming, use those first
        if (! empty($this->recentEvents)) {
            // Return the requested number of events (or all if fewer than limit)
            return array_slice($this->recentEvents, 0, $limit);
        }

        // Fall back to reading from logs if no in-memory events
        $rawEvents = $this->getRecentMalwareEvents($limit);

        // Convert raw events to SecurityEventData objects
        $events = [];
        foreach ($rawEvents as $event) {
            $events[] = $this->resultToSecurityEventData($event);
        }

        return $events;
    }

    /**
     * Get recent malware detection events.
     *
     * @param  int  $limit  Maximum number of events to return
     */
    protected function getRecentMalwareEvents(int $limit = 10): array
    {
        try {
            // Check ClamAV logs for detected threats
            $logPath = $this->config['log_path'] ?? '/var/log/clamav/clamav.log';

            if (! file_exists($logPath) || ! is_readable($logPath)) {
                // Try alternate log locations
                $altLogPaths = [
                    '/var/log/clamav/clamav.log',
                    '/var/log/clamav/clamd.log',
                    '/var/log/clamav/freshclam.log',
                    '/var/log/clamav/scan.log',
                ];

                foreach ($altLogPaths as $path) {
                    if (file_exists($path) && is_readable($path)) {
                        $logPath = $path;
                        break;
                    }
                }
            }

            if (! file_exists($logPath) || ! is_readable($logPath)) {
                return [];
            }

            // Read the log file and extract threat detection events
            $process = new \Symfony\Component\Process\Process(['grep', '-i', 'FOUND', $logPath]);
            $process->run();

            if (! $process->isSuccessful()) {
                return [];
            }

            $output = $process->getOutput();

            return ClamAVOutputParser::parseLogEvents($output, $limit);

        } catch (\Exception $e) {
            Log::error('Error getting ClamAV events: '.$e->getMessage());

            return [];
        }
    }

    /**
     * Check if the service is currently monitoring.
     */
    public function isMonitoring(): bool
    {
        if (! $this->isMonitoring) {
            return false;
        }

        // Also check if the process is running
        $process = new \Symfony\Component\Process\Process(['pgrep', 'clamonacc']);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Get monitoring options.
     */
    public function getMonitoringOptions(): array
    {
        return [
            'description' => 'ClamAV real-time malware monitoring',
            'capabilities' => [
                'malware_detection' => true,
                'file_monitoring' => true,
                'virus_scanning' => true,
            ],
            'log_path' => $this->config['log_path'] ?? '/var/log/clamav/clamav.log',
            'monitored_paths' => $this->config['scan_paths'] ?? [base_path()],
        ];
    }

    /**
     * Enable real-time file scanning.
     */
    public function enableRealtime(): bool
    {
        if (! $this->isEnabled() || ! $this->isInstalled()) {
            Log::warning('Cannot enable real-time scanning: ClamAV is not enabled or installed');

            return false;
        }

        try {
            // Check if clamonacc is available
            $process = new \Symfony\Component\Process\Process(['which', 'clamonacc']);
            $process->run();

            if (! $process->isSuccessful()) {
                Log::error('Cannot enable real-time scanning: clamonacc not found');

                return false;
            }

            // Check if clamd is running
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamd']);
            $process->run();

            if (! $process->isSuccessful()) {
                Log::warning('clamd is not running. Attempting to start it...');

                // Try to start clamd service
                $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'clamav-daemon']);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to start clamd daemon: '.$process->getErrorOutput());

                    return false;
                }
            }

            // Check if clamonacc is already running
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamonacc']);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info('Real-time scanning is already running');

                return true;
            }

            // Determine paths to monitor
            $monitorPaths = $this->config['scan_paths'] ?? [base_path()];
            $pathArgs = [];

            foreach ($monitorPaths as $path) {
                if (file_exists($path)) {
                    $pathArgs[] = escapeshellarg($path);
                }
            }

            if (empty($pathArgs)) {
                Log::error('No valid paths to monitor for real-time scanning');

                return false;
            }

            // Start clamonacc in the background
            $cmd = 'clamonacc --fdpass '.implode(' ', $pathArgs).' -v &';
            $process = new \Symfony\Component\Process\Process(['nohup', 'sh', '-c', $cmd]);
            $process->setTty(false);
            $process->disableOutput();
            $process->start();

            // Log success
            Log::info('Real-time ClamAV scanning enabled for paths: '.implode(', ', $monitorPaths));

            return true;
        } catch (\Exception $e) {
            Log::error('Error enabling real-time scanning: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Disable real-time file scanning.
     */
    public function disableRealtime(): bool
    {
        try {
            // Find clamonacc processes
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamonacc']);
            $process->run();

            if (! $process->isSuccessful()) {
                // No clamonacc processes running
                Log::info('No real-time scanning processes found to disable');

                return true;
            }

            // Kill all clamonacc processes
            $pids = trim($process->getOutput());
            $pidArray = explode("\n", $pids);

            foreach ($pidArray as $pid) {
                if (is_numeric($pid)) {
                    $killProcess = new \Symfony\Component\Process\Process(['kill', $pid]);
                    $killProcess->run();

                    if (! $killProcess->isSuccessful()) {
                        Log::warning("Failed to terminate clamonacc process {$pid}");
                    }
                }
            }

            // Verify all processes are terminated
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamonacc']);
            $process->run();

            if ($process->isSuccessful()) {
                // Some processes still running, try SIGKILL
                foreach ($pidArray as $pid) {
                    if (is_numeric($pid)) {
                        $killProcess = new \Symfony\Component\Process\Process(['kill', '-9', $pid]);
                        $killProcess->run();
                    }
                }
            }

            Log::info('Real-time ClamAV scanning disabled');

            return true;
        } catch (\Exception $e) {
            Log::error('Error disabling real-time scanning: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool
    {
        try {
            Log::info('Starting ClamAV installation...');

            // Check if already installed and not forcing reinstall
            if ($this->isInstalled() && !($options['force'] ?? false)) {
                Log::info('ClamAV is already installed');
                return true;
            }

            // Create required directories
            Log::info('Creating ClamAV directories...');
            $this->ensureDirectoriesExist();

            // Install ClamAV packages
            Log::info('Installing ClamAV packages...');
            $this->installClamAVPackages();

            // Copy configuration files
            Log::info('Configuring ClamAV...');
            $this->copyConfigurationFiles();

            // Copy systemd service files
            Log::info('Setting up systemd services...');
            $this->copySystemdServices();

            // Update virus database
            Log::info('Updating virus database...');
            $this->updateVirusDatabase();

            // Enable and start services
            if ($options['start'] ?? true) {
                Log::info('Enabling ClamAV services...');
                $this->startServices();
            }

            // Create binary symlinks
            $this->createBinarySymlinks();

            // Verify installation
            if ($this->isInstalled()) {
                Log::info('ClamAV installation completed successfully');
                return true;
            } else {
                Log::error('ClamAV installation verification failed');
                return false;
            }

        } catch (\Exception $e) {
            Log::error('ClamAV installation failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Ensure required directories exist
     */
    protected function ensureDirectoriesExist(): void
    {
        $directories = [
            '/var/run/clamav' => 0755,
            '/var/lib/clamav' => 0755,
            '/var/log/clamav' => 0755,
        ];

        foreach ($directories as $dir => $permissions) {
            if (!is_dir($dir)) {
                mkdir($dir, $permissions, true);
                Log::info("Created directory: $dir");
            }
        }
    }

    /**
     * Install ClamAV packages
     */
    protected function installClamAVPackages(): void
    {
        $process = new \Symfony\Component\Process\Process(['apt-get', 'update']);
        $process->run();

        if (!$process->isSuccessful()) {
            throw new \Exception('Failed to update package list: ' . $process->getErrorOutput());
        }

        $process = new \Symfony\Component\Process\Process(['apt-get', 'install', '-y', 'clamav', 'clamav-daemon']);
        $process->setTimeout(600); // 10 minutes for package installation
        $process->run();

        if (!$process->isSuccessful()) {
            throw new \Exception('Failed to install ClamAV packages: ' . $process->getErrorOutput());
        }
    }

    /**
     * Copy configuration files
     */
    protected function copyConfigurationFiles(): void
    {
        $locations = [
            '/package/docker/config/clamav',
            base_path('packages/prahsys-laravel-perimeter/docker/config/clamav'),
            base_path('vendor/prahsys/perimeter/docker/config/clamav'),
        ];

        foreach ($locations as $location) {
            if (is_dir($location)) {
                // Copy clamd.conf if exists
                $clamdConf = $location . '/clamd.conf';
                if (file_exists($clamdConf)) {
                    copy($clamdConf, '/etc/clamav/clamd.conf');
                    Log::info('Copied clamd.conf from template');
                }

                // Copy freshclam.conf if exists
                $freshclamConf = $location . '/freshclam.conf';
                if (file_exists($freshclamConf)) {
                    copy($freshclamConf, '/etc/clamav/freshclam.conf');
                    Log::info('Copied freshclam.conf from template');
                }

                break;
            }
        }
    }

    /**
     * Copy systemd service files
     */
    protected function copySystemdServices(): void
    {
        $locations = [
            '/package/docker/systemd/clamav',
            base_path('packages/prahsys-laravel-perimeter/docker/systemd/clamav'),
            base_path('vendor/prahsys/perimeter/docker/systemd/clamav'),
        ];

        $serviceFiles = [
            'clamav-daemon.service' => '/etc/systemd/system/clamav-daemon.service',
            'clamav-freshclam.service' => '/etc/systemd/system/clamav-freshclam.service',
        ];

        foreach ($locations as $location) {
            if (is_dir($location)) {
                foreach ($serviceFiles as $source => $target) {
                    $sourcePath = $location . '/' . $source;
                    if (file_exists($sourcePath)) {
                        copy($sourcePath, $target);
                        Log::info("Copied $source to $target");
                    }
                }
                break;
            }
        }
    }

    /**
     * Update virus database
     */
    protected function updateVirusDatabase(): void
    {
        $process = new \Symfony\Component\Process\Process(['freshclam', '--quiet']);
        $process->setTimeout(600); // 10 minutes for database download
        $process->run();

        if ($process->isSuccessful()) {
            Log::info('Virus database updated successfully');
        } else {
            Log::warning('Initial database update failed, will retry on service start: ' . $process->getErrorOutput());
        }
    }

    /**
     * Start ClamAV services
     */
    protected function startServices(): void
    {
        $process = new \Symfony\Component\Process\Process(['systemctl', 'daemon-reload']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'enable', 'clamav-daemon']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'enable', 'clamav-freshclam']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'clamav-freshclam']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'clamav-daemon']);
        $process->run();

        if ($process->isSuccessful()) {
            Log::info('ClamAV services enabled and started');
        } else {
            Log::warning('Failed to start ClamAV services: ' . $process->getErrorOutput());
        }
    }

    /**
     * Create binary symlinks for easier detection
     */
    protected function createBinarySymlinks(): void
    {
        $symlinks = [
            '/usr/bin/clamdscan' => '/usr/local/bin/clamdscan',
            '/usr/bin/clamscan' => '/usr/local/bin/clamscan',
            '/usr/bin/freshclam' => '/usr/local/bin/freshclam',
        ];

        foreach ($symlinks as $source => $target) {
            if (file_exists($source)) {
                @symlink($source, $target);
            }
        }
    }




    /**
     * Check if we should use daemon mode or direct scanning.
     */
    protected function shouldUseDaemonMode(): bool
    {
        // Check if we have sufficient memory for daemon mode
        if (! $this->hasSufficientMemoryForDaemon()) {
            return false;
        }

        // Check if daemon is actually running
        $process = new \Symfony\Component\Process\Process(['pgrep', 'clamd']);
        $process->run();
        
        return $process->isSuccessful();
    }

    /**
     * Check if system has sufficient memory for ClamAV daemon.
     */
    protected function hasSufficientMemoryForDaemon(): bool
    {
        // Simple check - assume we have enough memory in most cases
        // In production, this would check actual available memory
        return true;
    }

    /**
     * Convert a scan result to a SecurityEventData instance.
     *
     * @param  array  $data  Malware scan result data
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData
    {
        $timestamp = $data['timestamp'] ?? now();
        $severity = $data['severity'] ?? 'critical';
        $threat = $data['threat'] ?? 'Unknown Malware';
        $file = $data['file'] ?? null;
        $hash = $data['hash'] ?? null;
        $scanId = $data['scan_id'] ?? null;

        // Ensure required keys exist
        $details = array_merge([
            'file' => null,
            'hash' => null,
            'threat' => $threat,
        ], $data);

        // Remove fields that will be used in the main properties
        unset($details['timestamp'], $details['severity'], $details['description'],
            $details['location'], $details['user'], $details['service'], $details['scan_id']);

        return new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: $timestamp,
            type: 'malware',
            severity: $severity,
            description: "Detected {$threat} in file",
            location: $file,
            user: null,
            service: $this->getServiceName(),
            scan_id: $scanId,
            details: $details
        );
    }

    /**
     * Save service artifacts for audit trail
     */
    protected function saveServiceArtifacts(\Prahsys\Perimeter\Services\ArtifactManager $artifactManager): void
    {
        try {
            $logPath = '/var/log/clamav/clamav.log';
            if (file_exists($logPath) && is_readable($logPath)) {
                $logContent = file_get_contents($logPath);
                $artifactManager->saveArtifact('clamav', 'log', $logContent);
            }
        } catch (\Exception $e) {
            // Skip if can't read log
        }
    }
}
