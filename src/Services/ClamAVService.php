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
            $process->setTimeout($this->config['scan_timeout'] ?? 60);
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
                $process->setTimeout($this->config['scan_timeout'] ?? 300); // Configurable timeout
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
                    $scanProcess->setTimeout($this->config['health_check_timeout'] ?? 300); // Configurable timeout
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

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'clamav',
            enabled: $enabled,
            installed: $installed,
            configured: $configured,
            running: $running,
            message: $message,
            details: $details
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
    protected function performServiceSpecificAuditChecks($output = null): array
    {
        if (!$this->isEnabled() || !$this->isInstalled() || !$this->isConfigured()) {
            return [];
        }

        // Get scan configuration
        $scanPaths = $this->config['scan_paths'] ?? [base_path()];
        $excludePatterns = $this->config['exclude_patterns'] ?? [];

        if ($output) {
            $output->writeln("  <fg=yellow>🔍 Scanning " . count($scanPaths) . " paths for malware...</>");
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
                $output->writeln("  <fg=green>✅ No malware detected</>");
            } else {
                $output->writeln("  <fg=red>⚠️  " . count($securityEvents) . " threats detected</>");
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
            Log::info('Installing ClamAV with minimal configuration');

            // Check if already installed and not forcing reinstall
            if ($this->isInstalled() && ! ($options['force'] ?? false)) {
                Log::info('ClamAV is already installed. Use --force to reinstall.');

                return true;
            }

            // Store force flag if set
            if ($options['force'] ?? false) {
                $this->config['force'] = true;
            }

            // Install ClamAV packages
            if (! $this->installPackages()) {
                return false;
            }

            // Create required directories
            $this->createRequiredDirectories();

            // Copy configuration files
            $this->copyConfigurationFiles();

            // Copy systemd service files
            $this->copySystemdServices();

            // Update virus database
            $this->updateDefinitions();

            // Start service if requested
            if ($options['start'] ?? true) {
                $this->startService();
            }

            // Create symlinks for binary detection
            $this->createBinarySymlinks();

            // Verify the installation
            $status = $this->getStatus();
            if ($status->running) {
                Log::info('ClamAV installed and running successfully');
            } else {
                Log::warning('ClamAV installed but not running correctly. Check system logs for details.');
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error installing ClamAV: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Install ClamAV packages.
     */
    protected function installPackages(): bool
    {
        try {
            // Install ClamAV packages based on the operating system
            if ($this->isDebian()) {
                Log::info('Installing ClamAV on Debian-based system');

                // Update package lists
                $process = new \Symfony\Component\Process\Process(['apt-get', 'update']);
                $process->setTimeout(300);
                $process->run();

                // Install ClamAV packages
                $env = ['DEBIAN_FRONTEND' => 'noninteractive'];
                $process = new \Symfony\Component\Process\Process(['apt-get', 'install', '-y', 'clamav', 'clamav-daemon']);
                $process->setTimeout(300);
                $process->setEnv($env);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to install ClamAV packages: '.$process->getErrorOutput());

                    return false;
                }
            } elseif ($this->isMacOS()) {
                Log::info('Installing ClamAV on macOS');

                $process = new \Symfony\Component\Process\Process(['brew', 'install', 'clamav']);
                $process->setTimeout(300);
                $process->run();

                if (! $process->isSuccessful()) {
                    Log::error('Failed to install ClamAV via Homebrew: '.$process->getErrorOutput());

                    return false;
                }
            } else {
                Log::error('Unsupported operating system for ClamAV installation');

                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error installing ClamAV packages: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Create required directories for ClamAV.
     */
    protected function createRequiredDirectories(): void
    {
        Log::info('Creating required directories for ClamAV');

        $directories = [
            '/var/run/clamav' => 0755,
            '/var/lib/clamav' => 0755,
            '/var/log/clamav' => 0755,
            '/etc/clamav' => 0755,
        ];

        foreach ($directories as $dir => $permissions) {
            if (! is_dir($dir)) {
                mkdir($dir, $permissions, true);
                chmod($dir, $permissions);
            }
        }
    }

    /**
     * Copy ClamAV configuration files from templates.
     */
    protected function copyConfigurationFiles(): void
    {
        Log::info('Copying ClamAV configuration files');

        // Find template files in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/config/clamav',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/config/clamav'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/config/clamav'),
        ];

        $clamdTemplate = null;
        $freshclamTemplate = null;

        // Find the templates
        foreach ($locations as $location) {
            if (file_exists($location.'/clamd.conf')) {
                $clamdTemplate = $location.'/clamd.conf';
                Log::info("Found clamd.conf template at: $clamdTemplate");
            }

            if (file_exists($location.'/freshclam.conf')) {
                $freshclamTemplate = $location.'/freshclam.conf';
                Log::info("Found freshclam.conf template at: $freshclamTemplate");
            }

            if ($clamdTemplate && $freshclamTemplate) {
                break;
            }
        }

        // Copy clamd.conf if template exists
        $clamdPath = '/etc/clamav/clamd.conf';
        if ($clamdTemplate && (! file_exists($clamdPath) || ($this->config['force'] ?? false))) {
            Log::info('Copying clamd.conf template');
            copy($clamdTemplate, $clamdPath);
        }

        // Copy freshclam.conf if template exists
        $freshclamPath = '/etc/clamav/freshclam.conf';
        if ($freshclamTemplate && (! file_exists($freshclamPath) || ($this->config['force'] ?? false))) {
            Log::info('Copying freshclam.conf template');
            copy($freshclamTemplate, $freshclamPath);
        }
    }

    /**
     * Copy systemd service files.
     */
    protected function copySystemdServices(): void
    {
        Log::info('Copying ClamAV systemd service files');

        // Find template files in different possible locations
        $locations = [
            // Docker environment location
            '/package/docker/systemd/clamav',
            // Local package location
            base_path('packages/prahsys-laravel-perimeter/docker/systemd/clamav'),
            // Vendor package location
            base_path('vendor/prahsys/perimeter/docker/systemd/clamav'),
        ];

        $daemonTemplate = null;
        $freshclamTemplate = null;

        // Find the templates
        foreach ($locations as $location) {
            if (file_exists($location.'/clamav-daemon.service')) {
                $daemonTemplate = $location.'/clamav-daemon.service';
                Log::info("Found clamav-daemon.service template at: $daemonTemplate");
            }

            if (file_exists($location.'/clamav-freshclam.service')) {
                $freshclamTemplate = $location.'/clamav-freshclam.service';
                Log::info("Found clamav-freshclam.service template at: $freshclamTemplate");
            }

            if ($daemonTemplate && $freshclamTemplate) {
                break;
            }
        }

        // Copy daemon service if template exists
        $daemonServicePath = '/etc/systemd/system/clamav-daemon.service';
        if ($daemonTemplate && (! file_exists($daemonServicePath) || ($this->config['force'] ?? false))) {
            Log::info('Copying clamav-daemon.service template');
            copy($daemonTemplate, $daemonServicePath);
        }

        // Copy freshclam service if template exists
        $freshclamServicePath = '/etc/systemd/system/clamav-freshclam.service';
        if ($freshclamTemplate && (! file_exists($freshclamServicePath) || ($this->config['force'] ?? false))) {
            Log::info('Copying clamav-freshclam.service template');
            copy($freshclamTemplate, $freshclamServicePath);
        }
    }

    /**
     * Create symlinks for ClamAV binaries to ensure they're in standard locations.
     * This matches what's done in the raw-install-clamav.sh script.
     */
    protected function createBinarySymlinks(): void
    {
        Log::info('Creating binary symlinks for easier detection');

        $binaries = [
            'clamdscan' => '/usr/bin/clamdscan',
            'clamscan' => '/usr/bin/clamscan',
            'freshclam' => '/usr/bin/freshclam',
        ];

        foreach ($binaries as $binary => $sourcePath) {
            $targetPath = "/usr/local/bin/{$binary}";

            if (file_exists($sourcePath)) {
                try {
                    symlink($sourcePath, $targetPath);
                    Log::info("Created symlink for {$binary}");
                } catch (\Exception $e) {
                    // Non-critical error, continue with installation
                    Log::warning("Could not create symlink for {$binary}: ".$e->getMessage());
                }
            } else {
                Log::warning("Source binary {$sourcePath} not found, cannot create symlink");
            }
        }
    }

    /**
     * Start the ClamAV service.
     */
    protected function startService(): bool
    {
        try {
            Log::info('Starting ClamAV services');

            // Ensure required directories exist with correct permissions
            $this->ensureDirectoriesExist();

            // Reload systemd
            $process = new \Symfony\Component\Process\Process(['systemctl', 'daemon-reload']);
            $process->run();
            Log::info('Reloaded systemd configuration');

            // Update virus database first
            Log::info('Updating virus database before starting services...');
            $freshclamProcess = new \Symfony\Component\Process\Process(['freshclam', '--quiet']);
            $freshclamProcess->setTimeout(300); // 5 minutes should be enough
            $freshclamProcess->run();

            if (! $freshclamProcess->isSuccessful()) {
                Log::warning('Virus database update had issues: '.$freshclamProcess->getErrorOutput());
                Log::info('Will continue with service startup anyway');
            }

            // Enable and start freshclam service
            $process = new \Symfony\Component\Process\Process(['systemctl', 'enable', 'clamav-freshclam']);
            $process->run();
            if ($process->isSuccessful()) {
                Log::info('Enabled clamav-freshclam service');
            } else {
                Log::warning('Failed to enable clamav-freshclam service: '.$process->getErrorOutput());
            }

            $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'clamav-freshclam']);
            $process->run();
            if ($process->isSuccessful()) {
                Log::info('Started clamav-freshclam service');
            } else {
                Log::warning('Failed to start clamav-freshclam service: '.$process->getErrorOutput());

                // Try alternative service names
                $altServiceNames = ['freshclam', 'clamav-freshclam.service', 'clamfreshclam'];
                foreach ($altServiceNames as $serviceName) {
                    $process = new \Symfony\Component\Process\Process(['systemctl', 'start', $serviceName]);
                    $process->run();
                    if ($process->isSuccessful()) {
                        Log::info("Started freshclam using alternative name: $serviceName");
                        break;
                    }
                }
            }

            // Wait a moment for freshclam to initialize
            sleep(2);

            // Enable and start daemon service
            $process = new \Symfony\Component\Process\Process(['systemctl', 'enable', 'clamav-daemon']);
            $process->run();
            if ($process->isSuccessful()) {
                Log::info('Enabled clamav-daemon service');
            } else {
                Log::warning('Failed to enable clamav-daemon service: '.$process->getErrorOutput());
            }

            $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'clamav-daemon']);
            $process->run();

            if (! $process->isSuccessful()) {
                Log::warning('Failed to start ClamAV with systemctl, trying alternative approaches');

                // Try with service command as fallback
                $process = new \Symfony\Component\Process\Process(['service', 'clamav-daemon', 'start']);
                $process->run();

                if (! $process->isSuccessful()) {
                    // Try alternative service names that might be used on different distros
                    $altServiceNames = ['clamd', 'clamav', 'clamd.service'];
                    $started = false;

                    foreach ($altServiceNames as $serviceName) {
                        $process = new \Symfony\Component\Process\Process(['systemctl', 'start', $serviceName]);
                        $process->run();
                        if ($process->isSuccessful()) {
                            Log::info("Started ClamAV using alternative name: $serviceName");
                            $started = true;
                            break;
                        }

                        // Try with service command too
                        $process = new \Symfony\Component\Process\Process(['service', $serviceName, 'start']);
                        $process->run();
                        if ($process->isSuccessful()) {
                            Log::info("Started ClamAV using service command with name: $serviceName");
                            $started = true;
                            break;
                        }
                    }

                    if (! $started) {
                        Log::error('Failed to start ClamAV services after multiple attempts');
                        Log::warning('You may need to manually start ClamAV using: sudo systemctl start clamav-daemon');

                        // Print debugging information for manual troubleshooting
                        $debugProcess = new \Symfony\Component\Process\Process(['systemctl', 'status', 'clamav-daemon', '-l']);
                        $debugProcess->run();
                        Log::info('ClamAV service status: '.$debugProcess->getOutput());

                        return false;
                    }
                } else {
                    Log::info('Started clamav-daemon using service command');
                }
            } else {
                Log::info('Started clamav-daemon service');
            }

            // Verify the daemon is actually running
            sleep(1); // Give it a moment to start
            $checkRunning = $this->isClamdRunning();

            if (! $checkRunning) {
                Log::warning('ClamAV service was started but daemon is not running');
                Log::warning('You may need to manually start ClamAV: sudo systemctl start clamav-daemon');
                Log::warning('Or check logs: sudo journalctl -u clamav-daemon');

                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('Error starting ClamAV services: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Check if clamd process is actually running
     */
    protected function isClamdRunning(): bool
    {
        try {
            $process = new \Symfony\Component\Process\Process(['pgrep', 'clamd']);
            $process->run();

            if ($process->isSuccessful()) {
                return true;
            }

            // Check for alternative process names
            $altNames = ['clamd', 'clamav', 'clamd.service'];
            foreach ($altNames as $name) {
                $process = new \Symfony\Component\Process\Process(['pgrep', $name]);
                $process->run();
                if ($process->isSuccessful()) {
                    return true;
                }
            }

            // Check if socket exists as another indicator
            $socketPath = '/var/run/clamav/clamd.sock';
            if (file_exists($socketPath)) {
                return true;
            }

            return false;
        } catch (\Exception $e) {
            Log::warning('Error checking if clamd is running: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Check if we should use daemon mode or direct scanning.
     */
    protected function shouldUseDaemonMode(): bool
    {
        // If daemon is explicitly disabled in config, use direct scanning
        if (isset($this->config['force_direct_scan']) && $this->config['force_direct_scan']) {
            Log::info('ClamAV: Using direct scanning (forced by configuration)');

            return false;
        }

        // Check if we have sufficient memory for daemon mode
        if (! $this->hasSufficientMemoryForDaemon()) {
            Log::info('ClamAV: Using direct scanning (insufficient memory for daemon)');

            return false;
        }

        // Check if daemon is actually running
        if (! $this->isClamdRunning()) {
            Log::info('ClamAV: Using direct scanning (daemon not running)');

            return false;
        }

        Log::info('ClamAV: Using daemon scanning (optimal performance)');

        return true;
    }

    /**
     * Check if system has sufficient memory for ClamAV daemon.
     */
    protected function hasSufficientMemoryForDaemon(): bool
    {
        $availableMemoryMB = $this->getAvailableMemoryMB();
        $requiredMemoryMB = $this->config['min_memory_for_daemon'] ?? 1536; // 1.5GB default

        if ($availableMemoryMB === null) {
            // Cannot determine memory, assume we have enough
            Log::debug('ClamAV: Cannot determine available memory, assuming daemon mode is OK');

            return true;
        }

        Log::debug("ClamAV: Available memory: {$availableMemoryMB}MB, Required: {$requiredMemoryMB}MB");

        return $availableMemoryMB >= $requiredMemoryMB;
    }

    /**
     * Get available system memory in MB.
     */
    protected function getAvailableMemoryMB(): ?int
    {
        try {
            // Try to get memory info from /proc/meminfo (Linux)
            if (file_exists('/proc/meminfo')) {
                $meminfo = file_get_contents('/proc/meminfo');

                // Get MemAvailable (preferred) or calculate from MemFree + Buffers + Cached
                if (preg_match('/MemAvailable:\s+(\d+)\s+kB/', $meminfo, $matches)) {
                    return (int) ($matches[1] / 1024); // Convert KB to MB
                }

                // Fallback calculation
                $memFree = 0;
                $buffers = 0;
                $cached = 0;

                if (preg_match('/MemFree:\s+(\d+)\s+kB/', $meminfo, $matches)) {
                    $memFree = (int) $matches[1];
                }
                if (preg_match('/Buffers:\s+(\d+)\s+kB/', $meminfo, $matches)) {
                    $buffers = (int) $matches[1];
                }
                if (preg_match('/Cached:\s+(\d+)\s+kB/', $meminfo, $matches)) {
                    $cached = (int) $matches[1];
                }

                return (int) (($memFree + $buffers + $cached) / 1024); // Convert KB to MB
            }

            return null;
        } catch (\Exception $e) {
            Log::warning('Error determining available memory: '.$e->getMessage());

            return null;
        }
    }

    /**
     * Ensure required directories exist with proper permissions
     */
    protected function ensureDirectoriesExist(): void
    {
        // First ensure the clamav user exists
        $this->ensureClamavUserExists();

        $directories = [
            '/var/run/clamav' => 0755,
            '/var/lib/clamav' => 0755,
            '/var/log/clamav' => 0755,
        ];

        foreach ($directories as $dir => $perms) {
            if (! is_dir($dir)) {
                try {
                    mkdir($dir, $perms, true);
                    chmod($dir, $perms);
                    Log::info("Created directory: $dir");
                } catch (\Exception $e) {
                    Log::warning("Could not create directory $dir: ".$e->getMessage());
                }
            }

            // Ensure proper ownership regardless of whether directory existed
            if ($this->isRunningAsRoot()) {
                try {
                    // First check if clamav user exists before setting ownership
                    $userCheckProcess = new \Symfony\Component\Process\Process(['id', 'clamav']);
                    $userCheckProcess->run();

                    if ($userCheckProcess->isSuccessful()) {
                        // Set ownership to clamav user
                        $process = new \Symfony\Component\Process\Process(['chown', '-R', 'clamav:clamav', $dir]);
                        $process->run();

                        if ($process->isSuccessful()) {
                            Log::info("Set ownership for $dir to clamav:clamav");
                        } else {
                            Log::warning("Failed to set ownership for $dir: ".$process->getErrorOutput());
                        }
                    } else {
                        Log::warning("ClamAV user does not exist, using default ownership for $dir");
                    }

                    // Ensure permissions are correct
                    chmod($dir, $perms);
                } catch (\Exception $e) {
                    Log::warning("Could not set ownership for $dir: ".$e->getMessage());
                }
            } else {
                Log::info("Not running as root, skipping ownership changes for $dir");
            }
        }
    }

    /**
     * Ensure the clamav system user exists
     */
    protected function ensureClamavUserExists(): void
    {
        if (! $this->isRunningAsRoot()) {
            Log::info('Not running as root, skipping clamav user creation');

            return;
        }

        try {
            // Check if clamav user already exists
            $userCheckProcess = new \Symfony\Component\Process\Process(['id', 'clamav']);
            $userCheckProcess->run();

            if ($userCheckProcess->isSuccessful()) {
                Log::info('ClamAV user already exists');

                return;
            }

            // Create clamav user if it doesn't exist
            Log::info('Creating clamav system user');
            $createUserProcess = new \Symfony\Component\Process\Process([
                'useradd',
                '--system',
                '--shell', '/bin/false',
                '--home-dir', '/var/lib/clamav',
                '--create-home',
                '--comment', 'ClamAV antivirus',
                'clamav',
            ]);
            $createUserProcess->run();

            if ($createUserProcess->isSuccessful()) {
                Log::info('Successfully created clamav system user');
            } else {
                Log::warning('Failed to create clamav user: '.$createUserProcess->getErrorOutput());
            }

        } catch (\Exception $e) {
            Log::warning('Error ensuring clamav user exists: '.$e->getMessage());
        }
    }

    /**
     * Check if the command is running as root or with sudo.
     */
    protected function isRunningAsRoot(): bool
    {
        // On Unix/Linux systems
        if (function_exists('posix_getuid')) {
            return posix_getuid() === 0;
        }

        // Try to write to a system location to test permissions
        try {
            // If we can write to /tmp/sudo_test, we likely have root
            $testFile = '/tmp/sudo_test_'.time();
            $result = @file_put_contents($testFile, 'test');

            if ($result !== false) {
                @unlink($testFile);

                return true;
            }
        } catch (\Exception $e) {
            Log::warning('Failed to test for root permissions: '.$e->getMessage());
        }

        return false;
    }

    /**
     * Check if running on a Debian-based system.
     */
    protected function isDebian(): bool
    {
        return file_exists('/etc/debian_version') ||
               $this->checkOSRelease('ID', 'debian') ||
               $this->checkOSRelease('ID', 'ubuntu') ||
               $this->checkOSRelease('ID_LIKE', 'debian');
    }

    /**
     * Check if running on macOS.
     */
    protected function isMacOS(): bool
    {
        return strtolower(PHP_OS_FAMILY) === 'darwin';
    }

    /**
     * Check OS release information from /etc/os-release.
     */
    protected function checkOSRelease(string $key, string $value): bool
    {
        if (! file_exists('/etc/os-release')) {
            return false;
        }

        $content = file_get_contents('/etc/os-release');
        $pattern = "/$key=['\"]?.*$value.*['\"]?/i";

        return preg_match($pattern, $content) === 1;
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
     * Get real files in a path for scanning.
     */
    protected function getSampleFilesInPath(string $path): array
    {
        // This method is preserved for backward compatibility
        // but now actually scans the real filesystem

        $files = [];

        // Only proceed if the path exists and is readable
        if (! file_exists($path) || ! is_readable($path)) {
            Log::warning("Path not found or not readable: {$path}");

            return $files;
        }

        // Just return the path itself if it's a file
        if (is_file($path)) {
            return [$path];
        }

        // If it's a directory, we're no longer mocking files
        // Real scanning is handled by ClamAV directly in scanPaths method
        // so this is just a fallback for older implementations
        return $files;
    }

    /**
     * Get a random malware name for testing purposes only.
     * This method should NOT be used in production code.
     */
    protected function getRandomMalwareName(): string
    {
        // This method is kept for backward compatibility and testing
        // It should not be used in production code

        $malwareTypes = [
            '[TEST ONLY] Trojan.PHP.Agent',
            '[TEST ONLY] Backdoor.PHP.Shell',
            '[TEST ONLY] Virus.Win32.Sality',
            '[TEST ONLY] Ransomware.Cryptolocker',
            '[TEST ONLY] PUP.JS.Miner',
            '[TEST ONLY] Adware.HTML.Script',
        ];

        return $malwareTypes[array_rand($malwareTypes)];
    }

    /**
     * Check if we're running in a container environment.
     */
    public function isRunningInContainer(): bool
    {
        // Check for common container indicators
        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return true;
        }

        // Check cgroup info for Docker
        try {
            if (file_exists('/proc/1/cgroup') &&
                strpos(file_get_contents('/proc/1/cgroup'), 'docker') !== false) {
                return true;
            }

            if (file_exists('/proc/self/cgroup') &&
                strpos(file_get_contents('/proc/self/cgroup'), 'docker') !== false) {
                return true;
            }
        } catch (\Exception $e) {
            // If we can't read these files, it's not a standard Linux container
        }

        // Check for environment variables commonly set in containers
        if (! empty(getenv('KUBERNETES_SERVICE_HOST')) ||
            ! empty(getenv('DOCKER_CONTAINER')) ||
            ! empty(getenv('DOCKER_HOST'))) {
            return true;
        }

        // Check if hostname is a docker container ID (they're typically 12 hex chars)
        $hostname = gethostname();
        if (strlen($hostname) === 12 && ctype_xdigit($hostname)) {
            return true;
        }

        return false;
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
}
