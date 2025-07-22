<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\Parsers\TrivyOutputParser;

class TrivyService extends AbstractSecurityService implements VulnerabilityScannerInterface
{
    /**
     * Create a new Trivy service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        //
    }

    /**
     * Scan dependencies for vulnerabilities.
     */
    public function scanDependencies(): array
    {
        if (! $this->isEnabled()) {
            return [];
        }

        try {
            $results = [];
            $scanPaths = $this->config['scan_paths'] ?? [base_path()];
            $threshold = $this->config['severity_threshold'] ?? 'MEDIUM';

            // First, scan the system packages
            $systemResults = $this->scanSystemPackages($threshold);
            if (! empty($systemResults)) {
                $results = array_merge($results, $systemResults);
            }

            // Then scan the specified paths
            foreach ($scanPaths as $path) {
                if (! file_exists($path)) {
                    Log::warning('Trivy scan failed: Path not found', ['path' => $path]);

                    continue;
                }

                // Use Trivy to scan the file or directory
                // --format json: output in JSON format
                // --severity: only show vulnerabilities with severity >= threshold
                $process = new \Symfony\Component\Process\Process([
                    'trivy', 'fs', '--scanners', 'vuln', '--format', 'json', '--severity', $threshold, $path,
                ]);
                $process->setTimeout($this->config['scan_timeout'] ?? 900); // Configurable timeout for large directories
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();
                    // Use our parser to extract vulnerabilities
                    $parsedVulnerabilities = TrivyOutputParser::parseVulnerabilities($output);
                    $results = array_merge($results, $parsedVulnerabilities);
                } else {
                    // Log the error if the scan fails
                    Log::warning('Trivy scan error: '.$process->getErrorOutput(), ['path' => $path]);
                }
            }

            // Filter results by severity threshold
            return $this->filterBySeverity($results);
        } catch (\Exception $e) {
            Log::error('Trivy scan failed: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return [];
        }
    }

    /**
     * Scan system packages for vulnerabilities.
     */
    protected function scanSystemPackages(string $threshold): array
    {
        try {
            Log::info('Scanning system packages with Trivy');

            // Determine the OS distribution for scanning
            $osName = 'unknown';
            if (file_exists('/etc/os-release')) {
                $osRelease = file_get_contents('/etc/os-release');
                if (preg_match('/ID=([a-z]+)/', $osRelease, $matches)) {
                    $osName = $matches[1];
                }
            }

            // Use appropriate scanning command based on environment
            if (Perimeter::isRunningInContainer()) {
                // For containers, scan the base image
                $process = new \Symfony\Component\Process\Process([
                    'trivy', 'image', '--scanners', 'vuln', '--format', 'json', '--severity', $threshold, $osName.':latest',
                ]);
            } else {
                // For normal systems, scan the OS packages with minimal exclusions for performance
                $excludePaths = $this->config['exclude_paths'] ?? [
                    '/proc', '/sys', '/dev', '/run', '/tmp',
                ];

                $processArgs = ['trivy', 'rootfs', '--format', 'json', '--severity', $threshold];

                // Add skip paths for performance (only critical system directories)
                foreach ($excludePaths as $excludePath) {
                    $processArgs[] = '--skip-dirs';
                    $processArgs[] = $excludePath;
                }

                $processArgs[] = '/';

                $process = new \Symfony\Component\Process\Process($processArgs);
            }
            $process->setTimeout($this->config['scan_timeout'] ?? 1800); // Extended to 30 minutes for full system scans
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                // Use our parser to extract vulnerabilities
                $parsedVulnerabilities = TrivyOutputParser::parseVulnerabilities($output);

                Log::info('System package scan completed', [
                    'vulnerabilities_found' => count($parsedVulnerabilities),
                ]);

                return $parsedVulnerabilities;
            } else {
                Log::warning('System package scan failed: '.$process->getErrorOutput());

                return [];
            }
        } catch (\Exception $e) {
            Log::error('System package scan failed: '.$e->getMessage(), [
                'exception' => $e,
            ]);

            return [];
        }
    }

    /**
     * Scan specific file for vulnerabilities.
     */
    public function scanFile(string $filePath): array
    {
        if (! $this->isEnabled()) {
            return [];
        }

        try {
            $threshold = $this->config['severity_threshold'] ?? 'MEDIUM';

            // Use Trivy to directly scan the file
            $process = new \Symfony\Component\Process\Process([
                'trivy', 'fs', '--format', 'json', '--severity', $threshold, $filePath,
            ]);
            $process->setTimeout(120);
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                // Use our parser to extract vulnerabilities
                $parsedVulnerabilities = TrivyOutputParser::parseVulnerabilities($output);

                return $this->filterBySeverity($parsedVulnerabilities);
            } else {
                // Log the error if the scan fails
                Log::warning('Trivy file scan error: '.$process->getErrorOutput(), ['path' => $filePath]);
            }

            return [];
        } catch (\Exception $e) {
            Log::error('Trivy scan failed: '.$e->getMessage(), [
                'file' => $filePath,
                'exception' => $e,
            ]);

            return [];
        }
    }

    /**
     * Check if Trivy service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Check if Trivy is installed on the system.
     */
    public function isInstalled(): bool
    {
        // Run trivy --version to check if it's installed and working
        $process = new \Symfony\Component\Process\Process(['trivy', '--version']);
        $process->run();

        // If version command succeeds, trivy is installed
        return $process->isSuccessful();
    }

    /**
     * Check if Trivy is properly configured.
     */
    public function isConfigured(): bool
    {
        // If not installed, it can't be properly configured
        if (! $this->isInstalled()) {
            return false;
        }

        // Trivy doesn't need specific configuration files, only the binary
        // Make sure we have scan paths configured
        $scanPaths = $this->config['scan_paths'] ?? [];
        if (empty($scanPaths)) {
            return false;
        }

        // Check severity threshold is set
        $threshold = $this->config['severity_threshold'] ?? null;
        if (empty($threshold)) {
            return false;
        }

        return true;
    }

    /**
     * Get the current status of the service.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $enabled = $this->isEnabled();
        $installed = $this->isInstalled();
        $configured = $this->isConfigured();

        // Trivy doesn't have a daemon, so it's "running" if it's installed and configured
        $running = $installed && $configured;

        // Get version if installed
        $version = null;
        if ($installed) {
            try {
                $process = new \Symfony\Component\Process\Process(['trivy', '--version']);
                $process->run();

                if ($process->isSuccessful()) {
                    $output = $process->getOutput();
                    // Extract version from output
                    if (preg_match('/Version: ([0-9]+\.[0-9]+\.[0-9]+)/', $output, $matches)) {
                        $version = $matches[1];
                    }
                }
            } catch (\Exception $e) {
                Log::warning('Error getting Trivy version: '.$e->getMessage());
            }
        }

        $scanTargets = $this->config['scan_paths'] ?? [];
        $lastScanTime = 0;
        $vulnerabilityDb = [
            'last_update' => $this->getDatabaseUpdateTime(),
            'severity_threshold' => $this->config['severity_threshold'] ?? 'MEDIUM',
        ];

        // Create message
        $message = '';
        if (! $enabled) {
            $message = 'Trivy vulnerability scanner is disabled in configuration.';
        } elseif (! $installed) {
            $message = 'Trivy is not installed on the system.';
        } elseif (! $configured) {
            $message = 'Trivy is installed but not properly configured.';
        } else {
            $message = 'Trivy is ready to scan for system packages and application dependencies.';
        }

        // Build details array with vulnerability scanner-specific information
        $details = [
            'version' => $version,
            'scan_targets' => array_merge(['OS packages', 'system libraries'], $scanTargets),
            'last_scan_time' => $lastScanTime,
            'vulnerability_db' => $vulnerabilityDb,
        ];

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'trivy',
            enabled: $enabled,
            installed: $installed,
            configured: $configured,
            running: $running,
            message: $message,
            details: $details
        );
    }

    /**
     * Update vulnerability database.
     */
    public function updateDatabase(): bool
    {
        if (! $this->isEnabled() || ! $this->isInstalled()) {
            return false;
        }

        try {
            // Use trivy image to update the vulnerability database
            $process = new \Symfony\Component\Process\Process(['trivy', 'image', '--download-db-only']);
            $process->setTimeout(300); // Give it 5 minutes to update
            $process->run();

            $success = $process->isSuccessful();

            if ($success) {
                Log::info('Trivy vulnerability database updated successfully');
            } else {
                Log::error('Failed to update Trivy vulnerability database: '.$process->getErrorOutput());
            }

            return $success;
        } catch (\Exception $e) {
            Log::error('Error updating Trivy vulnerability database: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Get the last update time of the vulnerability database.
     *
     * @return int Unix timestamp
     */
    public function getDatabaseUpdateTime(): int
    {
        if (! $this->isInstalled()) {
            return 0;
        }

        try {
            // Trivy stores its database in a specific location
            $dbPath = getenv('HOME').'/.cache/trivy/db/trivy.db';
            $altDbPath = '/root/.cache/trivy/db/trivy.db';

            if (file_exists($dbPath)) {
                return filemtime($dbPath);
            } elseif (file_exists($altDbPath)) {
                return filemtime($altDbPath);
            }

            return 0;
        } catch (\Exception $e) {
            Log::warning('Error getting Trivy database update time: '.$e->getMessage());

            return 0;
        }
    }

    // No fallback methods needed - we rely directly on Trivy

    /**
     * Filter results by severity threshold.
     */
    protected function filterBySeverity(array $results): array
    {
        $threshold = $this->config['severity_threshold'] ?? 'MEDIUM';
        $severityLevels = [
            'CRITICAL' => 4,
            'HIGH' => 3,
            'MEDIUM' => 2,
            'LOW' => 1,
        ];

        $thresholdLevel = $severityLevels[$threshold] ?? 2;

        return array_filter($results, function ($result) use ($severityLevels, $thresholdLevel) {
            $resultLevel = $severityLevels[$result['severity']] ?? 0;

            return $resultLevel >= $thresholdLevel;
        });
    }

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool
    {
        try {
            Log::info('Starting Trivy installation...');

            // Check if already installed and not forcing reinstall
            if ($this->isInstalled() && ! ($options['force'] ?? false)) {
                Log::info('Trivy is already installed');

                return true;
            }

            // Create required directories
            Log::info('Creating Trivy directories...');
            $this->ensureDirectoriesExist();

            // Clean up any existing broken repository configuration
            $this->cleanupExistingTrivyRepository();

            // Install Trivy package
            Log::info('Installing Trivy package...');
            $this->installTrivyPackage();

            // Copy configuration files
            Log::info('Configuring Trivy services...');
            $this->copySystemdServices();
            $this->copyUtilityScripts();

            // Enable and start services
            if ($options['start'] ?? true) {
                Log::info('Enabling Trivy services...');
                $this->startServices();
            }

            // Download initial database
            Log::info('Downloading vulnerability database...');
            $this->downloadDatabase();

            // Verify installation
            if ($this->isInstalled()) {
                Log::info('Trivy installation completed successfully');

                return true;
            } else {
                Log::error('Trivy installation verification failed');

                return false;
            }

        } catch (\Exception $e) {
            Log::error('Trivy installation failed: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Ensure required directories exist
     */
    protected function ensureDirectoriesExist(): void
    {
        $directories = [
            '/var/log/trivy',
            '/var/log/trivy/.cache',
        ];

        foreach ($directories as $dir) {
            if (! is_dir($dir)) {
                mkdir($dir, 0755, true);
                Log::info("Created directory: $dir");
            }
        }
    }

    /**
     * Clean up any existing broken Trivy repository configuration
     */
    protected function cleanupExistingTrivyRepository(): void
    {
        Log::info('Cleaning up any existing Trivy repository configuration...');

        // Remove potentially broken repository configuration
        if (file_exists('/etc/apt/sources.list.d/trivy.list')) {
            unlink('/etc/apt/sources.list.d/trivy.list');
            Log::info('Removed existing trivy.list repository file');
        }

        // Remove any existing GPG key
        if (file_exists('/usr/share/keyrings/trivy.gpg')) {
            unlink('/usr/share/keyrings/trivy.gpg');
            Log::info('Removed existing Trivy GPG key');
        }

        // Also check for legacy apt-key entries (from older Docker script)
        $process = new \Symfony\Component\Process\Process(['apt-key', 'list', '4021833E14CB7A8D']);
        $process->run();

        if ($process->isSuccessful()) {
            Log::info('Found legacy Trivy GPG key, removing...');
            $process = new \Symfony\Component\Process\Process(['apt-key', 'del', '4021833E14CB7A8D']);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info('Successfully removed legacy Trivy GPG key');
            }
        }
    }

    /**
     * Install Trivy package
     */
    protected function installTrivyPackage(): void
    {
        Log::info('Installing Trivy package...');

        // Step 1: Install required dependencies
        Log::info('Installing dependencies for Trivy repository...');
        $process = new \Symfony\Component\Process\Process(['apt-get', 'update']);
        $process->run();

        // If it fails due to repository label changes, try with --allow-releaseinfo-change
        if (! $process->isSuccessful()) {
            $errorOutput = $process->getErrorOutput();

            if (strpos($errorOutput, 'changed its \'Label\' value') !== false) {
                Log::info('Repository label changes detected, retrying with --allow-releaseinfo-change');
                $process = new \Symfony\Component\Process\Process(['apt-get', 'update', '--allow-releaseinfo-change']);
                $process->run();

                if (! $process->isSuccessful()) {
                    throw new \Exception('Failed to update package list even with --allow-releaseinfo-change: '.$process->getErrorOutput());
                }
            } else {
                throw new \Exception('Failed to update package list before installing dependencies: '.$errorOutput);
            }
        }

        $process = new \Symfony\Component\Process\Process(['apt-get', 'install', '-y', '--no-install-recommends', 'wget', 'gnupg', 'ca-certificates']);
        $process->setTimeout(300);

        // Set environment variables to prevent interactive prompts
        $process->setEnv([
            'DEBIAN_FRONTEND' => 'noninteractive',
            'NEEDRESTART_MODE' => 'a',
        ]);

        $process->run();

        if (! $process->isSuccessful()) {
            throw new \Exception('Failed to install required dependencies: '.$process->getErrorOutput());
        }

        // Step 2: Download and add GPG key
        Log::info('Adding Trivy GPG key...');
        $process = new \Symfony\Component\Process\Process([
            'wget', '-qO', '-', 'https://aquasecurity.github.io/trivy-repo/deb/public.key',
        ]);
        $process->run();

        if (! $process->isSuccessful()) {
            throw new \Exception('Failed to download Trivy GPG key: '.$process->getErrorOutput());
        }

        $gpgKey = $process->getOutput();
        $process = new \Symfony\Component\Process\Process([
            'gpg', '--dearmor', '-o', '/usr/share/keyrings/trivy.gpg',
        ]);
        $process->setInput($gpgKey);
        $process->run();

        if (! $process->isSuccessful()) {
            throw new \Exception('Failed to add Trivy GPG key: '.$process->getErrorOutput());
        }

        // Step 3: Detect distribution codename
        Log::info('Detecting distribution codename...');
        $process = new \Symfony\Component\Process\Process(['lsb_release', '-sc']);
        $process->run();

        if (! $process->isSuccessful()) {
            throw new \Exception('Failed to detect distribution codename: '.$process->getErrorOutput());
        }

        $distroCodename = trim($process->getOutput());
        Log::info("Detected distribution: {$distroCodename}");

        // Step 4: Create repository configuration
        Log::info('Creating Trivy repository configuration...');
        $repoConfig = "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb {$distroCodename} main";

        if (! file_put_contents('/etc/apt/sources.list.d/trivy.list', $repoConfig."\n")) {
            throw new \Exception('Failed to create Trivy repository configuration file');
        }

        // Step 5: Update package list
        Log::info('Updating package lists with Trivy repository...');
        $process = new \Symfony\Component\Process\Process(['apt-get', 'update']);
        $process->run();

        if (! $process->isSuccessful()) {
            $errorOutput = $process->getErrorOutput();

            // Check if the error is due to repository label changes
            if (strpos($errorOutput, 'changed its \'Label\' value') !== false) {
                Log::info('Repository label changes detected, retrying with --allow-releaseinfo-change');
                $process = new \Symfony\Component\Process\Process(['apt-get', 'update', '--allow-releaseinfo-change']);
                $process->run();

                if (! $process->isSuccessful()) {
                    $errorOutput = $process->getErrorOutput();
                    throw new \Exception("Failed to update package list with Trivy repository even with --allow-releaseinfo-change. This might indicate the distribution '{$distroCodename}' is not supported by Trivy repository. Error: {$errorOutput}");
                }
            } else {
                throw new \Exception("Failed to update package list with Trivy repository. This might indicate the distribution '{$distroCodename}' is not supported by Trivy repository. Error: {$errorOutput}");
            }
        }

        // Step 6: Install Trivy package
        Log::info('Installing Trivy package...');
        $process = new \Symfony\Component\Process\Process(['apt-get', 'install', '-y', '--no-install-recommends', 'trivy']);
        $process->setTimeout(300);

        // Set environment variables to prevent interactive prompts
        $process->setEnv([
            'DEBIAN_FRONTEND' => 'noninteractive',
            'NEEDRESTART_MODE' => 'a',
        ]);

        $process->run();

        if (! $process->isSuccessful()) {
            throw new \Exception('Failed to install Trivy package: '.$process->getErrorOutput());
        }

        Log::info('Trivy package installed successfully');
    }

    /**
     * Copy systemd service files
     */
    protected function copySystemdServices(): void
    {
        $locations = [
            '/package/docker/systemd/trivy',
            base_path('packages/prahsys-laravel-perimeter/docker/systemd/trivy'),
            base_path('vendor/prahsys/perimeter/docker/systemd/trivy'),
        ];

        $serviceFiles = [
            'trivy-db-update.service' => '/etc/systemd/system/trivy-db-update.service',
            'trivy-db-update.timer' => '/etc/systemd/system/trivy-db-update.timer',
        ];

        foreach ($locations as $location) {
            if (is_dir($location)) {
                foreach ($serviceFiles as $source => $target) {
                    $sourcePath = $location.'/'.$source;
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
     * Copy utility scripts
     */
    protected function copyUtilityScripts(): void
    {
        $locations = [
            '/package/docker/bin',
            base_path('packages/prahsys-laravel-perimeter/docker/bin'),
            base_path('vendor/prahsys/perimeter/docker/bin'),
        ];

        foreach ($locations as $location) {
            $scriptPath = $location.'/scan-vulnerabilities';
            if (file_exists($scriptPath)) {
                copy($scriptPath, '/usr/local/bin/scan-vulnerabilities');
                chmod('/usr/local/bin/scan-vulnerabilities', 0755);
                Log::info('Copied scan-vulnerabilities script');
                break;
            }
        }
    }

    /**
     * Start Trivy services
     */
    protected function startServices(): void
    {
        $process = new \Symfony\Component\Process\Process(['systemctl', 'daemon-reload']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'enable', 'trivy-db-update.timer']);
        $process->run();

        $process = new \Symfony\Component\Process\Process(['systemctl', 'start', 'trivy-db-update.timer']);
        $process->run();

        if ($process->isSuccessful()) {
            Log::info('Trivy database update timer enabled and started');
        } else {
            Log::warning('Failed to start Trivy timer: '.$process->getErrorOutput());
        }
    }

    /**
     * Download vulnerability database
     */
    protected function downloadDatabase(): void
    {
        $process = new \Symfony\Component\Process\Process(['trivy', 'image', '--download-db-only']);
        $process->setTimeout(600); // 10 minutes for database download
        $process->run();

        if ($process->isSuccessful()) {
            Log::info('Trivy vulnerability database downloaded successfully');
        } else {
            Log::warning('Failed to download vulnerability database: '.$process->getErrorOutput());
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
     * Run service-specific audit checks.
     * Perform Trivy vulnerability scanning during the audit process.
     */
    protected function runServiceAuditTasks($output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): array
    {
        if (! $this->isEnabled() || ! $this->isInstalled() || ! $this->isConfigured()) {
            return [];
        }

        // Save Trivy log artifacts if artifact manager is provided
        if ($artifactManager) {
            $this->saveServiceArtifacts($artifactManager);
        }

        if ($output) {
            $output->writeln('  <fg=yellow>🔍 Scanning dependencies and system packages for vulnerabilities...</>');
        }

        // Perform the actual vulnerability scan
        $scanResults = $this->scanDependencies();

        // Convert scan results to SecurityEventData objects
        $securityEvents = [];
        foreach ($scanResults as $result) {
            $securityEvents[] = $this->resultToSecurityEventData(array_merge($result, [
                'timestamp' => now(),
                'scan_id' => null,
            ]));
        }

        if ($output) {
            if (empty($securityEvents)) {
                $output->writeln('  <fg=green>✅ No vulnerabilities detected</>');
            } else {
                $severityCounts = array_count_values(array_column($scanResults, 'severity'));
                $criticalHigh = ($severityCounts['CRITICAL'] ?? 0) + ($severityCounts['HIGH'] ?? 0);
                if ($criticalHigh > 0) {
                    $output->writeln('  <fg=red>⚠️  '.count($securityEvents)." vulnerabilities detected ($criticalHigh critical/high)</>");
                } else {
                    $output->writeln('  <fg=yellow>⚠️  '.count($securityEvents).' vulnerabilities detected (medium/low severity)</>');
                }
            }
        }

        return $securityEvents;
    }

    /**
     * Convert a vulnerability scan result to a SecurityEventData instance.
     *
     * @param  array  $data  Vulnerability scan result data
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData
    {
        $timestamp = $data['timestamp'] ?? now();
        $severity = strtolower($data['severity'] ?? 'high');
        $title = $data['title'] ?? $data['description'] ?? 'Vulnerability Detected';
        $packageName = $data['packageName'] ?? $data['package'] ?? null;
        $scanId = $data['scan_id'] ?? null;

        $details = array_merge($data, [
            'package' => $packageName,
            'fixed_version' => $data['fixedVersion'] ?? null,
        ]);

        // Remove fields that will be used in the main properties
        unset($details['timestamp'], $details['severity'], $details['description'],
            $details['title'], $details['location'], $details['user'],
            $details['service'], $details['scan_id']);

        return new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: $timestamp,
            type: 'vulnerability',
            severity: $severity,
            description: $title,
            location: $packageName,
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
            // Run a simple trivy scan to capture output
            $process = new \Symfony\Component\Process\Process(['trivy', '--version']);
            $process->run();

            if ($process->isSuccessful()) {
                $artifactManager->saveArtifact('trivy_version.txt', $process->getOutput(), [
                    'service' => 'trivy',
                    'type' => 'version',
                    'command' => 'trivy --version',
                ]);
            }

            // Save database info
            $process = new \Symfony\Component\Process\Process(['trivy', 'image', '--list-all-pkgs', '--quiet', 'alpine:latest']);
            $process->setTimeout(60);
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                if (! empty($output)) {
                    $artifactManager->saveArtifact('trivy_scan_output.txt', $output, [
                        'service' => 'trivy',
                        'type' => 'scan_output',
                        'command' => 'trivy image --list-all-pkgs --quiet alpine:latest',
                    ]);
                }
            }
        } catch (\Exception $e) {
            // Skip if can't run trivy
        }
    }
}
