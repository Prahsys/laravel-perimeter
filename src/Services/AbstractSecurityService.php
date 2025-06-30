<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Console\OutputStyle;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\SecurityServiceInterface;
use Prahsys\Perimeter\Data\ServiceAuditData;

abstract class AbstractSecurityService implements SecurityServiceInterface
{
    /**
     * Service configuration.
     */
    protected array $config = [];

    /**
     * Create a new service instance.
     *
     * @return void
     */
    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Check if the service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
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
     * Run service-specific audit tasks.
     * Override this method in child classes to perform service-specific tasks.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @param  \Prahsys\Perimeter\Services\ArtifactManager|null  $artifactManager  Optional artifact manager for saving audit data
     * @return array Array of SecurityEventData objects, empty array if no issues
     */
    protected function runServiceAuditTasks($output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): array
    {
        // Default implementation returns no issues
        return [];
    }

    /**
     * Get the service name for audit results.
     *
     * @return string The service name
     */
    public function getServiceName(): string
    {
        // Use the configured name if available, otherwise use a derived name
        return $this->config['name'] ?? strtolower(preg_replace('/Service$/', '', class_basename(static::class)));
    }

    /**
     * Get the display name for audit results.
     *
     * @return string The display name
     */
    protected function getDisplayName(): string
    {
        return str_replace('Service', '', class_basename(static::class));
    }

    /**
     * Run audit checks specific to this service and output results.
     * This is a template method that standardizes the audit process.
     * Child classes should override runServiceAuditTasks() instead.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @param  \Prahsys\Perimeter\Services\ArtifactManager|null  $artifactManager  Optional artifact manager for saving audit data
     * @return \Prahsys\Perimeter\Data\ServiceAuditData Audit results with any issues found
     */
    public function runServiceAudit(?OutputStyle $output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): ServiceAuditData
    {
        $serviceName = $this->getServiceName();
        $displayName = $this->getDisplayName();

        // Create the ServiceAuditData object
        $result = new ServiceAuditData;
        $result->service = $serviceName;
        $result->displayName = $displayName;

        // Output a section header if output is provided
        if ($output) {
            $output->section($displayName);
        }

        // Skip if not enabled
        if (! $this->isEnabled()) {
            if ($output) {
                $output->info($displayName.' checks are disabled in configuration');
            }
            $result->status = 'disabled';

            return $result;
        }

        // Check if installed
        if (! $this->isInstalled()) {
            if ($output) {
                $output->caution($displayName.' is not installed');
            }
            $result->status = 'not_installed';

            return $result;
        }

        // Check if configured
        if (! $this->isConfigured()) {
            if ($output) {
                $output->caution($displayName.' is installed but not properly configured');
            }
            $result->status = 'not_configured';

            return $result;
        }

        // Show progress indicator for long-running scans
        if ($output && in_array($serviceName, ['clamav', 'trivy'])) {
            $output->writeln("  <fg=yellow>⏳ Running {$displayName} security scan...</>");
            if ($serviceName === 'clamav') {
                $scanLogPath = $this->getServiceLogPath('scan.log');
                $output->writeln("  <fg=cyan>💡 Watch scan progress with: tail -f {$scanLogPath}</>");
            }
        }

        // Run service-specific tasks
        $issues = $this->runServiceAuditTasks($output, $artifactManager);
        $result->issues = $issues;

        // Set status based on issues
        $result->status = empty($issues) ? 'secure' : 'issues_found';

        // Show results if output is provided
        if ($output) {
            if (empty($issues)) {
                $output->success($displayName.': No security issues found');
            } else {
                $output->caution($displayName.': '.count($issues).' security issues found');

                // Show first few issues - using SecurityEventData objects
                $issuesToShow = array_slice($issues, 0, 3);
                foreach ($issuesToShow as $issue) {
                    $description = $issue->description;
                    $severity = $issue->severity;
                    $output->writeln("  • [$severity] $description");
                }

                if (count($issues) > 3) {
                    $output->writeln('  • ... and '.(count($issues) - 3).' more issues');
                }
            }
        }

        return $result;
    }

    /**
     * Check if running in a Docker/container environment
     */
    public function isRunningInContainer(): bool
    {
        // Check for Docker
        if (file_exists('/.dockerenv')) {
            return true;
        }

        // Check for container-specific cgroup paths
        if (file_exists('/proc/1/cgroup')) {
            $content = @file_get_contents('/proc/1/cgroup');
            if ($content && (strpos($content, '/docker') !== false ||
                            strpos($content, '/lxc') !== false ||
                            strpos($content, '/kubepods') !== false)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Try to find a readable file from a list of potential file paths
     *
     * @param  array  $potentialPaths  List of file paths to check
     * @param  bool  $logDebug  Whether to log debug information
     * @return string|null Path to the first readable file found, or null if none found
     */
    protected function findReadableFile(array $potentialPaths, bool $logDebug = false): ?string
    {
        foreach ($potentialPaths as $path) {
            if (file_exists($path) && is_readable($path)) {
                if ($logDebug) {
                    Log::debug('Found readable file at: '.$path);
                }

                return $path;
            }
        }

        if ($logDebug) {
            Log::debug('No readable file found among paths: '.implode(', ', $potentialPaths));
        }

        return null;
    }

    /**
     * Create a directory path recursively with proper permissions
     *
     * @param  string  $path  Directory path to create
     * @param  int  $mode  Permissions (default: 0755)
     * @param  bool  $logDebug  Whether to log debug information
     * @return bool Whether the operation was successful
     */
    protected function ensureDirectoryExists(string $path, int $mode = 0755, bool $logDebug = false): bool
    {
        if (file_exists($path) && is_dir($path)) {
            if ($logDebug) {
                Log::debug('Directory already exists: '.$path);
            }

            return true;
        }

        try {
            if (mkdir($path, $mode, true)) {
                if ($logDebug) {
                    Log::debug('Created directory: '.$path);
                }

                return true;
            }
        } catch (\Exception $e) {
            if ($logDebug) {
                Log::debug('Failed to create directory: '.$path.', error: '.$e->getMessage());
            }
        }

        return false;
    }

    /**
     * Get the storage path for service logs.
     *
     * @param  string  $filename  The log filename
     * @return string Full path to the log file in Laravel storage
     */
    protected function getServiceLogPath(string $filename): string
    {
        $serviceName = $this->getServiceName();
        
        // Use realpath to resolve symlinks for Envoyer deployments
        $storagePath = storage_path();
        if (is_link($storagePath)) {
            $realStoragePath = realpath($storagePath);
            if ($realStoragePath !== false) {
                $storagePath = $realStoragePath;
            }
        }
        
        $logDir = "{$storagePath}/logs/perimeter/{$serviceName}";
        
        // Ensure the directory exists
        $this->ensureDirectoryExists($logDir, 0755, true);
        
        return "{$logDir}/{$filename}";
    }

    /**
     * Convert a service-specific result to a SecurityEventData instance.
     * This is a base implementation that should be overridden by specific services.
     *
     * @param  array  $data  Service-specific result data
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData
    {
        $serviceName = $this->getServiceName();

        // Default event type based on the service type
        $type = match (true) {
            $this instanceof \Prahsys\Perimeter\Contracts\ScannerServiceInterface => 'malware',
            $this instanceof \Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface => 'vulnerability',
            $this instanceof \Prahsys\Perimeter\Contracts\MonitorServiceInterface => 'behavioral',
            $this instanceof \Prahsys\Perimeter\Contracts\IntrusionPreventionInterface => 'intrusion',
            $this instanceof \Prahsys\Perimeter\Contracts\FirewallServiceInterface => 'firewall',
            default => 'security'
        };

        // Extract common fields or use defaults
        $timestamp = $data['timestamp'] ?? now();
        $severity = $data['severity'] ?? 'medium';
        $description = $data['description'] ?? 'Security event detected';
        $location = $data['location'] ?? null;
        $user = $data['user'] ?? null;
        $scanId = $data['scan_id'] ?? null;

        // Remove fields that should be in the top-level structure
        $details = $data;
        unset($details['timestamp'], $details['type'], $details['severity'],
            $details['description'], $details['location'], $details['user'],
            $details['service'], $details['scan_id']);

        return new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: $timestamp,
            type: $type,
            severity: $severity,
            description: $description,
            location: $location,
            user: $user,
            service: $serviceName,
            scan_id: $scanId,
            details: $details
        );
    }
}
