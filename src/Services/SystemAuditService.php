<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Console\OutputStyle;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Contracts\SystemAuditInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Data\ServiceAuditData;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Process\Process;

class SystemAuditService extends AbstractSecurityService implements SystemAuditInterface
{
    /**
     * The detected security issues.
     *
     * @var array
     */
    protected $issues = [];

    /**
     * The highest security level detected.
     *
     * @var string
     */
    protected $highestSeverity = 'info';

    /**
     * Security scan record.
     *
     * @var \Prahsys\Perimeter\Models\SecurityScan|null
     */
    protected $scan = null;

    /**
     * Console output.
     *
     * @var \Illuminate\Console\OutputStyle
     */
    protected $output;

    /**
     * Last audit time.
     *
     * @var int
     */
    protected $lastAuditTime = 0;

    /**
     * Create a new system audit service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        $this->output = app(OutputStyle::class, [
            'input' => new ArrayInput([]),
            'output' => new ConsoleOutput,
        ]);
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
        // System audit has no external dependencies to check
        return true;
    }

    /**
     * Check if the service is properly configured.
     */
    public function isConfigured(): bool
    {
        return $this->isEnabled();
    }

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool
    {
        // System audit service doesn't require installation
        return true;
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
     * @return array Array of SecurityEventData objects, empty array if no issues
     */
    protected function performServiceSpecificAuditChecks($output = null): array
    {
        // Reset state
        $this->issues = [];
        $this->highestSeverity = 'info';

        // Create a temporary scan record
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);
        $scan = $scanClass::start('system', 'runServiceAudit');

        // Check for security updates
        $output?->section('Security Updates Check');
        $this->checkSecurityUpdates();

        // Run the SSH, updates and certificate checks
        $failedControls = [];

        $output?->section('Security Controls Check');
        $this->checkSSHForAudit($failedControls, true);
        $this->checkAutomaticUpdatesForAudit($failedControls, true);

        if (! empty($failedControls)) {
            $this->addIssue('security_controls', 'medium', count($failedControls).' security controls need attention', [
                'failed_controls' => $failedControls,
            ]);
        }

        // Complete the scan
        $scan->complete(count($this->issues), [
            'severity' => $this->highestSeverity,
            'issues' => $this->issues,
        ]);

        // Convert issues to SecurityEventData objects
        $securityEvents = [];
        foreach ($this->issues as $issue) {
            $securityEvents[] = $this->resultToSecurityEventData([
                'timestamp' => now(),
                'severity' => $issue['severity'],
                'description' => $issue['description'],
                'details' => $issue['details'] ?? [],
                'scan_id' => $scan->id,
            ]);
        }

        return $securityEvents;
    }

    /**
     * Run audit checks specific to this service and output results.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @return \Prahsys\Perimeter\Data\ServiceAuditData Audit results with any issues found
     */
    public function runServiceAudit(?OutputStyle $output = null): ServiceAuditData
    {
        // Let the parent template method handle the flow
        return parent::runServiceAudit($output);
    }

    /**
     * Check security updates specifically for the audit.
     */
    protected function checkSecurityUpdatesForAudit(): void
    {
        // Check for security updates
        $process = new Process(['apt-get', '-s', 'upgrade']);
        $process->setTimeout(30);
        $process->run();
        $output = $process->getOutput();

        // Check if there are packages to upgrade
        if (strpos($output, '0 upgraded, 0 newly installed') === false) {
            // Simple pattern match to estimate number of updates
            preg_match('/(\d+) upgraded, (\d+) newly installed/', $output, $matches);
            $updates = isset($matches[1]) ? (int) $matches[1] : 0;

            // Add to issues
            $this->addIssue('security_updates', 'medium', 'System updates available', [
                'count' => $updates,
            ]);
        }
    }

    /**
     * Check SSH configuration for the audit.
     */
    protected function checkSSHForAudit(array &$failedControls, bool $printOutput = false): void
    {
        $process = new Process(['bash', '-c', '[ -r /etc/ssh/sshd_config ] && echo "readable" || echo "not_readable"']);
        $process->run();
        $isReadable = trim($process->getOutput()) === 'readable';

        if ($isReadable) {
            $process = new Process(['bash', '-c', 'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config']);
            $process->run();

            if ($process->isSuccessful()) {
                if ($printOutput) {
                    $this->output->success('SSH key-based authentication enforced');
                }
            } else {
                // Check for default commented config (which disables password auth on Ubuntu 24.04)
                $process = new Process(['bash', '-c', 'grep -q "^#PasswordAuthentication yes" /etc/ssh/sshd_config']);
                $process->run();

                if ($process->isSuccessful()) {
                    if ($printOutput) {
                        $this->output->success('SSH using secure defaults (password auth disabled)');
                    }
                } else {
                    if ($printOutput) {
                        $this->output->writeln('ℹ Review SSH config (unable to verify)');
                    }
                    $failedControls[] = 'ssh_config';
                }
            }
        } else {
            if ($printOutput) {
                $this->output->success('ℹ Cannot read SSH config');
            }
        }
    }

    /**
     * Check automatic updates configuration for the audit.
     */
    protected function checkAutomaticUpdatesForAudit(array &$failedControls, bool $printOutput = false): void
    {
        $process = new Process(['bash', '-c', 'dpkg -l | grep -q unattended-upgrades && systemctl is-enabled --quiet unattended-upgrades 2>/dev/null']);
        $process->run();

        if ($process->isSuccessful()) {
            if ($printOutput) {
                $this->output->success('Automatic security updates enabled');
            }
        } else {
            if ($printOutput) {
                $this->output->caution('Automatic updates may not be configured');
            }
            $failedControls[] = 'auto_updates';
        }
    }

    /**
     * Check for security updates.
     *
     * @return void
     */
    protected function checkSecurityUpdates()
    {
        $this->output->writeln('Checking if security updates are available...');

        // First, update package lists
        $process = new Process(['apt', 'update', '-qq']);
        $process->setTimeout(120);
        $process->run();

        // Then check specifically for security updates
        $process = new Process(['bash', '-c', 'apt list --upgradable 2>/dev/null | grep -i security | wc -l']);
        $process->run();
        $securityUpdates = (int) trim($process->getOutput());

        // Also check for all available updates
        $process = new Process(['apt-get', '-s', 'upgrade']);
        $process->setTimeout(30);
        $process->run();
        $output = $process->getOutput();

        // Check if there are packages to upgrade
        preg_match('/(\d+) upgraded, (\d+) newly installed/', $output, $matches);
        $allUpdates = isset($matches[1]) ? (int) $matches[1] : 0;

        if ($securityUpdates === 0 && $allUpdates === 0) {
            $this->output->success('No security updates needed');
            $this->output->writeln('System packages are up-to-date with security patches.');
        } elseif ($securityUpdates > 0 || $allUpdates > 0) {
            // Get details of the security updates
            $details = [];
            if ($securityUpdates > 0) {
                $process = new Process(['bash', '-c', 'apt list --upgradable 2>/dev/null | grep -i security | head -5']);
                $process->run();
                $details = explode("\n", trim($process->getOutput()));
            }

            // Determine severity based on update type
            $severity = $securityUpdates > 0 ? 'critical' : 'medium';
            $description = $securityUpdates > 0
                ? "$securityUpdates security updates available"
                : "$allUpdates system updates available";

            // Add to issues
            $this->addIssue('security_updates', $severity, $description, [
                'security_updates_count' => $securityUpdates,
                'all_updates_count' => $allUpdates,
                'details' => $details,
            ]);

            // Output to console
            $this->output->caution($description);
            if (! empty($details)) {
                $this->output->writeln('');
                foreach ($details as $detail) {
                    $this->output->writeln("  - $detail");
                }
            }

            $this->output->writeln('');
            $this->output->writeln('Recommendation: Run the following command to apply updates:');
            $this->output->writeln('  <fg=cyan>apt-get update && apt-get upgrade -y</>');
        }
    }

    /**
     * Check security controls.
     *
     * @return void
     */
    protected function checkSecurityControls()
    {
        $this->output->section('Security Controls Check');

        $failedControls = [];

        // Check SSH configuration
        $process = new Process(['bash', '-c', '[ -r /etc/ssh/sshd_config ] && echo "readable" || echo "not_readable"']);
        $process->run();
        $isReadable = trim($process->getOutput()) === 'readable';

        if ($isReadable) {
            $process = new Process(['bash', '-c', 'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config']);
            $process->run();

            if ($process->isSuccessful()) {
                $this->output->success('Access Control: SSH key-based authentication enforced');
            } else {
                // Check for default commented config (which disables password auth on Ubuntu 24.04)
                $process = new Process(['bash', '-c', 'grep -q "^#PasswordAuthentication yes" /etc/ssh/sshd_config']);
                $process->run();

                if ($process->isSuccessful()) {
                    $this->output->success('Access Control: SSH using secure defaults (password auth disabled)');
                } else {
                    $this->output->writeln('ℹ Access Control: Review SSH config (unable to verify)');
                    $failedControls[] = 'ssh_config';
                }
            }
        } else {
            $this->output->success('ℹ Access Control: Cannot read SSH config');
        }

        // Check unattended-upgrades
        $process = new Process(['bash', '-c', 'dpkg -l | grep -q unattended-upgrades && systemctl is-enabled --quiet unattended-upgrades 2>/dev/null']);
        $process->run();

        if ($process->isSuccessful()) {
            $this->output->success('Updates: Automatic security updates enabled');
        } else {
            $this->output->caution('Updates: Automatic updates may not be configured');
            $failedControls[] = 'auto_updates';
        }

        if (! empty($failedControls)) {
            // Add to issues
            $this->addIssue('security_controls', 'medium', count($failedControls).' security controls need attention', [
                'failed_controls' => $failedControls,
            ]);
        }
    }

    /**
     * Add an issue to the list and update highest severity.
     *
     * @param  string  $type
     * @param  string  $severity
     * @param  string  $description
     * @return void
     */
    protected function addIssue($type, $severity, $description, array $details = [])
    {
        $this->issues[] = [
            'type' => $type,
            'severity' => $severity,
            'description' => $description,
            'details' => $details,
            'timestamp' => now()->toIso8601String(),
        ];

        // Update highest severity if needed
        $severityLevels = [
            'critical' => 0,
            'high' => 1,
            'medium' => 2,
            'low' => 3,
            'info' => 4,
        ];

        if ($severityLevels[$severity] < $severityLevels[$this->highestSeverity]) {
            $this->highestSeverity = $severity;
        }
    }

    /**
     * Get counts of issues by severity.
     */
    protected function getSeverityCounts(): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($this->issues as $issue) {
            $counts[$issue['severity']]++;
        }

        return $counts;
    }

    /**
     * Log scan results with the appropriate severity level.
     *
     * @return void
     */
    protected function logScanResults()
    {
        if (empty($this->issues)) {
            Log::info('System security audit completed with no issues detected', [
                'scan_id' => $this->scan->id,
                'timestamp' => now()->toIso8601String(),
            ]);

            return;
        }

        // Map severity to log level
        $logLevelMap = [
            'critical' => 'critical',
            'high' => 'error',
            'medium' => 'warning',
            'low' => 'notice',
            'info' => 'info',
        ];

        $logLevel = $logLevelMap[$this->highestSeverity] ?? 'error';
        $channels = config('perimeter.logging.channels', ['stack']);

        // Create a security event for each issue
        $eventClass = config('perimeter.storage.models.security_event', \Prahsys\Perimeter\Models\SecurityEvent::class);

        foreach ($this->issues as $issue) {
            // Create event data
            $eventData = $this->resultToSecurityEventData([
                'timestamp' => now(),
                'severity' => $issue['severity'],
                'description' => $issue['description'],
                'details' => $issue['details'],
                'type' => $issue['type'] ?? 'system',
                'scan_id' => $this->scan->id,
            ]);

            Log::info('Creating security event for system audit issue', [
                'scan_id' => $this->scan->id,
                'description' => $issue['description'],
                'severity' => $issue['severity'],
                'type' => $issue['type'] ?? 'system',
            ]);

            // Store in database
            try {
                $eventClass::create($eventData->toModelArray());
            } catch (\Exception $e) {
                Log::error('Failed to create security event for system audit issue', [
                    'error' => $e->getMessage(),
                    'description' => $issue['description'],
                ]);
            }
        }

        // Log a summary with the highest severity level
        $message = sprintf(
            'System security audit detected %d issues with highest severity: %s',
            count($this->issues),
            strtoupper($this->highestSeverity)
        );

        foreach ($channels as $channel) {
            Log::channel($channel)->log($logLevel, $message, [
                'scan_id' => $this->scan->id,
                'issues_count' => count($this->issues),
                'highest_severity' => $this->highestSeverity,
                'timestamp' => now()->toIso8601String(),
            ]);
        }

        // Update the last audit time
        $this->lastAuditTime = time();
    }

    /**
     * Get the last time an audit was run.
     *
     * @return int Unix timestamp or 0 if never run
     */
    public function getLastAuditTime(): int
    {
        if ($this->lastAuditTime > 0) {
            return $this->lastAuditTime;
        }

        // Try to get the timestamp from the last scan
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);
        $lastScan = $scanClass::where('type', 'system')
            ->orderBy('created_at', 'desc')
            ->first();

        if ($lastScan) {
            $this->lastAuditTime = $lastScan->created_at->timestamp;

            return $this->lastAuditTime;
        }

        return 0;
    }

    /**
     * Get a count of issues by severity.
     */
    public function getIssueCountBySeverity(): array
    {
        return $this->getSeverityCounts();
    }

    /**
     * Get the current status of the service.
     */
    public function getStatus(): \Prahsys\Perimeter\Data\ServiceStatusData
    {
        $lastAuditTime = $this->getLastAuditTime();
        $formattedTime = $lastAuditTime > 0 ? date('Y-m-d H:i:s', $lastAuditTime) : 'Never';

        return new \Prahsys\Perimeter\Data\ServiceStatusData(
            name: 'System Audit',
            enabled: $this->isEnabled(),
            installed: $this->isInstalled(),
            configured: $this->isConfigured(),
            running: true, // System audit is always running if installed and configured
            message: $this->isEnabled() ? 'System audit service is ready' : 'System audit service is disabled',
            details: [
                'last_audit' => $formattedTime,
                'issues_count' => count($this->issues),
                'severity_counts' => $this->getIssueCountBySeverity(),
                'highest_severity' => $this->highestSeverity,
            ]
        );
    }

    /**
     * Convert a system audit result to a SecurityEventData instance.
     *
     * @param  array  $data  System audit result data
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData
    {
        $timestamp = $data['timestamp'] ?? now();
        $severity = strtolower($data['severity'] ?? 'info');
        $description = $data['description'] ?? 'System audit issue detected';
        $scanId = $data['scan_id'] ?? null;

        $details = array_merge($data, []);

        // Remove fields that will be used in the main properties
        unset($details['timestamp'], $details['severity'], $details['description'],
            $details['location'], $details['user'], $details['service'], $details['scan_id']);

        return new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: $timestamp,
            type: 'system',
            severity: $severity,
            description: $description,
            location: null,
            user: null,
            service: $this->getServiceName(),
            scan_id: $scanId,
            details: $details
        );
    }
}
