<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\Fail2banService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\TrivyService;
use Prahsys\Perimeter\Services\UfwService;

class PerimeterHealth extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:health';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check the health of all security components';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Checking Perimeter security components health...');
        $this->newLine();

        $results = [];
        $allHealthy = true;

        // Check ClamAV
        $clamAV = $this->checkClamAV();
        $results[] = [
            'Component' => 'ClamAV (Malware Protection)',
            'Enabled' => $clamAV['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => $clamAV['installed'] ? '<fg=green>Yes</>' : ($clamAV['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Configured' => $clamAV['configured'] ? '<fg=green>Yes</>' : ($clamAV['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $clamAV['enabled'] ? '<fg=gray>N/A</>' : ($clamAV['healthy'] ? '<fg=green>Healthy</>' : '<fg=red>Unhealthy</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($clamAV['enabled']) {
            $allHealthy = $allHealthy && $clamAV['healthy'];
        }

        // Check Falco
        $falco = $this->checkFalco();
        $results[] = [
            'Component' => 'Falco (Runtime Protection)',
            'Enabled' => $falco['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => $falco['installed'] ? '<fg=green>Yes</>' : ($falco['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Configured' => $falco['configured'] ? '<fg=green>Yes</>' : ($falco['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $falco['enabled'] ? '<fg=gray>N/A</>' : ($falco['healthy'] ? '<fg=green>Healthy</>' : '<fg=red>Unhealthy</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($falco['enabled']) {
            $allHealthy = $allHealthy && $falco['healthy'];
        }

        // Check Trivy
        $trivy = $this->checkTrivy();
        $results[] = [
            'Component' => 'Trivy (Vulnerability Scanning)',
            'Enabled' => $trivy['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => $trivy['installed'] ? '<fg=green>Yes</>' : ($trivy['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Configured' => $trivy['configured'] ? '<fg=green>Yes</>' : ($trivy['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $trivy['enabled'] ? '<fg=gray>N/A</>' : ($trivy['healthy'] ? '<fg=green>Healthy</>' : '<fg=red>Unhealthy</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($trivy['enabled']) {
            $allHealthy = $allHealthy && $trivy['healthy'];
        }

        // Check UFW
        $ufw = $this->checkUfw();
        $results[] = [
            'Component' => 'UFW (Firewall)',
            'Enabled' => $ufw['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => $ufw['installed'] ? '<fg=green>Yes</>' : ($ufw['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Configured' => $ufw['configured'] ? '<fg=green>Yes</>' : ($ufw['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $ufw['enabled'] ? '<fg=gray>N/A</>' : ($ufw['healthy'] ? '<fg=green>Healthy</>' : '<fg=red>Unhealthy</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($ufw['enabled']) {
            $allHealthy = $allHealthy && $ufw['healthy'];
        }

        // Check Fail2Ban
        $fail2ban = $this->checkFail2ban();
        $results[] = [
            'Component' => 'Fail2Ban (Intrusion Prevention)',
            'Enabled' => $fail2ban['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => $fail2ban['installed'] ? '<fg=green>Yes</>' : ($fail2ban['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Configured' => $fail2ban['configured'] ? '<fg=green>Yes</>' : ($fail2ban['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $fail2ban['enabled'] ? '<fg=gray>N/A</>' : ($fail2ban['healthy'] ? '<fg=green>Healthy</>' : '<fg=red>Unhealthy</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($fail2ban['enabled']) {
            $allHealthy = $allHealthy && $fail2ban['healthy'];
        }

        // Check environment configuration
        $env = $this->checkEnvironment();
        $results[] = [
            'Component' => 'Environment Configuration',
            'Enabled' => $env['enabled'] ? '<fg=green>Yes</>' : '<fg=yellow>No</>',
            'Installed' => '<fg=gray>N/A</>',
            'Configured' => $env['configured'] ? '<fg=green>Yes</>' : ($env['enabled'] ? '<fg=red>No</>' : '<fg=gray>N/A</>'),
            'Status' => ! $env['enabled'] ? '<fg=gray>N/A</>' : ($env['healthy'] ? '<fg=green>Healthy</>' : '<fg=yellow>Warning</>'),
        ];
        // Only consider it for overall health if it's enabled
        if ($env['enabled']) {
            $allHealthy = $allHealthy && $env['healthy'];
        }

        $this->table(['Component', 'Enabled', 'Installed', 'Configured', 'Status'], $results);
        $this->newLine();

        if ($allHealthy) {
            $this->info('All security components are healthy and operational.');
        } else {
            $this->warn('Some security components are not healthy. See details above.');
            $this->line('Run <fg=yellow>php artisan perimeter:install</> to fix potential issues.');
        }

        return $allHealthy ? 0 : 1;
    }

    /**
     * Check ClamAV health.
     */
    protected function checkClamAV(): array
    {
        try {
            $clamAVService = app(ClamAVService::class);
            $status = $clamAVService->getStatus();

            // If not installed, show warnings
            if (! $status->isInstalled()) {
                $this->line('ClamAV is not installed or not functioning properly.');
            }

            // If not configured, show warnings
            if (! $status->isConfigured()) {
                $socketPath = config('perimeter.clamav.socket', '/var/run/clamav/clamd.ctl');
                $this->line('ClamAV socket directory does not exist: '.dirname($socketPath));
            }

            // Show message if available
            if ($status->getMessage()) {
                $this->line('ClamAV status: '.$status->getMessage());
            }

            // Show version if available
            if (isset($status->details['version']) && $status->details['version']) {
                $this->line('  • <fg=white>Version:</> '.$status->details['version']);
            }

            // Show scan paths if available
            if (! empty($status->details['scan_paths'])) {
                $this->line('  • <fg=white>Scan paths:</> '.implode(', ', $status->details['scan_paths']));
            }

            // Component is healthy if all conditions are met
            return [
                'enabled' => $status->isEnabled(),
                'installed' => $status->isInstalled(),
                'configured' => $status->isConfigured(),
                'healthy' => $status->isHealthy(),
                'status' => $status,
            ];
        } catch (\Exception $e) {
            $this->line('ClamAV check error: '.$e->getMessage());

            return [
                'enabled' => false,
                'installed' => false,
                'configured' => false,
                'healthy' => false,
            ];
        }
    }

    /**
     * Check Falco health.
     */
    protected function checkFalco(): array
    {
        try {
            $falcoService = app(FalcoService::class);
            $status = $falcoService->getStatus();

            // Show message if available
            if ($status->getMessage()) {
                $this->line('Falco status: '.$status->getMessage());
            }

            // If not installed, show warnings
            if (! $status->isInstalled()) {
                $this->line('Falco is not installed or not functioning properly.');
            }

            // If not configured, show warnings
            if (! $status->isConfigured()) {
                $this->line('Falco configuration issues detected.');
            }

            // Show version if available
            if (isset($status->details['version']) && $status->details['version']) {
                $this->line('  • <fg=white>Version:</> '.$status->details['version']);
            }

            // Show rules if available
            if (! empty($status->details['rules'])) {
                $this->line('  • <fg=white>Custom rules:</> '.count($status->details['rules']));
            }

            // Show recent events if available
            if (! empty($status->details['recent_events'])) {
                $this->line('  • <fg=white>Recent security events:</> '.count($status->details['recent_events']));

                foreach ($status->details['recent_events'] as $index => $event) {
                    if ($index >= 3) {
                        break;
                    } // Show up to 3 events

                    $description = $event['description'] ?? 'Unknown event';
                    $priority = $event['priority'] ?? 'unknown';
                    $this->line("    - [$priority] $description");
                }
            }

            return [
                'enabled' => $status->isEnabled(),
                'installed' => $status->isInstalled(),
                'configured' => $status->isConfigured(),
                'healthy' => $status->isHealthy(),
                'status' => $status,
            ];
        } catch (\Exception $e) {
            $this->line('Falco check error: '.$e->getMessage());

            return [
                'enabled' => false,
                'installed' => false,
                'configured' => false,
                'healthy' => false,
            ];
        }
    }

    /**
     * Check Trivy health.
     */
    protected function checkTrivy(): array
    {
        try {
            $trivyService = app(TrivyService::class);
            $status = $trivyService->getStatus();

            // Show message if available
            if ($status->getMessage()) {
                $this->line('Trivy status: '.$status->getMessage());
            }

            // If not installed, show warnings
            if (! $status->isInstalled()) {
                $this->line('Trivy is not installed or not functioning properly.');
            }

            // If not configured, show warnings
            if (! $status->isConfigured()) {
                $this->line('Trivy configuration issues detected.');
            }

            // Show version if available
            if (isset($status->details['version']) && $status->details['version']) {
                $this->line('  • <fg=white>Version:</> '.$status->details['version']);
            }

            // Show database info if available
            if (! empty($status->details['vulnerability_db'])) {
                $dbInfo = $status->details['vulnerability_db'];

                if (isset($dbInfo['last_update']) && $dbInfo['last_update'] > 0) {
                    $lastUpdate = date('Y-m-d H:i:s', $dbInfo['last_update']);
                    $this->line("  • <fg=white>Database last updated:</> $lastUpdate");
                }

                if (isset($dbInfo['severity_threshold'])) {
                    $this->line('  • <fg=white>Severity threshold:</> '.$dbInfo['severity_threshold']);
                }
            }

            // Show scan targets if available
            if (! empty($status->details['scan_targets'])) {
                $this->line('  • <fg=white>Scan targets:</> '.implode(', ', $status->details['scan_targets']));
            }

            return [
                'enabled' => $status->isEnabled(),
                'installed' => $status->isInstalled(),
                'configured' => $status->isConfigured(),
                'healthy' => $status->isHealthy(),
                'status' => $status,
            ];
        } catch (\Exception $e) {
            $this->line('Trivy check error: '.$e->getMessage());

            return [
                'enabled' => false,
                'installed' => false,
                'configured' => false,
                'healthy' => false,
            ];
        }
    }

    /**
     * Check UFW health.
     */
    protected function checkUfw(): array
    {
        try {
            $ufwService = app(UfwService::class);
            $status = $ufwService->getStatus();

            // Show message if available
            if ($status->getMessage()) {
                $this->line('UFW status: '.$status->getMessage());
            }

            // Display status information
            if ($status->isInstalled()) {
                if ($status->isConfigured() && $status->isRunning()) {
                    // Don't print redundant status line, use the message from UfwService

                    // Show rule information
                    $ruleCount = count($status->details['rules'] ?? []);
                    if ($ruleCount > 0) {
                        $this->line("  • <fg=white>Rules configured:</> $ruleCount");

                        // Show policy information
                        $defaultPolicy = $status->details['default_policy'] ?? [];

                        if (is_array($defaultPolicy)) {
                            $incomingPolicy = $defaultPolicy['incoming'] ?? 'unknown';
                            $outgoingPolicy = $defaultPolicy['outgoing'] ?? 'unknown';
                            $this->line("  • <fg=white>Default policies:</> incoming=$incomingPolicy, outgoing=$outgoingPolicy");
                        } else {
                            $this->line("  • <fg=white>Default policy:</> $defaultPolicy");
                        }
                    } else {
                        // Don't print redundant no rules message, already in the status message
                    }

                    // Show port configuration from service status
                    $expectedPorts = $status->details['expected_ports'] ?? [];
                    $publicPorts = $status->details['public_ports'] ?? [];
                    $restrictedPorts = $status->details['restricted_ports'] ?? [];

                    if (! empty($expectedPorts)) {
                        $portsStr = is_array($expectedPorts) ? implode(', ', $expectedPorts) : $expectedPorts;
                        $this->line("  • <fg=white>Expected ports:</> $portsStr");
                    }

                    if (! empty($publicPorts)) {
                        $portsStr = is_array($publicPorts) ? implode(', ', $publicPorts) : $publicPorts;
                        $this->line("  • <fg=white>Public ports:</> $portsStr");
                    }

                    if (! empty($restrictedPorts)) {
                        $portsStr = is_array($restrictedPorts) ? implode(', ', $restrictedPorts) : $restrictedPorts;
                        $this->line("  • <fg=white>Restricted ports:</> $portsStr");
                    }
                } else {
                    $this->line('<fg=red>UFW is installed but not active.</>');
                    $this->line('  • Run <fg=cyan>php artisan perimeter:install-ufw</> or manually enable with <fg=cyan>ufw enable</>');
                }
            } else {
                $this->line('<fg=red>UFW is not installed or not functioning properly.</>');
                $this->line('  • Run <fg=cyan>php artisan perimeter:install-ufw</> to install it');
            }

            return [
                'enabled' => $status->isEnabled(),
                'installed' => $status->isInstalled(),
                'configured' => $status->isConfigured(),
                'healthy' => $status->isHealthy(),
                'status' => $status,
            ];
        } catch (\Exception $e) {
            $this->line('<fg=red>UFW check error: '.$e->getMessage().'</>');

            return [
                'enabled' => false,
                'installed' => false,
                'configured' => false,
                'healthy' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check Fail2Ban health.
     */
    protected function checkFail2ban(): array
    {
        try {
            $fail2banService = app(Fail2banService::class);
            $status = $fail2banService->getStatus();

            // Show message if available
            if ($status->getMessage()) {
                $this->line('Fail2Ban status: '.$status->getMessage());
            }

            // Display status information
            if ($status->isInstalled()) {
                if ($status->isConfigured() && $status->isRunning()) {
                    $this->line('Fail2Ban is active and properly configured');

                    // Show jail information
                    $jails = $status->details['jails'] ?? [];
                    if (! empty($jails)) {
                        $this->line('  • <fg=white>Active jails:</> '.implode(', ', $jails));

                        // Show jail configuration details for each active jail
                        foreach ($jails as $jail) {
                            $jailStatus = $fail2banService->getJailStatus($jail);
                            $bannedCount = count($jailStatus['banned_ips'] ?? []);
                            $this->line("    - <fg=white>$jail:</> $bannedCount banned IPs");
                        }
                    } else {
                        $this->line('  • <fg=yellow>No active jails configured</>');
                    }

                    // Show Fail2ban configuration
                    $findTime = $status->details['find_time'] ?? 600;
                    $banTime = $status->details['ban_time'] ?? 3600;
                    $maxRetry = $status->details['max_retry'] ?? 5;

                    $this->line("  • <fg=white>Settings:</> find_time=${findTime}s, ban_time=${banTime}s, max_retry=$maxRetry");

                    // Show enabled jails from config
                    $enabledJails = $status->details['enabled_jails'] ?? [];
                    if (! empty($enabledJails)) {
                        $this->line('  • <fg=white>Configured jails:</> '.implode(', ', $enabledJails));
                    }

                    // Show version if available
                    if (isset($status->details['version']) && $status->details['version']) {
                        $this->line('  • <fg=white>Version:</> '.$status->details['version']);
                    }
                } else {
                    $this->line('<fg=red>Fail2Ban is installed but not running.</>');
                    $this->line('  • Run <fg=cyan>php artisan perimeter:install-fail2ban</> or manually start with <fg=cyan>systemctl start fail2ban</>');
                }
            } else {
                $this->line('<fg=red>Fail2Ban is not installed or not functioning properly.</>');
                $this->line('  • Run <fg=cyan>php artisan perimeter:install-fail2ban</> to install it');
            }

            return [
                'enabled' => $status->isEnabled(),
                'installed' => $status->isInstalled(),
                'configured' => $status->isConfigured(),
                'healthy' => $status->isHealthy(),
                'status' => $status,
            ];
        } catch (\Exception $e) {
            $this->error('<fg=red>Error checking Fail2Ban health: '.$e->getMessage().'</>');

            return [
                'enabled' => false,
                'installed' => false,
                'configured' => false,
                'healthy' => false,
            ];
        }
    }

    /**
     * Check environment configuration.
     */
    protected function checkEnvironment(): array
    {
        $issues = 0;
        $enabled = config('perimeter.enabled', false);

        // Check if perimeter is enabled
        if (! $enabled) {
            $this->line('Warning: Perimeter is disabled in configuration.');
            $issues++;
        }

        $configured = true;

        // Check logging configuration
        $logChannels = config('perimeter.logging.channels', []);
        if (empty($logChannels)) {
            $this->line('Warning: No logging channels configured for Perimeter.');
            $issues++;
            $configured = false;
        }

        // Consider environment healthy if there are no more than 1 issue
        $healthy = $issues <= 1;

        return [
            'enabled' => $enabled,
            'configured' => $configured,
            'healthy' => $healthy,
        ];
    }

    /**
     * Check if we're running in a container environment.
     */
    protected function isRunningInContainer(): bool
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
}
