<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Services\Fail2banService;

class InstallFail2ban extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install-fail2ban 
                            {--force : Force installation even if Fail2Ban is already installed}
                            {--configure : Create a basic configuration file}
                            {--ban-time=3600 : Duration in seconds for banning IPs}
                            {--find-time=600 : Time window in seconds for finding failed attempts}
                            {--max-retry=5 : Number of retries before banning}
                            {--no-start : Don\'t start the service after installation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure Fail2Ban for intrusion prevention';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(Fail2banService $fail2banService)
    {
        $this->info('Checking for Fail2Ban installation...');

        $isInstalled = $fail2banService->isInstalled();
        $isConfigured = $fail2banService->isConfigured();
        $isInContainer = \Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer();

        $this->info('Environment details:');
        $this->info('- Running in container: '.($isInContainer ? 'Yes' : 'No'));
        $this->info('- Fail2ban installed: '.($isInstalled ? 'Yes' : 'No'));
        $this->info('- Fail2ban configured: '.($isConfigured ? 'Yes' : 'No'));

        // If already installed and not forced, exit early
        if ($isInstalled && $isConfigured && ! $this->option('force')) {
            $this->info('Fail2Ban is already installed and configured.');

            return 0;
        }

        // Check for root/sudo (skip in container as we often have root already)
        if (! $isInContainer && ! $this->isRunningAsRoot()) {
            $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
            $this->warn('Please run this command as: sudo php artisan perimeter:install-fail2ban');

            return 1;
        }

        $this->info('Installing Fail2Ban...');

        // Use the service's install method with our command line options
        $options = [
            'configure' => true, // Always configure when passing command-line options
            'force' => $this->option('force'),
            'start' => ! $this->option('no-start'),
            'ban_time' => $this->option('ban-time'),
            'find_time' => $this->option('find-time'),
            'max_retry' => $this->option('max-retry'),
            'container_mode' => $isInContainer,
            'create_auth_log' => $isInContainer,
            'use_dummy_actions' => $isInContainer,
        ];

        $this->info('Installing with parameters:');
        $this->info("- Ban time: {$options['ban_time']} seconds");
        $this->info("- Find time: {$options['find_time']} seconds");
        $this->info("- Max retry: {$options['max_retry']} attempts");

        $result = $fail2banService->install($options);

        if ($result) {
            $this->info('Fail2Ban has been successfully installed!');

            // Display status
            $status = $fail2banService->getStatus();

            $this->info('Fail2Ban Status:');
            $this->info('- Running: '.($status->running ? 'Yes' : 'No'));

            if (! empty($status->details['version'])) {
                $this->info('- Version: '.$status->details['version']);
            }

            if (! empty($status->details['jails'])) {
                $this->info('- Active Jails: '.implode(', ', $status->details['jails']));
            } else {
                $this->info('- Active Jails: None');
            }

            return 0;
        } else {
            $this->error('Failed to install Fail2Ban. Check the logs for more details.');

            return 1;
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

        // Check if USER environment variable is set to root
        if (getenv('USER') === 'root' || $_SERVER['USER'] ?? null === 'root') {
            return true;
        }

        // Check if running under sudo
        if (getenv('SUDO_USER') !== false) {
            return true;
        }

        return false;
    }
}
