<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Services\FalcoService;

class InstallFalco extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install-falco
                            {--force : Force installation even if already installed}
                            {--no-start : Don\'t start the service after installation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure Falco for runtime security monitoring';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(FalcoService $falcoService)
    {
        $this->info('Checking for Falco installation...');

        $isInstalled = $falcoService->isInstalled();
        $isConfigured = $falcoService->isConfigured();

        $this->info('Environment details:');
        $this->info('- Falco installed: '.($isInstalled ? 'Yes' : 'No'));
        $this->info('- Falco configured: '.($isConfigured ? 'Yes' : 'No'));

        // If already installed and not forced, exit early
        if ($isInstalled && ! $this->option('force')) {
            $this->info('Falco is already installed. Use --force to reinstall.');

            return 0;
        }

        // Check for root/sudo
        if (! $this->isRunningAsRoot()) {
            $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
            $this->warn('Please run this command as: sudo php artisan perimeter:install-falco');

            return 1;
        }

        // Prepare minimal installation options
        $options = [
            'force' => $this->option('force'),
            'start' => ! $this->option('no-start'),
        ];

        $this->info('Installing Falco with default configuration...');

        $result = $falcoService->install($options);

        if ($result) {
            $this->info('Falco has been successfully installed!');

            // Display status
            $status = $falcoService->getStatus();
            $this->info('Falco Status: '.($status->running ? 'Running' : 'Not running'));

            if (! empty($status->details['version'])) {
                $this->info('Version: '.$status->details['version']);
            }

            return 0;
        } else {
            $this->error('Failed to install Falco. Check the logs for more details.');

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
