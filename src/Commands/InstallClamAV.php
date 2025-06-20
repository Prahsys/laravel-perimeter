<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Services\ClamAVService;

class InstallClamAV extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install-clamav 
                            {--force : Force installation even if ClamAV is already installed}
                            {--no-start : Don\'t start the service after installation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure ClamAV for malware protection';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(ClamAVService $clamavService)
    {
        $this->info('Checking for ClamAV installation...');

        $isInstalled = $clamavService->isInstalled();
        $isConfigured = $clamavService->isConfigured();

        $this->info('Environment details:');
        $this->info('- ClamAV installed: '.($isInstalled ? 'Yes' : 'No'));
        $this->info('- ClamAV configured: '.($isConfigured ? 'Yes' : 'No'));

        // If already installed and not forced, exit early
        if ($isInstalled && ! $this->option('force')) {
            $this->info('ClamAV is already installed. Use --force to reinstall.');

            return 0;
        }

        // Check for root/sudo
        if (! $this->isRunningAsRoot()) {
            $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
            $this->warn('Please run this command as: sudo php artisan perimeter:install-clamav');

            return 1;
        }

        // Prepare minimal installation options
        $options = [
            'force' => $this->option('force'),
            'start' => ! $this->option('no-start'),
        ];

        $this->info('Installing ClamAV with default configuration...');

        $result = $clamavService->install($options);

        if ($result) {
            $this->info('ClamAV has been successfully installed!');

            // Display status
            $status = $clamavService->getStatus();
            $this->info('ClamAV Status: '.($status->running ? 'Running' : 'Not running'));

            if (! empty($status->details['version'])) {
                $this->info('Version: '.$status->details['version']);
            }

            return 0;
        } else {
            $this->error('Failed to install ClamAV. Check the logs for more details.');

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
}
