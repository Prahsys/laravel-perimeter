<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\AppArmorManager;

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

        // Check AppArmor status
        $appArmorManager = AppArmorManager::instance();
        $appArmorStatus = $appArmorManager->getStatus();
        $this->info('- AppArmor installed: '.($appArmorStatus['installed'] ? 'Yes' : 'No'));
        $this->info('- AppArmor enabled: '.($appArmorStatus['enabled'] ? 'Yes' : 'No'));

        // If already installed and not forced, check AppArmor configuration
        if ($isInstalled && ! $this->option('force')) {
            $this->info('ClamAV is already installed. Checking AppArmor configuration...');
            
            // Check if we need to force AppArmor configuration
            $needsAppArmorConfig = false;
            if ($appArmorStatus['installed'] && $appArmorStatus['enabled']) {
                if (!$appArmorManager->isProfileActive('usr.sbin.clamonacc')) {
                    $needsAppArmorConfig = true;
                    $this->warn('AppArmor profile for clamonacc is not loaded. This will be configured.');
                }
            }
            
            // Handle AppArmor configuration
            $this->handleAppArmorConfiguration();
            
            // Setup system permissions
            $this->setupSystemPermissions();

            if ($needsAppArmorConfig) {
                $this->info('AppArmor configuration has been updated. Please restart ClamAV daemon:');
                $this->line('  sudo systemctl restart clamav-daemon');
                $this->line('  sudo systemctl restart clamav-freshclam');
            }

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

            // Handle AppArmor configuration
            $this->handleAppArmorConfiguration();

            // Setup system permissions
            $this->setupSystemPermissions();

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
        // Check if running as root user (UID 0)
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

    /**
     * Handle AppArmor configuration for ClamAV.
     */
    protected function handleAppArmorConfiguration(): void
    {
        $this->newLine();
        $this->info('Configuring AppArmor for ClamAV...');

        $appArmorManager = AppArmorManager::instance();
        $appArmorStatus = $appArmorManager->getStatus();
        
        if (!$appArmorStatus['installed']) {
            $this->warn('AppArmor is not installed. ClamAV real-time scanning may work without it.');
            return;
        }

        if (!$appArmorStatus['enabled']) {
            $this->warn('AppArmor is installed but not enabled. Some ClamAV features may be restricted.');
            $this->warn('To enable AppArmor: sudo systemctl enable apparmor && sudo reboot');
            return;
        }

        // Install clamonacc profile
        $profiles = ['usr.sbin.clamonacc'];
        $success = $appArmorManager->configureForService('ClamAV', $profiles);
        
        if ($success) {
            $this->info('✓ AppArmor profiles configured successfully');
        } else {
            $this->warn('⚠ Failed to configure some AppArmor profiles');
            $this->warn('ClamAV may still work, but real-time scanning might be restricted');
            $this->displayAppArmorInstructions();
        }
    }

    /**
     * Display manual AppArmor configuration instructions.
     */
    protected function displayAppArmorInstructions(): void
    {
        $this->newLine();
        $this->warn('Manual AppArmor configuration may be required:');
        
        $appArmorManager = AppArmorManager::instance();
        $instructions = $appArmorManager->getInstallationInstructions('usr.sbin.clamonacc');
        foreach ($instructions as $instruction) {
            $this->line("  {$instruction}");
        }

        $this->newLine();
        $this->warn('Alternative: Put clamonacc in complain mode for debugging:');
        $this->line('  sudo aa-complain /usr/sbin/clamonacc');
    }

    /**
     * Setup system permissions for ClamAV operations.
     */
    protected function setupSystemPermissions(): void
    {
        $this->newLine();
        $this->info('Setting up system permissions...');

        $appArmorManager = AppArmorManager::instance();
        $success = $appArmorManager->setupSystemPermissions();
        
        if ($success) {
            $this->info('✓ System permissions configured successfully');
        } else {
            $this->warn('⚠ Some permission issues detected. Check the logs.');
        }

        // Additional permission fixes for the current user
        try {
            // Ensure /tmp is writable for scan logs
            if (!is_writable('/tmp')) {
                $this->warn('Warning: /tmp is not writable. This may affect ClamAV scanning.');
            }

            // Check that ClamAV directories exist and are accessible
            $clamavDirs = [
                '/var/run/clamav',
                '/var/log/clamav', 
                '/var/lib/clamav'
            ];

            foreach ($clamavDirs as $dir) {
                if (!is_dir($dir)) {
                    $this->warn("ClamAV directory does not exist: {$dir}");
                } elseif (!is_readable($dir)) {
                    $this->warn("ClamAV directory is not readable: {$dir}");
                }
            }
        } catch (\Exception $e) {
            $this->warn('Could not verify all permissions: ' . $e->getMessage());
        }

        // Verify AppArmor profile is loaded
        if ($appArmorManager->isInstalled() && $appArmorManager->isEnabled()) {
            if (!$appArmorManager->isProfileActive('usr.sbin.clamonacc')) {
                $this->warn('AppArmor profile for clamonacc is not loaded. Attempting to reload...');
                $success = $appArmorManager->installProfile('usr.sbin.clamonacc');
                if ($success) {
                    $this->info('✓ AppArmor profile reloaded successfully');
                } else {
                    $this->warn('⚠ Failed to reload AppArmor profile. ClamAV monitoring may fail.');
                    $this->displayAppArmorInstructions();
                }
            } else {
                $this->info('✓ AppArmor profile is properly loaded');
            }
        }
    }
}
