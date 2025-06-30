<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\Process;

class AppArmorManager
{
    /**
     * Get the singleton instance of AppArmorManager.
     */
    public static function instance(): self
    {
        return app(self::class);
    }
    /**
     * Check if AppArmor is installed and active on the system.
     */
    public function isInstalled(): bool
    {
        try {
            $process = new Process(['which', 'apparmor_parser']);
            $process->run();

            return $process->isSuccessful();
        } catch (\Exception $e) {
            Log::debug('AppArmor check failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if AppArmor is enabled and enforcing.
     */
    public function isEnabled(): bool
    {
        if (!$this->isInstalled()) {
            return false;
        }

        try {
            $process = new Process(['aa-enabled']);
            $process->run();

            return $process->isSuccessful();
        } catch (\Exception $e) {
            Log::debug('AppArmor enabled check failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get AppArmor status information.
     */
    public function getStatus(): array
    {
        $status = [
            'installed' => $this->isInstalled(),
            'enabled' => false,
            'profiles' => [],
            'mode' => 'unknown',
        ];

        if (!$status['installed']) {
            return $status;
        }

        $status['enabled'] = $this->isEnabled();

        try {
            $process = new Process(['aa-status']);
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                $status['profiles'] = $this->parseStatusOutput($output);
                
                if (str_contains($output, 'apparmor module is loaded')) {
                    $status['mode'] = 'enforcing';
                }
            }
        } catch (\Exception $e) {
            Log::debug('AppArmor status check failed: ' . $e->getMessage());
        }

        return $status;
    }

    /**
     * Check if a specific profile exists.
     */
    public function profileExists(string $profilePath): bool
    {
        $profileFile = "/etc/apparmor.d/{$profilePath}";
        return file_exists($profileFile);
    }

    /**
     * Install an AppArmor profile from the package.
     */
    public function installProfile(string $profileName, string $sourcePath = null): bool
    {
        if (!$this->isInstalled()) {
            Log::warning('AppArmor is not installed, skipping profile installation');
            return false;
        }

        try {
            // Determine source path
            if ($sourcePath === null) {
                $sourcePath = $this->getPackageProfilePath($profileName);
            }

            if (!file_exists($sourcePath)) {
                Log::error("AppArmor profile source not found: {$sourcePath}");
                return false;
            }

            $targetPath = "/etc/apparmor.d/{$profileName}";

            // Copy profile file
            if (!copy($sourcePath, $targetPath)) {
                Log::error("Failed to copy AppArmor profile to {$targetPath}");
                return false;
            }

            // Set correct permissions
            chmod($targetPath, 0644);
            Log::info("Copied AppArmor profile to: {$targetPath}");

            // Load the profile
            $process = new Process(['apparmor_parser', '-r', $targetPath]);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info("AppArmor profile installed successfully: {$profileName}");
                
                // Verify it's actually loaded
                if ($this->isProfileActive($profileName)) {
                    Log::info("AppArmor profile verified as active: {$profileName}");
                    return true;
                } else {
                    Log::warning("AppArmor profile copied but not showing as active: {$profileName}");
                    return false;
                }
            } else {
                $errorOutput = $process->getErrorOutput();
                Log::error("Failed to load AppArmor profile: {$errorOutput}");
                
                // Try to put it in complain mode as fallback
                $complainProcess = new Process(['aa-complain', '/usr/sbin/clamonacc']);
                $complainProcess->run();
                
                if ($complainProcess->isSuccessful()) {
                    Log::info("AppArmor profile set to complain mode as fallback: {$profileName}");
                    return true;
                }
                
                return false;
            }

        } catch (\Exception $e) {
            Log::error("AppArmor profile installation failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Put a profile in complain mode (for debugging).
     */
    public function setComplainMode(string $binaryPath): bool
    {
        if (!$this->isInstalled()) {
            return false;
        }

        try {
            $process = new Process(['aa-complain', $binaryPath]);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info("AppArmor profile set to complain mode: {$binaryPath}");
                return true;
            } else {
                Log::error("Failed to set AppArmor complain mode: " . $process->getErrorOutput());
                return false;
            }
        } catch (\Exception $e) {
            Log::error("AppArmor complain mode failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Put a profile in enforce mode.
     */
    public function setEnforceMode(string $binaryPath): bool
    {
        if (!$this->isInstalled()) {
            return false;
        }

        try {
            $process = new Process(['aa-enforce', $binaryPath]);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info("AppArmor profile set to enforce mode: {$binaryPath}");
                return true;
            } else {
                Log::error("Failed to set AppArmor enforce mode: " . $process->getErrorOutput());
                return false;
            }
        } catch (\Exception $e) {
            Log::error("AppArmor enforce mode failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get installation instructions for AppArmor configuration.
     */
    public function getInstallationInstructions(string $profileName): array
    {
        $instructions = [];

        if (!$this->isInstalled()) {
            $instructions[] = 'AppArmor is not installed. Install it with: sudo apt-get install apparmor-utils';
            return $instructions;
        }

        if (!$this->isEnabled()) {
            $instructions[] = 'AppArmor is installed but not enabled. Enable it with: sudo systemctl enable apparmor';
            $instructions[] = 'Reboot may be required after enabling AppArmor';
        }

        $profilePath = "/etc/apparmor.d/{$profileName}";
        if (!file_exists($profilePath)) {
            $sourcePath = $this->getPackageProfilePath($profileName);
            $instructions[] = "Copy AppArmor profile: sudo cp {$sourcePath} {$profilePath}";
            $instructions[] = "Load AppArmor profile: sudo apparmor_parser -r {$profilePath}";
        }

        if (empty($instructions)) {
            $instructions[] = 'AppArmor is properly configured for this service';
        }

        return $instructions;
    }

    /**
     * Configure AppArmor for a specific service.
     */
    public function configureForService(string $serviceName, array $profiles): bool
    {
        if (!$this->isInstalled()) {
            Log::info("AppArmor not installed, skipping {$serviceName} profile configuration");
            return true; // Not an error if AppArmor isn't installed
        }

        $success = true;
        foreach ($profiles as $profile) {
            if (!$this->installProfile($profile)) {
                $success = false;
                Log::warning("Failed to install AppArmor profile: {$profile}");
            }
        }

        return $success;
    }

    /**
     * Setup necessary directories and permissions for system operations.
     */
    public function setupSystemPermissions(): bool
    {
        try {
            // Create and set permissions for necessary directories
            $directories = [
                '/tmp' => 0755,
                '/var/run' => 0755,
                '/var/log' => 0755,
                '/var/run/clamav' => 0755,
                '/var/log/clamav' => 0755,
                '/var/lib/clamav' => 0755,
            ];

            foreach ($directories as $dir => $permissions) {
                if (!is_dir($dir)) {
                    if (!mkdir($dir, $permissions, true)) {
                        Log::warning("Failed to create directory: {$dir}");
                        continue;
                    }
                    Log::info("Created directory: {$dir}");
                }

                // Check if directory is writable
                if (!is_writable($dir)) {
                    Log::warning("Directory is not writable: {$dir}");
                }
            }

            // Setup ClamAV specific directories and permissions if running as root
            if (function_exists('posix_getuid') && posix_getuid() === 0) {
                $this->setupClamAVPermissions();
            }

            return true;
        } catch (\Exception $e) {
            Log::error("Failed to setup system permissions: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if AppArmor profile is loaded and active.
     */
    public function isProfileActive(string $profileName): bool
    {
        if (!$this->isInstalled() || !$this->isEnabled()) {
            return false;
        }

        try {
            $process = new Process(['aa-status']);
            $process->run();

            if ($process->isSuccessful()) {
                $output = $process->getOutput();
                // Check if profile is loaded (in any mode - enforce or complain)
                return str_contains($output, $profileName);
            }

            return false;
        } catch (\Exception $e) {
            Log::debug("Failed to check profile status: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Setup ClamAV specific directories and permissions.
     */
    protected function setupClamAVPermissions(): void
    {
        try {
            // ClamAV directories that need specific ownership
            $clamavDirs = [
                '/var/run/clamav',
                '/var/log/clamav',
                '/var/lib/clamav',
            ];

            foreach ($clamavDirs as $dir) {
                if (is_dir($dir)) {
                    // Try to set proper ownership if running as root
                    exec("chown -R clamav:clamav {$dir} 2>/dev/null", $output, $exitCode);
                    if ($exitCode === 0) {
                        Log::info("Set ownership for ClamAV directory: {$dir}");
                    }
                    
                    // Set proper permissions
                    exec("chmod 755 {$dir} 2>/dev/null", $output, $exitCode);
                    if ($exitCode === 0) {
                        Log::info("Set permissions for ClamAV directory: {$dir}");
                    }
                }
            }
            
            // Ensure socket directory permissions
            if (is_dir('/var/run/clamav')) {
                exec("chmod 750 /var/run/clamav 2>/dev/null");
            }
            
        } catch (\Exception $e) {
            Log::warning("Failed to setup ClamAV specific permissions: " . $e->getMessage());
        }
    }

    /**
     * Get the path to a profile file in the package.
     */
    protected function getPackageProfilePath(string $profileName): string
    {
        // Get the package root directory
        $packageRoot = dirname(__DIR__, 2);
        return "{$packageRoot}/docker/apparmor/{$profileName}";
    }

    /**
     * Parse aa-status output to extract profile information.
     */
    protected function parseStatusOutput(string $output): array
    {
        $profiles = [];
        $lines = explode("\n", $output);
        
        $currentSection = null;
        foreach ($lines as $line) {
            $line = trim($line);
            
            if (str_contains($line, 'profiles are loaded')) {
                $currentSection = 'loaded';
            } elseif (str_contains($line, 'profiles are in enforce mode')) {
                $currentSection = 'enforce';
            } elseif (str_contains($line, 'profiles are in complain mode')) {
                $currentSection = 'complain';
            } elseif ($currentSection && str_starts_with($line, '   ')) {
                $profileName = trim($line);
                if ($profileName) {
                    $profiles[$currentSection][] = $profileName;
                }
            }
        }

        return $profiles;
    }
}