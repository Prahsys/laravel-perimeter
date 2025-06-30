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

            // Load the profile
            $process = new Process(['apparmor_parser', '-r', $targetPath]);
            $process->run();

            if ($process->isSuccessful()) {
                Log::info("AppArmor profile installed successfully: {$profileName}");
                return true;
            } else {
                Log::error("Failed to load AppArmor profile: " . $process->getErrorOutput());
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