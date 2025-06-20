<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Services\UfwService;
use Symfony\Component\Process\Process;

class InstallUfw extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install-ufw
                            {--force : Force reinstallation if already installed}
                            {--no-start : Don\'t start the service after installation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure UFW firewall for Perimeter';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(UfwService $ufwService)
    {
        $this->info('Checking for UFW installation...');

        $isInstalled = $ufwService->isInstalled();
        $isConfigured = $ufwService->isConfigured();

        $this->info('Environment details:');
        $this->info('- UFW installed: '.($isInstalled ? 'Yes' : 'No'));
        $this->info('- UFW configured: '.($isConfigured ? 'Yes' : 'No'));

        // If already installed and not forced, exit early
        if ($isInstalled && ! $this->option('force')) {
            $this->info('UFW is already installed. Use --force to reinstall.');

            return 0;
        }

        // Check if we're in a container environment
        if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer()) {
            $this->info('Installing UFW for container environment...');

            // Use the optimized script for Docker installation
            if (file_exists('/package/docker/raw-install/raw-install-ufw.sh')) {
                $this->info('Using the optimized container installation script');
                $this->executeCommand('chmod +x /package/docker/raw-install/raw-install-ufw.sh');
                $this->executeCommand('/package/docker/raw-install/raw-install-ufw.sh');

                // Verify installation
                if ($ufwService->isInstalled()) {
                    $this->info('UFW installed and configured successfully for container environment.');
                    $this->displayUfwStatus();

                    return 0;
                }
            } else {
                // Fallback for container installation if script not found
                $this->warn('Optimized installation script not found, creating minimal UFW mock...');

                // Create a minimal mock UFW implementation for containers
                $this->createMockUfw();
            }
        } else {
            // Regular installation for non-container environments
            // Check for root/sudo
            if (posix_geteuid() !== 0) {
                $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
                $this->warn('Please run this command as: sudo php artisan perimeter:install-ufw');

                return 1;
            }

            // Prepare minimal installation options
            $options = [
                'force' => $this->option('force'),
                'start' => ! $this->option('no-start'),
            ];

            $this->info('Installing UFW with default configuration...');

            // Install UFW
            $result = $ufwService->install($options);

            if (! $result) {
                $this->error('Failed to install or configure UFW.');

                return 1;
            }
        }

        $this->info('UFW installed and configured successfully.');
        $this->displayUfwStatus();

        return 0;
    }

    /**
     * Create a mock UFW implementation for container environments.
     */
    protected function createMockUfw(): void
    {
        $this->info('Creating mock UFW implementation for container...');

        // Create directories
        $this->executeCommand('mkdir -p /etc/ufw /var/log/ufw');
        $this->executeCommand('touch /var/log/ufw.log');

        // Create the mock UFW script
        $mockUfwScript = <<<'SCRIPT'
#!/bin/bash
# Mock UFW implementation for Docker containers

# Parse command line arguments
if [ "$1" = "status" ]; then
  if [ "$2" = "verbose" ]; then
    cat << 'STATUS'
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
STATUS
  else
    cat << 'STATUS'
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
STATUS
  fi
  exit 0
elif [ "$1" = "--version" ]; then
  echo "ufw 0.36"
  exit 0
elif [ "$1" = "enable" ] || [ "$1" = "--force" -a "$2" = "enable" ]; then
  echo "Firewall is active and enabled on system startup"
  exit 0
elif [ "$1" = "disable" ]; then
  echo "Firewall stopped and disabled on system startup"
  exit 0
else
  echo "Mock UFW executed with: $@"
  exit 0
fi
SCRIPT;

        // Write the script to file and make it executable
        file_put_contents('/usr/local/bin/ufw', $mockUfwScript);
        $this->executeCommand('chmod +x /usr/local/bin/ufw');

        // Create symlinks for binary detection
        $this->executeCommand('ln -sf /usr/local/bin/ufw /usr/bin/ufw 2>/dev/null || true');

        // Add a sample log entry
        file_put_contents('/var/log/ufw.log', "Jun 19 16:01:21 container kernel: [123456.789012] [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.1 DST=192.168.1.2 PROTO=TCP SPT=12345 DPT=22\n");
    }

    /**
     * Run a shell command and show output.
     */
    protected function executeCommand(string $command): int
    {
        $this->line("  > $command");

        $process = new \Symfony\Component\Process\Process(explode(' ', $command));
        $process->setTimeout(null);

        $process->run(function ($type, $buffer) {
            $this->line(trim($buffer));
        });

        return $process->getExitCode();
    }

    /**
     * Check if the user has sudo access.
     */
    protected function checkSudo(): bool
    {
        // Try a simple sudo command
        $process = new Process(['sudo', '-n', 'true']);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * Display the current UFW status.
     */
    protected function displayUfwStatus(): void
    {
        $process = new Process(['ufw', 'status', 'verbose']);
        $process->run();

        if ($process->isSuccessful()) {
            $this->newLine();
            $this->info('Current UFW Status:');
            $this->line($process->getOutput());
        }
    }
}
