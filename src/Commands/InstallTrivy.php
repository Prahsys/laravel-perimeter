<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Process\Process;

class InstallTrivy extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install-trivy 
                            {--force : Force installation even if already installed}
                            {--no-start : Don\'t start the service after installation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure Trivy for vulnerability scanning';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Checking for Trivy installation...');

        // Use the TrivyService for installation
        $trivyService = new \Prahsys\Perimeter\Services\TrivyService;

        $isInstalled = $trivyService->isInstalled();

        $this->info('Environment details:');
        $this->info('- Trivy installed: '.($isInstalled ? 'Yes' : 'No'));

        // If already installed and not forced, exit early
        if ($isInstalled && ! $this->option('force')) {
            $this->info('Trivy is already installed. Use --force to reinstall.');

            return 0;
        }

        // Check for root/sudo
        if (posix_geteuid() !== 0) {
            $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
            $this->warn('Please run this command as: sudo php artisan perimeter:install-trivy');

            return 1;
        }

        // Prepare minimal installation options
        $options = [
            'force' => $this->option('force'),
            'start' => ! $this->option('no-start'),
        ];

        $this->info('Installing Trivy with default configuration...');

        // Execute raw installer script if available in Docker environment
        if (\Prahsys\Perimeter\Facades\Perimeter::isRunningInContainer() && file_exists('/package/docker/raw-install/raw-install-trivy.sh')) {
            $this->info('Using raw installer script in Docker environment');
            $process = Process::fromShellCommandline('bash /package/docker/raw-install/raw-install-trivy.sh');
            $process->setTimeout(null);
            $process->run(function ($type, $buffer) {
                $this->line(trim($buffer));
            });

            if ($process->isSuccessful()) {
                $this->info('Trivy installed successfully using raw installer script.');

                return 0;
            }
        }

        // Otherwise use the service
        $result = $trivyService->install($options);

        if ($result) {
            $this->info('Trivy has been successfully installed!');

            // Display version
            $process = new Process(['trivy', '--version']);
            $process->run();
            if ($process->isSuccessful()) {
                $this->info('Version: '.trim($process->getOutput()));
            }

            return 0;
        } else {
            $this->error('Failed to install Trivy. Check the logs for more details.');

            return 1;
        }
    }

    /**
     * Detect the current operating system.
     */
    protected function detectOS(): string
    {
        $uname = strtolower(php_uname('s'));
        if (str_contains($uname, 'darwin')) {
            return 'macos';
        } elseif (str_contains($uname, 'linux')) {
            $osRelease = @file_get_contents('/etc/os-release');
            if ($osRelease && (str_contains($osRelease, 'ubuntu') || str_contains($osRelease, 'debian'))) {
                return 'debian';
            }
        }

        return 'unknown';
    }

    /**
     * Run a shell command and stream output to the console.
     */
    protected function cmd(string $command): int
    {
        $this->line("  > $command");

        $process = Process::fromShellCommandline($command);
        $process->setTimeout(null); // Allow long-running commands

        $process->run(function ($type, $buffer) {
            $output = trim($buffer);

            if ($type === Process::ERR) {
                $this->error($output);
            } else {
                $this->line($output);
            }
        });

        return $process->getExitCode();
    }
}
