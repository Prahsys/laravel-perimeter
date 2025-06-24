<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class PerimeterInstall extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:install {--force : Force installation even if components are already installed}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure all security components';

    protected string $osType = 'unknown';

    protected bool $isRoot = false;

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->detectOS();
        $this->checkSudo();

        if (! $this->isRoot) {
            $this->error('ERROR: This command must be run with sudo or as root to install system packages.');
            $this->error('Please run this command as: sudo php artisan perimeter:install');
            $this->newLine();

            return 1;
        }

        $this->info('Installing Perimeter security components...');
        $this->newLine();

        // Check if configuration is published
        if (! File::exists(config_path('perimeter.php'))) {
            $this->warn('Configuration file not found. Please publish it first with:');
            $this->line('  php artisan vendor:publish --tag=perimeter-config');
            $this->newLine();

            return 1;
        }

        // Dynamically install each service using their dedicated installer
        // Each service must define an 'installer' key in its config pointing to the installer class
        $services = config('perimeter.services', []);

        // Track which services have been installed
        $installedServices = [];

        foreach ($services as $serviceClass => $config) {
            // Skip disabled services
            if (isset($config['enabled']) && $config['enabled'] === false) {
                $this->line('Skipping disabled service: '.$this->getServiceName($serviceClass));

                continue;
            }

            // Check if the service has an installer defined
            if (! isset($config['installer'])) {
                $this->warn('No installer defined for service: '.$this->getServiceName($serviceClass));

                continue;
            }

            $installerClass = $config['installer'];
            $this->info('Installing '.$this->getServiceName($serviceClass).'...');

            // Find the command name for this installer class
            $kernel = $this->getLaravel()->make('Illuminate\Contracts\Console\Kernel');
            $commandName = null;

            foreach ($kernel->all() as $name => $command) {
                if (get_class($command) === $installerClass) {
                    $commandName = $name;
                    break;
                }
            }

            if (! $commandName) {
                $this->warn("Could not resolve command name for installer: $installerClass");

                continue;
            }

            // Prepare command options
            $options = ['--force' => $this->option('force')];

            // Add OS type and root status options if supported
            $command = $kernel->all()[$commandName];
            $definition = $command->getDefinition();

            if ($definition->hasOption('os-type')) {
                $options['--os-type'] = $this->osType;
            }

            if ($definition->hasOption('is-root')) {
                $options['--is-root'] = $this->isRoot;
            }

            // Add configure option for Fail2ban if supported
            if (strpos($installerClass, 'InstallFail2ban') !== false && $definition->hasOption('configure')) {
                $options['--configure'] = true;
            }

            // Call the install command with appropriate options
            $this->call($commandName, $options);

            $installedServices[] = $this->getServiceName($serviceClass);
            $this->newLine();
        }

        if (empty($installedServices)) {
            $this->warn('No services were installed. Make sure your configuration includes valid services.');
        } else {
            $this->info('Installed services: '.implode(', ', $installedServices));
        }
        $this->newLine();

        // Configure environment
        $this->configureEnvironment();
        $this->newLine();

        $this->info('Installation complete! Run the following to verify installation:');
        $this->line('  php artisan perimeter:health');
        $this->newLine();

        $this->info('Add the following to your scheduler to enable regular security scanning:');
        $this->line('  $schedule->command(\'perimeter:audit\')->daily();');
        $this->newLine();

        $this->comment('Configuration Management:');
        $this->line('  To publish config:     php artisan vendor:publish --tag=perimeter-config');
        $this->line('  To publish migrations: php artisan vendor:publish --tag=perimeter-migrations');
        $this->newLine();

        return 0;
    }

    /**
     * Detect the current operating system.
     */
    protected function detectOS(): void
    {
        $uname = strtolower(php_uname('s'));
        if (str_contains($uname, 'darwin')) {
            $this->osType = 'macos';
        } elseif (str_contains($uname, 'linux')) {
            $osRelease = @file_get_contents('/etc/os-release');
            if ($osRelease && str_contains($osRelease, 'ubuntu') || str_contains($osRelease, 'debian')) {
                $this->osType = 'debian';
            }
        }

        $this->info("Detected OS: {$this->osType}");
    }

    /**
     * Check for root privileges.
     */
    protected function checkSudo(): void
    {
        // Check if running as root (uid 0)
        $this->isRoot = function_exists('posix_geteuid') ? posix_geteuid() === 0 : false;

        // Alternative check for Windows or environments without posix
        if (! $this->isRoot && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            // On Windows, check if running as Administrator
            $this->isRoot = isset($_SERVER['SESSIONNAME']) && preg_match('/SYSTEM|Administrator/i', $_SERVER['SESSIONNAME']);
        }

        // No special handling for CI environments - behavior should be consistent
    }

    // Removed isInCIEnvironment method - we don't need special handling for CI

    /**
     * Extract the short name from a fully qualified class name
     */
    protected function getServiceName(string $className): string
    {
        $parts = explode('\\', $className);

        return end($parts);
    }

    /**
     * Configure environment.
     */
    protected function configureEnvironment(): void
    {
        $this->info('Configuring environment...');

        // Check if .env file exists
        if (! File::exists(base_path('.env'))) {
            $this->warn('.env file not found. Skipping environment configuration.');

            return;
        }

        // Read .env file
        $envContent = File::get(base_path('.env'));

        // Add Perimeter configuration if not already present
        $additions = [];

        // Core configuration
        if (! str_contains($envContent, 'PERIMETER_ENABLED')) {
            $additions[] = 'PERIMETER_ENABLED=true';
        }

        if (! str_contains($envContent, 'PERIMETER_LOG_CHANNELS')) {
            $additions[] = 'PERIMETER_LOG_CHANNELS=stack';
        }

        if (! str_contains($envContent, 'PERIMETER_REALTIME_SCAN')) {
            $additions[] = 'PERIMETER_REALTIME_SCAN=true';
        }

        // Dynamic service configuration based on registered services
        $services = config('perimeter.services', []);
        foreach ($services as $serviceClass => $config) {
            $serviceName = $this->getServiceName($serviceClass);
            $serviceEnvKey = 'PERIMETER_'.strtoupper(str_replace('Service', '', $serviceName)).'_ENABLED';

            if (! str_contains($envContent, $serviceEnvKey)) {
                $additions[] = $serviceEnvKey.'=true';
            }
        }

        // Add the additions to .env file if there are any
        if (! empty($additions)) {
            // Add a new line if the file doesn't end with one
            if (! str_ends_with($envContent, PHP_EOL)) {
                $envContent .= PHP_EOL;
            }

            // Add a comment for the Perimeter section
            $envContent .= PHP_EOL.'# Perimeter Security Configuration'.PHP_EOL;

            // Add each new configuration
            $envContent .= implode(PHP_EOL, $additions).PHP_EOL;

            // Write back to .env file
            File::put(base_path('.env'), $envContent);

            $this->info('Added Perimeter configuration to .env file.');
        } else {
            $this->line('Perimeter configuration already exists in .env file.');
        }
    }
}
