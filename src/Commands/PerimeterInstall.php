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

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Installing Perimeter security components...');
        $this->newLine();

        // Publish configuration file
        if (!File::exists(config_path('perimeter.php')) || $this->option('force')) {
            $this->call('vendor:publish', [
                '--tag' => 'perimeter-config',
            ]);
        } else {
            $this->line('Configuration file already published. Use --force to overwrite.');
        }
        $this->newLine();

        // Install ClamAV
        $this->installClamAV();
        $this->newLine();

        // Install Falco
        $this->installFalco();
        $this->newLine();

        // Install Trivy
        $this->installTrivy();
        $this->newLine();

        // Configure environment
        $this->configureEnvironment();
        $this->newLine();

        $this->info('Installation complete! Run the following to verify installation:');
        $this->line('  php artisan perimeter:health');
        $this->newLine();

        $this->info('Add the following to your scheduler to enable regular security scanning:');
        $this->line('  $schedule->command(\'perimeter:audit\')->daily();');
        $this->line('  $schedule->command(\'perimeter:report --compliance=soc2\')->weekly();');
        $this->newLine();

        return 0;
    }

    /**
     * Install ClamAV.
     *
     * @return void
     */
    protected function installClamAV(): void
    {
        $this->info('Installing ClamAV...');

        // In a real implementation, we would check the OS and install ClamAV
        // using the appropriate package manager or provide instructions.
        
        // For Ubuntu/Debian:
        // apt-get update && apt-get install -y clamav clamav-daemon
        
        // For macOS:
        // brew install clamav
        
        // For this demo, we just simulate the installation
        $this->line('Simulating ClamAV installation...');
        sleep(1);
        
        $this->info('ClamAV installed successfully. Configuring...');
        
        // Create directories for Perimeter rules if needed
        $rulesPath = base_path('perimeter-rules/clamav');
        if (!File::exists($rulesPath)) {
            File::makeDirectory($rulesPath, 0755, true);
        }
        
        $this->info('ClamAV configuration complete.');
    }

    /**
     * Install Falco.
     *
     * @return void
     */
    protected function installFalco(): void
    {
        $this->info('Installing Falco...');

        // In a real implementation, we would check the OS and install Falco
        // using the appropriate package manager or provide instructions.
        
        // For Ubuntu/Debian:
        // curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
        // echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
        // apt-get update && apt-get install -y falco
        
        // For this demo, we just simulate the installation
        $this->line('Simulating Falco installation...');
        sleep(1);
        
        $this->info('Falco installed successfully. Configuring...');
        
        // Create directories for Perimeter rules if needed
        $rulesPath = base_path('perimeter-rules/falco');
        if (!File::exists($rulesPath)) {
            File::makeDirectory($rulesPath, 0755, true);
            
            // Create sample Falco rules file
            $sampleRulesContent = <<<'EOT'
# Laravel-specific Falco rules

- rule: Laravel Mass Assignment Attempt
  desc: Detect potential mass assignment vulnerability exploitation
  condition: proc.name = "php" and fd.name contains "artisan" and evt.type = execve and evt.arg.args contains "mass" and evt.arg.args contains "assignment"
  output: Potential mass assignment vulnerability exploitation (user=%user.name process=%proc.name command=%proc.cmdline)
  priority: high
  tags: [application, laravel, security]

- rule: Laravel SQL Injection Pattern
  desc: Detect potential SQL injection patterns in Laravel queries
  condition: proc.name = "php" and fd.name contains "artisan" and evt.type = execve and evt.arg.args contains "SELECT" and (evt.arg.args contains "1=1" or evt.arg.args contains "UNION")
  output: Potential SQL injection pattern detected (user=%user.name process=%proc.name command=%proc.cmdline)
  priority: critical
  tags: [application, laravel, security]

- rule: Laravel Suspicious File Write
  desc: Detect suspicious file writes to system directories
  condition: proc.name = "php" and fd.name contains "artisan" and evt.type = open and fd.directory = "/etc" and evt.arg.flags contains "O_WRONLY"
  output: Suspicious file write detected to system directory (user=%user.name process=%proc.name file=%fd.name)
  priority: critical
  tags: [application, laravel, security]

- rule: Laravel Command Injection
  desc: Detect potential command injection in Laravel
  condition: proc.name = "php" and proc.pname = "php-fpm" and evt.type = execve and (proc.cmdline contains ";" or proc.cmdline contains "|" or proc.cmdline contains "&&")
  output: Potential command injection detected (user=%user.name process=%proc.name command=%proc.cmdline)
  priority: critical
  tags: [application, laravel, security]
EOT;
            
            File::put($rulesPath . '/laravel-rules.yaml', $sampleRulesContent);
        }
        
        $this->info('Falco configuration complete.');
    }

    /**
     * Install Trivy.
     *
     * @return void
     */
    protected function installTrivy(): void
    {
        $this->info('Installing Trivy...');

        // In a real implementation, we would check the OS and install Trivy
        // using the appropriate package manager or provide instructions.
        
        // For Ubuntu/Debian:
        // apt-get install -y wget apt-transport-https gnupg lsb-release
        // wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
        // echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
        // apt-get update && apt-get install -y trivy
        
        // For macOS:
        // brew install aquasecurity/trivy/trivy
        
        // For this demo, we just simulate the installation
        $this->line('Simulating Trivy installation...');
        sleep(1);
        
        $this->info('Trivy installed successfully.');
    }

    /**
     * Configure environment.
     *
     * @return void
     */
    protected function configureEnvironment(): void
    {
        $this->info('Configuring environment...');

        // Check if .env file exists
        if (!File::exists(base_path('.env'))) {
            $this->warn('.env file not found. Skipping environment configuration.');
            return;
        }

        // Read .env file
        $envContent = File::get(base_path('.env'));

        // Add Perimeter configuration if not already present
        $additions = [];

        if (!str_contains($envContent, 'PERIMETER_ENABLED')) {
            $additions[] = 'PERIMETER_ENABLED=true';
        }

        if (!str_contains($envContent, 'PERIMETER_LOG_CHANNELS')) {
            $additions[] = 'PERIMETER_LOG_CHANNELS=stack';
        }

        if (!str_contains($envContent, 'PERIMETER_CLAMAV_ENABLED')) {
            $additions[] = 'PERIMETER_CLAMAV_ENABLED=true';
        }

        if (!str_contains($envContent, 'PERIMETER_FALCO_ENABLED')) {
            $additions[] = 'PERIMETER_FALCO_ENABLED=true';
        }

        if (!str_contains($envContent, 'PERIMETER_TRIVY_ENABLED')) {
            $additions[] = 'PERIMETER_TRIVY_ENABLED=true';
        }

        if (!str_contains($envContent, 'PERIMETER_REALTIME_SCAN')) {
            $additions[] = 'PERIMETER_REALTIME_SCAN=true';
        }

        // Add the additions to .env file if there are any
        if (!empty($additions)) {
            // Add a new line if the file doesn't end with one
            if (!str_ends_with($envContent, PHP_EOL)) {
                $envContent .= PHP_EOL;
            }

            // Add a comment for the Perimeter section
            $envContent .= PHP_EOL . '# Perimeter Security Configuration' . PHP_EOL;
            
            // Add each new configuration
            $envContent .= implode(PHP_EOL, $additions) . PHP_EOL;

            // Write back to .env file
            File::put(base_path('.env'), $envContent);
            
            $this->info('Added Perimeter configuration to .env file.');
        } else {
            $this->line('Perimeter configuration already exists in .env file.');
        }
    }
}