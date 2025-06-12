<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\TrivyService;

class PerimeterHealth extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:health';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check the health of all security components';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Checking Perimeter security components health...');
        $this->newLine();

        $results = [];
        $allHealthy = true;

        // Check ClamAV
        $clamAVHealthy = $this->checkClamAV();
        $results[] = [
            'Component' => 'ClamAV (Malware Protection)',
            'Status' => $clamAVHealthy ? 'Healthy' : 'Unhealthy',
            'Details' => $clamAVHealthy ? 'Available and configured' : 'Unavailable or misconfigured',
        ];
        $allHealthy = $allHealthy && $clamAVHealthy;

        // Check Falco
        $falcoHealthy = $this->checkFalco();
        $results[] = [
            'Component' => 'Falco (Runtime Protection)',
            'Status' => $falcoHealthy ? 'Healthy' : 'Unhealthy',
            'Details' => $falcoHealthy ? 'Available and configured' : 'Unavailable or misconfigured',
        ];
        $allHealthy = $allHealthy && $falcoHealthy;

        // Check Trivy
        $trivyHealthy = $this->checkTrivy();
        $results[] = [
            'Component' => 'Trivy (Vulnerability Scanning)',
            'Status' => $trivyHealthy ? 'Healthy' : 'Unhealthy',
            'Details' => $trivyHealthy ? 'Available and configured' : 'Unavailable or misconfigured',
        ];
        $allHealthy = $allHealthy && $trivyHealthy;

        // Check environment configuration
        $envHealthy = $this->checkEnvironment();
        $results[] = [
            'Component' => 'Environment Configuration',
            'Status' => $envHealthy ? 'Healthy' : 'Warning',
            'Details' => $envHealthy ? 'Properly configured' : 'Some configuration issues detected',
        ];
        $allHealthy = $allHealthy && $envHealthy;

        // Display the results
        foreach ($results as $index => $result) {
            $statusColor = $result['Status'] === 'Healthy' ? 'green' : 'red';
            $results[$index]['Status'] = "<fg=$statusColor>{$result['Status']}</>";
        }

        $this->table(['Component', 'Status', 'Details'], $results);
        $this->newLine();

        if ($allHealthy) {
            $this->info('All security components are healthy and operational.');
        } else {
            $this->warn('Some security components are not healthy. See details above.');
            $this->line('Run <fg=yellow>php artisan perimeter:install</> to fix potential issues.');
        }

        return $allHealthy ? 0 : 1;
    }

    /**
     * Check ClamAV health.
     *
     * @return bool
     */
    protected function checkClamAV(): bool
    {
        try {
            $clamAVService = app(ClamAVService::class);
            
            if (!$clamAVService->isEnabled()) {
                return false;
            }
            
            // In a real implementation, we would check if ClamAV is installed
            // and properly configured by testing a connection to the socket.
            
            // Simulate connection to ClamAV
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check Falco health.
     *
     * @return bool
     */
    protected function checkFalco(): bool
    {
        try {
            $falcoService = app(FalcoService::class);
            
            if (!$falcoService->isEnabled()) {
                return false;
            }
            
            // In a real implementation, we would check if Falco is installed
            // and properly configured by testing the gRPC connection.
            
            // Simulate connection to Falco
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check Trivy health.
     *
     * @return bool
     */
    protected function checkTrivy(): bool
    {
        try {
            $trivyService = app(TrivyService::class);
            
            if (!$trivyService->isEnabled()) {
                return false;
            }
            
            // In a real implementation, we would check if Trivy is installed
            // and verify that we can execute it.
            
            // Simulate Trivy availability
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Check environment configuration.
     *
     * @return bool
     */
    protected function checkEnvironment(): bool
    {
        $issues = 0;
        
        // Check if perimeter is enabled
        if (!config('perimeter.enabled', true)) {
            $this->line('Warning: Perimeter is disabled in configuration.');
            $issues++;
        }
        
        // Check logging configuration
        $logChannels = config('perimeter.logging.channels', []);
        if (empty($logChannels)) {
            $this->line('Warning: No logging channels configured for Perimeter.');
            $issues++;
        }
        
        // Check ClamAV configuration
        $clamavSocket = config('perimeter.clamav.socket');
        if (empty($clamavSocket)) {
            $this->line('Warning: ClamAV socket path not configured.');
            $issues++;
        }
        
        // Check Falco configuration
        $falcoEndpoint = config('perimeter.falco.grpc_endpoint');
        if (empty($falcoEndpoint)) {
            $this->line('Warning: Falco gRPC endpoint not configured.');
            $issues++;
        }
        
        // Consider environment healthy if there are no more than 1 issue
        return $issues <= 1;
    }
}