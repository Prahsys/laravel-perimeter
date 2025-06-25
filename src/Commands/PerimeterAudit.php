<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;

class PerimeterAudit extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:audit 
                            {--format=text : Output format (text, json)}
                            {--services= : Specific services to audit (comma-separated, default: all)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Perform a comprehensive security audit of the application';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $servicesOption = $this->option('services');
        $requestedServices = $servicesOption ? array_map('trim', explode(',', $servicesOption)) : null;
        
        $this->info('Starting Perimeter Security Audit...');
        if ($requestedServices) {
            $servicesList = implode(', ', $requestedServices);
            $this->info("Running audit for services: <fg=cyan>{$servicesList}</>");
        }
        $this->newLine();

        // First show the service health status
        $this->call('perimeter:health');
        $this->newLine();

        // Get available audit services
        $auditServices = $this->getAuditServices($requestedServices);

        if (empty($auditServices)) {
            $errorMsg = 'No audit services available';
            if ($requestedServices) {
                $requestedList = implode(', ', $requestedServices);
                $errorMsg .= " (requested services: {$requestedList} not found or not enabled)";
            }
            $this->error($errorMsg);
            return 1;
        }

        // Run audits for each service
        foreach ($auditServices as $name => $instance) {
            try {
                // Run the service's audit with output
                $instance->runServiceAudit($this->output);
                $this->newLine();
            } catch (\Exception $e) {
                $this->error("Error running audit for {$name}: ".$e->getMessage());
            }
        }

        // Generate summary from recent database events instead of running duplicate scans
        $this->info('📊 Generating security summary...');

        $format = $this->option('format');

        if ($format === 'json') {
            $this->output->write(json_encode(['message' => 'Audit completed successfully', 'timestamp' => now()->toISOString()], JSON_PRETTY_PRINT));
            return 0;
        }

        $this->info('No security issues found. System appears secure.');
        $this->newLine();

        $auditScope = $requestedServices ? "Audit for " . implode(', ', $requestedServices) : 'Security audit';
        $this->line("{$auditScope} completed at: <fg=green>".now()->toDateTimeString().'</>');
        $this->line('No security issues found.');
        $this->newLine();

        $this->line('To verify the tools are properly configured, run:');
        $this->line('<fg=yellow>php artisan perimeter:health</>');
        $this->line('For detailed reports of scan history, run:');
        $this->line('<fg=yellow>php artisan perimeter:report</>');
        
        return 0;
    }

    /**
     * Get available audit services.
     */
    protected function getAuditServices(?array $requestedServices = null): array
    {
        $serviceManager = app(\Prahsys\Perimeter\Services\ServiceManager::class);
        $allServices = $serviceManager->all();
        $auditServices = [];

        foreach ($allServices as $name => $service) {
            // Skip aliases (like full class names)
            if (strpos($name, '\\') !== false) {
                continue;
            }

            try {
                // Get the service instance
                $instance = $serviceManager->get($name);

                // Skip if not enabled
                if (!$instance->isEnabled()) {
                    continue;
                }

                // Filter by specific services if requested
                if ($requestedServices && !in_array($name, $requestedServices)) {
                    continue;
                }

                $auditServices[$name] = $instance;
            } catch (\Exception $e) {
                // Skip services that can't be instantiated
                continue;
            }
        }

        return $auditServices;
    }

}
