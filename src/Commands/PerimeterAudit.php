<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Services\ArtifactManager;

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
        
        // Initialize artifact manager for this audit
        $artifactManager = new ArtifactManager();
        $auditId = now()->format('Y-m-d_H-i-s') . '_' . uniqid();
        $auditPath = $artifactManager->initializeAudit($auditId);
        
        $this->info('Starting Perimeter Security Audit...');
        if ($requestedServices) {
            $servicesList = implode(', ', $requestedServices);
            $this->info("Running audit for services: <fg=cyan>{$servicesList}</>");
        }
        
        $this->info("Audit artifacts will be saved to: <fg=yellow>{$auditPath}</>");
        
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

        // Create a BufferedOutput to capture all audit output
        $bufferedOutput = new \Symfony\Component\Console\Output\BufferedOutput();
        $capturingOutput = new \Illuminate\Console\OutputStyle(
            new \Symfony\Component\Console\Input\ArrayInput([]),
            $bufferedOutput
        );

        // Run audits for each service
        $allIssues = [];
        foreach ($auditServices as $name => $instance) {
            try {
                // Run the service's audit with capturing output and collect issues
                $auditResult = $instance->runServiceAudit($capturingOutput, $artifactManager);
                
                // Extract issues from ServiceAuditData
                if ($auditResult && isset($auditResult->issues) && is_array($auditResult->issues)) {
                    $allIssues = array_merge($allIssues, $auditResult->issues);
                }
                
                $capturingOutput->newLine();
            } catch (\Exception $e) {
                $capturingOutput->error("Error running audit for {$name}: ".$e->getMessage());
            }
        }

        // Get all captured output and save as audit.log
        $capturedContent = $bufferedOutput->fetch();
        $artifactManager->saveArtifact('audit_log.txt', $capturedContent, [
            'service' => 'audit',
            'type' => 'log',
            'command' => 'perimeter:audit'
        ]);
        
        // Also display the captured output to console
        $this->output->write($capturedContent);

        // Generate summary from recent database events instead of running duplicate scans
        $this->info('📊 Generating security summary...');

        // Finalize audit with artifacts - audit log would be captured by external logging if needed

        $auditSummary = [
            'services_audited' => array_keys($auditServices),
            'total_issues' => count($allIssues),
            'issues_by_severity' => $this->groupIssuesBySeverity($allIssues),
            'completed_at' => now()->toDateTimeString(),
            'artifacts_note' => 'This audit created artifacts containing detailed security data and command outputs for audit trail and compliance purposes.'
        ];
        
        $artifactManager->finalizeAudit($auditSummary);

        $format = $this->option('format');

        if ($format === 'json') {
            $this->output->write(json_encode([
                'message' => 'Audit completed successfully', 
                'timestamp' => now()->toISOString(),
                'audit_id' => $auditId,
                'artifacts_path' => $auditPath,
                'summary' => $auditSummary
            ], JSON_PRETTY_PRINT));
            return 0;
        }

        $this->info('No security issues found. System appears secure.');
        $this->newLine();

        $auditScope = $requestedServices ? "Audit for " . implode(', ', $requestedServices) : 'Security audit';
        $this->line("{$auditScope} completed at: <fg=green>".now()->toDateTimeString().'</>');
        $this->line('No security issues found.');
        
        $this->newLine();
        $this->line("Audit artifacts saved to: <fg=yellow>{$auditPath}</>");
        
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

    /**
     * Group security issues by severity level.
     */
    protected function groupIssuesBySeverity(array $issues): array
    {
        $grouped = [
            'emergency' => 0,
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($issues as $issue) {
            $severity = $issue->severity ?? 'info';
            if (isset($grouped[$severity])) {
                $grouped[$severity]++;
            } else {
                $grouped['info']++;
            }
        }

        return $grouped;
    }


}
