<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;

class PerimeterMonitor extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:monitor 
                            {--duration=0 : Duration in seconds (0 for indefinite)}
                            {--services= : Specific services to monitor (comma-separated, default: all)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Monitor the system for security events';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $duration = (int) $this->option('duration');
        $servicesOption = $this->option('services');
        $requestedServices = $servicesOption ? array_map('trim', explode(',', $servicesOption)) : null;

        // Get all monitoring services or specific ones if requested
        $monitoringServices = $this->getMonitoringServices($requestedServices);

        if (empty($monitoringServices)) {
            $errorMsg = 'No monitoring services available';
            if ($requestedServices) {
                $requestedList = implode(', ', $requestedServices);
                $errorMsg .= " (requested services: {$requestedList} not found or not enabled)";
            }
            $this->error($errorMsg);

            return 1;
        }

        return $this->runMonitoring($monitoringServices, $duration, $requestedServices);
    }

    /**
     * Get available monitoring services.
     */
    protected function getMonitoringServices(?array $requestedServices = null): array
    {
        $serviceManager = app(\Prahsys\Perimeter\Services\ServiceManager::class);
        $allServices = $serviceManager->all();
        $monitoringServices = [];

        foreach ($allServices as $name => $service) {
            // Skip aliases (like full class names)
            if (strpos($name, '\\') !== false) {
                continue;
            }

            // Get the service instance
            $instance = $serviceManager->get($name);

            // Skip if not enabled
            if (! $instance->isEnabled() || ! $instance->isInstalled() || ! $instance->isConfigured()) {
                continue;
            }

            // Check if it's a monitoring service
            if ($instance instanceof SecurityMonitoringServiceInterface) {
                // Filter by specific services if requested
                if ($requestedServices && ! in_array($name, $requestedServices)) {
                    continue;
                }

                $monitoringServices[$name] = $instance;
            }
        }

        return $monitoringServices;
    }

    /**
     * Run continuous monitoring.
     */
    protected function runMonitoring(array $monitoringServices, int $duration, ?array $requestedServices = null): int
    {
        $this->info('Starting security monitoring...');
        if ($requestedServices) {
            $servicesList = implode(', ', $requestedServices);
            $this->info("Monitoring services: <fg=cyan>{$servicesList}</>");
        }
        if ($duration > 0) {
            $this->info("Will run for {$duration} seconds (press Ctrl+C to stop earlier)");
        } else {
            $this->info('Running indefinitely (press Ctrl+C to stop)');
        }
        $this->newLine();

        $startTime = now();
        $endTime = $duration > 0 ? $startTime->addSeconds($duration) : null;

        // Start monitoring for each service
        foreach ($monitoringServices as $name => $service) {
            $actualDuration = $duration > 0 ? $duration : null; // Pass null for indefinite
            $result = $service->startMonitoring($actualDuration);
            $this->line("Service <fg=blue>{$name}</> ".($result ? '<fg=green>started</>' : '<fg=red>failed to start</>'));
        }
        $this->newLine();

        // Monitoring loop
        $checkInterval = 5; // seconds
        $lastCheck = time();
        $eventCounts = [];

        // Initialize event counts for each service
        foreach ($monitoringServices as $name => $service) {
            $eventCounts[$name] = 0;
        }

        // Main monitoring loop - run indefinitely or until end time
        while ($endTime === null || now()->lessThan($endTime)) {
            // Check for termination signal
            if ($this->shouldTerminate()) {
                $this->newLine();
                $this->info('Termination signal received. Shutting down gracefully...');
                break;
            }

            // Check if we've been running for at least $checkInterval seconds
            if (time() - $lastCheck >= $checkInterval) {
                $hasNewEvents = false;
                $totalNewEvents = 0;

                // Check each monitoring service for new events
                foreach ($monitoringServices as $name => $service) {
                    $events = $service->getMonitoringEvents();
                    $currentCount = count($events);
                    $newEvents = $currentCount - $eventCounts[$name];

                    if ($newEvents > 0) {
                        $hasNewEvents = true;
                        $totalNewEvents += $newEvents;
                        $eventCounts[$name] = $currentCount;

                        // Display events that are new since last check
                        $newEventsList = array_slice($events, 0, $newEvents);
                        foreach ($newEventsList as $event) {
                            $severityColor = $this->getSeverityColor($event->severity);
                            $this->line(
                                now()->format('Y-m-d H:i:s').
                                " <fg=blue>[{$name}]</> ".
                                "<fg={$severityColor}>{$event->severity}</> - ".
                                "{$event->description}".
                                ($event->location ? " at {$event->location}" : '')
                            );
                        }
                    }
                }

                if (! $hasNewEvents) {
                    $this->output->write("\r".now()->format('Y-m-d H:i:s').' - Monitoring active, no new events');
                }

                $lastCheck = time();
            }

            // Sleep for a bit to avoid hammering the CPU
            usleep(500000); // 0.5 seconds
        }

        // Stop monitoring for each service
        $this->newLine(2);
        foreach ($monitoringServices as $name => $service) {
            $result = $service->stopMonitoring();
            $this->line("Service <fg=blue>{$name}</> ".($result ? '<fg=green>stopped</>' : '<fg=red>failed to stop</>'));
        }

        $this->newLine();
        $this->info('Monitoring complete.');

        return 0;
    }

    /**
     * Get color for event severity.
     */
    protected function getSeverityColor(string $severity): string
    {
        return match (strtolower($severity)) {
            'emergency', 'critical', 'high' => 'red',
            'warning', 'medium' => 'yellow',
            'info', 'low' => 'green',
            default => 'white',
        };
    }

    /**
     * Check if monitoring should terminate
     */
    protected function shouldTerminate(): bool
    {
        return Cache::has('perimeter:terminate');
    }
}
