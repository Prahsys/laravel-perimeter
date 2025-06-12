<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\Services\FalcoService;

class PerimeterMonitor extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:monitor 
                            {--realtime : Run in real-time monitoring mode}
                            {--duration=3600 : Duration in seconds (for real-time mode)}';

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
        $realtime = $this->option('realtime');
        $duration = (int) $this->option('duration');
        
        if ($realtime) {
            return $this->runRealtimeMonitoring($duration);
        }
        
        return $this->runPointInTimeMonitoring();
    }

    /**
     * Run real-time monitoring.
     *
     * @param int $duration
     * @return int
     */
    protected function runRealtimeMonitoring(int $duration): int
    {
        $this->info('Starting real-time security monitoring...');
        $this->info("Press Ctrl+C to stop monitoring (will run for {$duration} seconds otherwise)");
        $this->newLine();
        
        $startTime = now();
        $endTime = $startTime->addSeconds($duration);
        
        // Start monitoring
        Perimeter::monitor($duration);
        
        // In real implementation, this would be event-driven
        // For demo purposes, we periodically check for events
        $falcoService = app(FalcoService::class);
        
        $checkInterval = 5; // seconds
        $lastCheck = time();
        $lastEventCount = 0;
        
        while (now()->lessThan($endTime)) {
            // Check if we've been running for at least $checkInterval seconds
            if (time() - $lastCheck >= $checkInterval) {
                $events = $falcoService->getRecentEvents();
                $newEvents = count($events) - $lastEventCount;
                
                if ($newEvents > 0) {
                    $this->output->write("<fg=yellow>\r" . now()->format('Y-m-d H:i:s') . " - {$newEvents} new security event(s) detected</>");
                    $lastEventCount = count($events);
                    
                    // Display the most recent event
                    if (!empty($events)) {
                        $latestEvent = $events[0];
                        $this->newLine();
                        $this->line("<fg=red>{$latestEvent['priority']}</> - {$latestEvent['description']}");
                        $this->newLine();
                    }
                } else {
                    $this->output->write("\r" . now()->format('Y-m-d H:i:s') . " - Monitoring active, no new events");
                }
                
                $lastCheck = time();
            }
            
            // Sleep for a bit to avoid hammering the CPU
            usleep(500000); // 0.5 seconds
        }
        
        $this->newLine(2);
        $this->info('Monitoring complete.');
        
        return 0;
    }

    /**
     * Run point-in-time monitoring.
     *
     * @return int
     */
    protected function runPointInTimeMonitoring(): int
    {
        $this->info('Running point-in-time security check...');
        $this->newLine();
        
        $falcoService = app(FalcoService::class);
        $events = $falcoService->getRecentEvents(25);
        
        if (empty($events)) {
            $this->info('No security events detected.');
            return 0;
        }
        
        $this->line('<fg=white;bg=blue>SECURITY EVENTS</>');
        $this->newLine();
        
        $headers = ['Priority', 'Rule', 'Description', 'Process', 'User', 'Timestamp'];
        $rows = [];
        
        foreach ($events as $event) {
            $priorityColor = $this->getPriorityColor($event['priority']);
            
            $rows[] = [
                "<fg={$priorityColor}>{$event['priority']}</>",
                $event['rule'],
                $event['description'],
                $event['process'],
                $event['user'],
                $event['timestamp'],
            ];
        }
        
        $this->table($headers, $rows);
        
        return 0;
    }

    /**
     * Get color for event priority.
     *
     * @param string $priority
     * @return string
     */
    protected function getPriorityColor(string $priority): string
    {
        switch ($priority) {
            case 'emergency':
                return 'red';
            case 'critical':
                return 'bright-red';
            case 'high':
                return 'yellow';
            case 'warning':
                return 'bright-yellow';
            default:
                return 'white';
        }
    }
}