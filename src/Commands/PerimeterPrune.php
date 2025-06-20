<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class PerimeterPrune extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:prune
                            {--days= : Override the retention period (in days)}
                            {--force : Force prune without confirmation}
                            {--dry-run : Show what would be pruned without actually pruning}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune old security events and scans based on retention policy';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        // Database storage is always enabled

        // Get retention period
        $retentionDays = $this->option('days') ?: config('perimeter.reporting.retention_days', 90);
        $cutoffDate = now()->subDays($retentionDays);

        // Get model classes
        $eventClass = config('perimeter.storage.models.security_event');
        $scanClass = config('perimeter.storage.models.security_scan');

        // Get counts of records to be pruned
        $eventCount = $eventClass::where('created_at', '<=', $cutoffDate)->count();
        $scanCount = $scanClass::where('created_at', '<=', $cutoffDate)->count();

        $this->info("Pruning records older than {$retentionDays} days ({$cutoffDate})");
        $this->info("Found {$eventCount} security events and {$scanCount} security scans to prune");

        // If dry run, just show the counts and exit
        if ($this->option('dry-run')) {
            $this->info('Dry run completed. No records were pruned.');

            return 0;
        }

        // Confirm unless --force is used
        if (! $this->option('force') && ! $this->confirm('Do you wish to continue?')) {
            $this->info('Pruning cancelled.');

            return 0;
        }

        $this->info('Pruning security events...');
        $bar = $this->output->createProgressBar($eventCount > 0 ? $eventCount : 1);
        $bar->start();

        // Prune in batches to avoid memory issues
        $eventClass::where('created_at', '<=', $cutoffDate)
            ->chunk(100, function ($events) use ($bar) {
                foreach ($events as $event) {
                    $event->delete();
                    $bar->advance();
                }
            });

        $bar->finish();
        $this->newLine();

        $this->info('Pruning security scans...');
        $bar = $this->output->createProgressBar($scanCount > 0 ? $scanCount : 1);
        $bar->start();

        // Prune in batches to avoid memory issues
        $scanClass::where('created_at', '<=', $cutoffDate)
            ->chunk(100, function ($scans) use ($bar) {
                foreach ($scans as $scan) {
                    $scan->delete();
                    $bar->advance();
                }
            });

        $bar->finish();
        $this->newLine(2);

        $this->info('Pruning completed successfully.');
        Log::info("Perimeter security records pruned: {$eventCount} events, {$scanCount} scans.");

        return 0;
    }
}
