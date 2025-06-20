<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Schema;
use Prahsys\Perimeter\Models\SecurityEvent;
use Prahsys\Perimeter\Models\SecurityScan;

class PerimeterSeedTestData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:seed-test-data {--count=30 : Number of events to generate}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Seed test security events for development and testing';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Seeding test security events for development...');

        // Check if tables exist
        if (! Schema::hasTable('perimeter_security_events') || ! Schema::hasTable('perimeter_security_scans')) {
            $this->error('Perimeter security tables do not exist. Run migrations first.');

            return 1;
        }

        // Debug database structure
        $this->info('Checking database structure...');
        $columns = \Illuminate\Support\Facades\DB::select('PRAGMA table_info(perimeter_security_events)');
        $this->info('Event table columns: '.implode(', ', array_column($columns, 'name')));

        // Get count from options
        $count = (int) $this->option('count');
        if ($count < 1) {
            $count = 30;
        }

        // Create a security scan
        $scan = SecurityScan::create([
            'scan_type' => 'audit',
            'started_at' => now()->subMinutes(5),
            'completed_at' => now()->subMinutes(4),
            'status' => 'completed',
            'issues_found' => (int) ($count * 0.4), // About 40% of events
            'scan_details' => [
                'malware_count' => (int) ($count * 0.1),
                'vulnerability_count' => (int) ($count * 0.2),
                'behavioral_count' => (int) ($count * 0.1),
            ],
            'command' => 'perimeter:audit',
            'command_options' => null,
        ]);

        $this->info('Created test security scan #'.$scan->id);

        // Create events by type
        $malwareCount = (int) ($count * 0.25);
        $vulnerabilityCount = (int) ($count * 0.45);
        $behavioralCount = (int) ($count * 0.15);
        $otherCount = $count - $malwareCount - $vulnerabilityCount - $behavioralCount;

        // Create specific events with scan_id
        SecurityEvent::factory()
            ->count($malwareCount)
            ->malware()
            ->create([
                'scan_id' => $scan->id,
                'timestamp' => now()->subMinutes(rand(1, 60)),
            ]);
        $this->info("Created $malwareCount malware events");

        SecurityEvent::factory()
            ->count($vulnerabilityCount)
            ->vulnerability()
            ->create([
                'scan_id' => $scan->id,
                'timestamp' => now()->subMinutes(rand(1, 60)),
            ]);
        $this->info("Created $vulnerabilityCount vulnerability events");

        SecurityEvent::factory()
            ->count($behavioralCount)
            ->behavioral()
            ->create([
                'scan_id' => $scan->id,
                'timestamp' => now()->subMinutes(rand(1, 60)),
            ]);
        $this->info("Created $behavioralCount behavioral events");

        // Create some random events not associated with a scan (simulating runtime monitoring events)
        if ($otherCount > 0) {
            SecurityEvent::factory()
                ->count($otherCount)
                ->create(['timestamp' => now()->subMinutes(rand(1, 60))]);
            $this->info("Created $otherCount additional runtime monitoring events");
        }

        $this->newLine();
        $this->info("Successfully created $count test security events");
        $this->info("Run 'php artisan perimeter:audit' to see them displayed in tables");

        return 0;
    }
}
