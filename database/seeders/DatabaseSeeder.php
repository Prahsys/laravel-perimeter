<?php

namespace Prahsys\Perimeter\Database\Seeders;

use Illuminate\Database\Seeder;
use Prahsys\Perimeter\Models\SecurityEvent;
use Prahsys\Perimeter\Models\SecurityScan;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        // Create a security scan
        $scan = SecurityScan::create([
            'scan_type' => 'audit',
            'started_at' => now()->subMinutes(30),
            'completed_at' => now()->subMinutes(29),
            'status' => 'completed',
            'issues_found' => 12,
            'scan_details' => [
                'malware_count' => 2,
                'vulnerability_count' => 8,
                'behavioral_count' => 2,
            ],
            'command' => 'perimeter:audit',
            'command_options' => null,
        ]);

        // Create specific events
        SecurityEvent::factory()
            ->count(2)
            ->malware()
            ->create(['scan_id' => $scan->id]);

        SecurityEvent::factory()
            ->count(8)
            ->vulnerability()
            ->create(['scan_id' => $scan->id]);

        SecurityEvent::factory()
            ->count(2)
            ->behavioral()
            ->create(['scan_id' => $scan->id]);

        // Create some random events not associated with a scan
        SecurityEvent::factory()
            ->count(20)
            ->create();
    }
}
