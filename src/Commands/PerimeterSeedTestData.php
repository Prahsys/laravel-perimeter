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

        // Optional: seed test files for other testing
        $this->seedTestFiles();

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

        // Calculate event distribution ensuring variety
        $malwareCount = max(2, (int) ($count * 0.25));
        $vulnerabilityCount = max(2, (int) ($count * 0.35));
        $behavioralCount = max(2, (int) ($count * 0.20));
        $intrusionCount = max(2, (int) ($count * 0.15));
        $firewallCount = max(1, (int) ($count * 0.05));

        // Adjust counts to match total if needed
        $total = $malwareCount + $vulnerabilityCount + $behavioralCount + $intrusionCount + $firewallCount;
        if ($total != $count) {
            $diff = $count - $total;
            $vulnerabilityCount += $diff; // Adjust the vulnerability count to match total
        }

        // Create specific events with varied types
        SecurityEvent::factory()
            ->count($malwareCount)
            ->malware()
            ->create([
                'scan_id' => $scan->id,
            ]);
        $this->info("Created $malwareCount malware events");

        SecurityEvent::factory()
            ->count($vulnerabilityCount)
            ->vulnerability()
            ->create([
                'scan_id' => $scan->id,
            ]);
        $this->info("Created $vulnerabilityCount vulnerability events");

        SecurityEvent::factory()
            ->count($behavioralCount)
            ->behavioral()
            ->create([
                'scan_id' => $scan->id,
            ]);
        $this->info("Created $behavioralCount behavioral events");

        // Create intrusion events with scan_id
        $intrusionEvents = [];
        for ($i = 0; $i < $intrusionCount; $i++) {
            $ip = fake()->ipv4;
            $jail = fake()->randomElement(['sshd', 'apache-auth', 'php-fpm', 'wordpress']);
            $timestamp = fake()->dateTimeBetween('-2 days', '-30 minutes')->format('Y-m-d H:i:s');

            $descriptions = [
                "Intrusion attempt blocked from {$ip}",
                "Banned IP {$ip} after multiple failed attempts",
                "Suspicious login activity from {$ip}",
                "Brute force attack detected from {$ip}",
                "Multiple authentication failures from {$ip}",
                "{$jail}: Failed authentication attempts from {$ip}",
            ];

            $intrusionEvents[] = [
                'scan_id' => $scan->id,
                'timestamp' => $timestamp,
                'type' => 'intrusion',
                'severity' => fake()->randomElement(['high', 'medium']),
                'description' => fake()->randomElement($descriptions),
                'location' => $ip,
                'user' => null,
                'service' => 'fail2ban',
                'details' => json_encode([
                    'ip' => $ip,
                    'jail' => $jail,
                    'attempts' => fake()->numberBetween(3, 20),
                    'action' => 'ban',
                    'timestamp' => $timestamp,
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }

        SecurityEvent::insert($intrusionEvents);
        $this->info("Created $intrusionCount intrusion events");

        // Create firewall events
        $firewallEvents = [];
        for ($i = 0; $i < $firewallCount; $i++) {
            $ip = fake()->ipv4;
            $port = fake()->numberBetween(1000, 65535);
            $protocol = fake()->randomElement(['TCP', 'UDP']);
            $timestamp = fake()->dateTimeBetween('-3 days', '-1 hour')->format('Y-m-d H:i:s');

            $descriptions = [
                "Blocked connection attempt to port {$port}/{$protocol}",
                "Firewall blocked incoming traffic from {$ip}",
                "Suspicious connection attempt to port {$port}",
            ];

            $firewallEvents[] = [
                'scan_id' => $scan->id,
                'timestamp' => $timestamp,
                'type' => 'firewall',
                'severity' => fake()->randomElement(['medium', 'low']),
                'description' => fake()->randomElement($descriptions),
                'location' => $ip,
                'user' => null,
                'service' => 'ufw',
                'details' => json_encode([
                    'ip' => $ip,
                    'port' => $port,
                    'protocol' => $protocol,
                    'direction' => 'inbound',
                    'timestamp' => $timestamp,
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }

        SecurityEvent::insert($firewallEvents);
        $this->info("Created $firewallCount firewall events");

        $this->newLine();
        $this->info("Successfully created $count test security events with improved variety");
        $this->info("Run 'php artisan perimeter:audit' to see them displayed in tables");

        return 0;
    }

    /**
     * Seed test files for testing various security components
     */
    protected function seedTestFiles(): void
    {
        // Copy test auth.log file if available
        $testAuthLog = __DIR__.'/../../resources/testdata/auth.log';
        if (file_exists($testAuthLog)) {
            $authLogPath = '/var/log/auth/auth.log';

            // Make sure the directory exists
            $authLogDir = dirname($authLogPath);
            if (! is_dir($authLogDir)) {
                mkdir($authLogDir, 0755, true);
            }

            // Always copy test data to auth.log as part of seeding
            copy($testAuthLog, $authLogPath);
            $this->info('Copied test auth.log file for fail2ban testing');
        }

        // Copy EICAR test file for malware detection testing
        $eicarTestFile = __DIR__.'/../../resources/testdata/eicar.txt';
        if (file_exists($eicarTestFile)) {
            $targetDir = '/tmp/test-files';
            if (! is_dir($targetDir)) {
                mkdir($targetDir, 0755, true);
            }

            $targetFile = $targetDir.'/eicar.txt';
            // Always copy test file as part of seeding
            copy($eicarTestFile, $targetFile);
            $this->info('Created EICAR test file for ClamAV testing');
        }
    }
}
