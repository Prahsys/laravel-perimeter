<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Models\SecurityEvent;
use Prahsys\Perimeter\Models\SecurityScan;

class PerimeterTestMonitoring extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:test-monitoring 
                            {--type=all : Type of test to run (all, malware, behavioral, vulnerability, intrusion, firewall)}
                            {--severity=all : Severity level to test (all, emergency, critical, error, warning, info)}
                            {--channel=* : Log channels to test (uses config default if not specified)}
                            {--dry-run : Show what would be logged without actually logging}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test monitoring and alerting by generating security events at various log levels';

    /**
     * Test event templates for different security types
     */
    protected array $testEvents = [
        'malware' => [
            'emergency' => [
                'subtype' => 'ransomware',
                'description' => 'TEST ALERT: Ransomware-like behavior detected in file encryption process',
                'location' => '/tmp/test-encryption-process',
                'details' => ['pattern' => 'mass_file_encryption', 'files_affected' => 150, 'test' => true],
            ],
            'critical' => [
                'subtype' => 'trojan',
                'description' => 'TEST ALERT: Trojan signature detected in uploaded file',
                'location' => '/tmp/test-malicious-upload.exe',
                'details' => ['signature' => 'Win32.Trojan.Test', 'hash' => 'abc123def456', 'test' => true],
            ],
            'warning' => [
                'subtype' => 'adware',
                'description' => 'TEST ALERT: Adware-like behavior detected in browser extension',
                'location' => '/tmp/test-suspicious-extension',
                'details' => ['extension_id' => 'test-ext-123', 'behavior' => 'popup_injection', 'test' => true],
            ],
            'info' => [
                'subtype' => 'test',
                'description' => 'TEST ALERT: Test malware signature for monitoring verification',
                'location' => '/tmp/test-eicar-file.txt',
                'details' => ['signature' => 'EICAR-Test-File', 'action' => 'quarantined', 'test' => true],
            ],
        ],
        'behavioral' => [
            'emergency' => [
                'subtype' => 'privilege_escalation',
                'description' => 'TEST ALERT: Privilege escalation attempt detected',
                'location' => '/usr/bin/sudo',
                'user' => 'test-user',
                'details' => ['process' => 'sudo su -', 'parent_process' => 'test-shell', 'test' => true],
            ],
            'critical' => [
                'subtype' => 'suspicious_network',
                'description' => 'TEST ALERT: Suspicious network connection to known malicious IP',
                'location' => '192.168.1.100',
                'details' => ['destination' => '10.0.0.1', 'port' => 4444, 'protocol' => 'TCP', 'test' => true],
            ],
            'error' => [
                'subtype' => 'abnormal_file_access',
                'description' => 'TEST ALERT: Abnormal file access pattern detected',
                'location' => '/etc/passwd',
                'user' => 'test-user',
                'details' => ['access_count' => 50, 'time_window' => '5 minutes', 'test' => true],
            ],
            'warning' => [
                'subtype' => 'unusual_process',
                'description' => 'TEST ALERT: Unusual process execution detected',
                'location' => '/tmp/test-unusual-process',
                'details' => ['process_name' => 'test-miner', 'cpu_usage' => '95%', 'test' => true],
            ],
        ],
        'vulnerability' => [
            'critical' => [
                'subtype' => 'critical',
                'description' => 'TEST ALERT: Critical vulnerability detected in system component',
                'location' => 'package://test-vulnerable-lib@1.0.0',
                'details' => ['cve' => 'CVE-2024-TEST-001', 'cvss' => 9.8, 'fix_available' => true, 'test' => true],
            ],
            'error' => [
                'subtype' => 'high',
                'description' => 'TEST ALERT: High severity vulnerability in application dependency',
                'location' => 'composer://test-package@2.1.0',
                'details' => ['cve' => 'CVE-2024-TEST-002', 'cvss' => 7.5, 'fix_available' => false, 'test' => true],
            ],
            'warning' => [
                'subtype' => 'medium',
                'description' => 'TEST ALERT: Medium severity security issue in configuration',
                'location' => '/etc/test-config.conf',
                'details' => ['issue' => 'weak_encryption', 'recommendation' => 'Update cipher suite', 'test' => true],
            ],
            'info' => [
                'subtype' => 'low',
                'description' => 'TEST ALERT: Low severity information disclosure vulnerability',
                'location' => '/var/log/test-application.log',
                'details' => ['issue' => 'sensitive_data_logging', 'data_type' => 'user_tokens', 'test' => true],
            ],
        ],
        'intrusion' => [
            'critical' => [
                'description' => 'TEST ALERT: Multiple failed authentication attempts detected',
                'location' => '192.168.1.200',
                'details' => ['attempts' => 25, 'service' => 'ssh', 'time_window' => '2 minutes', 'test' => true],
            ],
            'error' => [
                'description' => 'TEST ALERT: Brute force attack detected and blocked',
                'location' => '10.0.0.50',
                'details' => ['jail' => 'sshd', 'ban_duration' => '1 hour', 'attempts' => 10, 'test' => true],
            ],
            'warning' => [
                'description' => 'TEST ALERT: Suspicious login pattern detected',
                'location' => '172.16.0.1',
                'user' => 'test-admin',
                'details' => ['login_times' => ['02:30', '03:15', '04:00'], 'unusual_location' => true, 'test' => true],
            ],
        ],
        'firewall' => [
            'error' => [
                'description' => 'TEST ALERT: Blocked connection attempt to restricted port',
                'location' => '203.0.113.1',
                'details' => ['port' => 22, 'protocol' => 'TCP', 'direction' => 'inbound', 'test' => true],
            ],
            'warning' => [
                'description' => 'TEST ALERT: High volume of blocked connections detected',
                'location' => '198.51.100.1',
                'details' => ['blocked_count' => 500, 'time_window' => '10 minutes', 'ports' => [80, 443, 8080], 'test' => true],
            ],
            'info' => [
                'description' => 'TEST ALERT: Firewall rule triggered for monitoring',
                'location' => '192.0.2.1',
                'details' => ['rule' => 'test-monitoring-rule', 'action' => 'log', 'matched_packets' => 1, 'test' => true],
            ],
        ],
    ];

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $type = $this->option('type');
        $severity = $this->option('severity');
        $channels = $this->option('channel');
        $dryRun = $this->option('dry-run');

        // Use configured channels if none specified
        if (empty($channels)) {
            $channels = config('perimeter.logging.channels', ['stack']);
        }

        $this->info('🔍 Perimeter Monitoring Test');
        $this->info('Testing log channels: '.implode(', ', $channels));

        if ($dryRun) {
            $this->warn('DRY RUN MODE: Events will be shown but not logged or stored');
        }

        $this->newLine();

        // Create a test security scan
        $scan = null;
        if (! $dryRun) {
            $scan = SecurityScan::create([
                'scan_type' => 'monitoring_test',
                'started_at' => now(),
                'status' => 'running',
                'command' => 'perimeter:test-monitoring',
                'command_options' => array_merge($this->options(), ['test' => true]),
            ]);
            $this->info("Created test security scan #{$scan->id}");
        }

        $eventsGenerated = 0;
        $typesToTest = $type === 'all' ? array_keys($this->testEvents) : [$type];

        foreach ($typesToTest as $eventType) {
            if (! isset($this->testEvents[$eventType])) {
                $this->error("Unknown event type: {$eventType}");

                continue;
            }

            $this->info("🔥 Testing {$eventType} events:");

            $severityLevels = $severity === 'all' ?
                array_keys($this->testEvents[$eventType]) :
                [$severity];

            foreach ($severityLevels as $severityLevel) {
                if (! isset($this->testEvents[$eventType][$severityLevel])) {
                    $this->warn("  ⚠️  No test data for {$eventType} at {$severityLevel} level");

                    continue;
                }

                $eventData = $this->testEvents[$eventType][$severityLevel];
                $eventData['type'] = $eventType;
                $eventData['severity'] = $severityLevel;
                $eventData['service'] = 'perimeter-test';
                $eventData['timestamp'] = now();
                $eventData['scan_id'] = $scan?->id;
                $eventData['test'] = true; // Mark as test event

                $logLevel = $this->getLogLevel($eventType, $severityLevel);
                $logMessage = "[TEST] {$eventData['description']}";

                // Add test context to log data
                $logContext = array_merge($eventData, [
                    'test' => true,
                    'test_command' => 'perimeter:test-monitoring',
                    'test_timestamp' => now()->toISOString(),
                ]);

                if ($dryRun) {
                    $this->line("  📝 Would log [{$logLevel}]: {$logMessage}");
                    $this->line('      Channels: '.implode(', ', $channels));
                    $this->line('      Data: '.json_encode($logContext, JSON_PRETTY_PRINT));
                } else {
                    // Log to specified channels
                    foreach ($channels as $channel) {
                        Log::channel($channel)->log($logLevel, $logMessage, $logContext);
                    }

                    // Store in database with test flag
                    SecurityEvent::create([
                        'scan_id' => $scan?->id,
                        'timestamp' => $eventData['timestamp'],
                        'type' => $eventData['type'],
                        'severity' => $eventData['severity'],
                        'description' => $eventData['description'],
                        'location' => $eventData['location'] ?? null,
                        'user' => $eventData['user'] ?? null,
                        'service' => $eventData['service'],
                        'details' => json_encode(array_merge($eventData['details'] ?? [], [
                            'test' => true,
                            'test_command' => 'perimeter:test-monitoring',
                            'test_timestamp' => now()->toISOString(),
                        ])),
                    ]);

                    $this->line("  ✅ Logged [{$logLevel}]: {$logMessage}");
                }

                $eventsGenerated++;
            }
        }

        if (! $dryRun && $scan) {
            $scan->update([
                'completed_at' => now(),
                'status' => 'completed',
                'issues_found' => $eventsGenerated,
                'scan_details' => [
                    'test' => true,
                    'test_type' => $type,
                    'severity_filter' => $severity,
                    'channels_tested' => $channels,
                    'events_generated' => $eventsGenerated,
                ],
            ]);
        }

        $this->newLine();
        $this->info('🎉 Monitoring test completed!');
        $this->info("Generated {$eventsGenerated} test events");

        if (! $dryRun) {
            $this->info('Check your monitoring systems (Sentry, logs, etc.) for the test alerts');
            $this->info("Run 'php artisan perimeter:report' to view the generated events");
            $this->info("💡 To clean up test events, filter by 'test' field in details JSON");
        }

        return 0;
    }

    /**
     * Get the appropriate log level for a given event type and severity
     */
    protected function getLogLevel(string $eventType, string $severity): string
    {
        $configLevels = config("perimeter.logging.levels.{$eventType}.{$severity}");

        if ($configLevels) {
            return $configLevels;
        }

        // Fallback mapping
        return match ($severity) {
            'emergency' => 'emergency',
            'critical' => 'critical',
            'error' => 'error',
            'warning' => 'warning',
            'info' => 'info',
            default => 'info',
        };
    }
}
