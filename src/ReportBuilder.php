<?php

namespace Prahsys\Perimeter;

use Carbon\Carbon;

class ReportBuilder
{
    /**
     * From timestamp.
     */
    protected ?Carbon $from = null;

    /**
     * To timestamp.
     */
    protected ?Carbon $to = null;

    /**
     * Event types to include.
     */
    protected ?array $types = null;

    /**
     * Severity levels to include.
     */
    protected ?array $severities = null;

    /**
     * Output format.
     */
    protected string $format = 'json';

    /**
     * Set the from timestamp.
     *
     * @param  \Carbon\Carbon|string  $from
     * @return $this
     */
    public function from($from)
    {
        if (is_string($from)) {
            $from = Carbon::parse($from);
        }

        $this->from = $from;

        return $this;
    }

    /**
     * Set the to timestamp.
     *
     * @param  \Carbon\Carbon|string  $to
     * @return $this
     */
    public function to($to)
    {
        if (is_string($to)) {
            $to = Carbon::parse($to);
        }

        $this->to = $to;

        return $this;
    }

    /**
     * Set the event types to include.
     *
     * @return $this
     */
    public function type(array $types)
    {
        $this->types = $types;

        return $this;
    }

    /**
     * Set the severity levels to include.
     *
     * @return $this
     */
    public function severity(array $severities)
    {
        $this->severities = $severities;

        return $this;
    }

    /**
     * Set the output format.
     *
     * @return $this
     */
    public function format(string $format)
    {
        $this->format = $format;

        return $this;
    }

    /**
     * The service manager instance.
     *
     * @var \Prahsys\Perimeter\Services\ServiceManager|null
     */
    protected $serviceManager = null;

    /**
     * Set the service manager.
     *
     * @return $this
     */
    public function setServiceManager(\Prahsys\Perimeter\Services\ServiceManager $serviceManager)
    {
        $this->serviceManager = $serviceManager;

        return $this;
    }

    /**
     * Get the events matching the criteria.
     */
    public function get(): array
    {
        // Try to get events from the database first
        $events = $this->getEventsFromDatabase();

        // If we got events from the database, return them
        if (! empty($events)) {
            return $events;
        }

        // Fall back to getting events from services if no database results
        $events = $this->getRealEvents();

        // Apply filters
        $events = $this->applyFilters($events);

        return $events;
    }

    /**
     * Get events from the database with applied filters.
     */
    protected function getEventsFromDatabase(): array
    {
        // Get the model class from config
        $eventClass = config('perimeter.storage.models.security_event', \Prahsys\Perimeter\Models\SecurityEvent::class);

        // Start building the query
        $query = $eventClass::query();

        // Apply date filters
        if ($this->from) {
            $query->where('timestamp', '>=', $this->from);
        }

        if ($this->to) {
            $query->where('timestamp', '<=', $this->to);
        }

        // Apply type filter
        if ($this->types) {
            $query->whereIn('type', $this->types);
        }

        // Apply severity filter
        if ($this->severities) {
            $query->whereIn('severity', $this->severities);
        }

        // Order by timestamp, newest first
        $query->orderBy('timestamp', 'desc');

        // Convert models to array format
        return $query->get()->map(function ($event) {
            return $event->toReportFormat();
        })->all();
    }

    /**
     * Export the report to the configured format.
     */
    public function export(): string
    {
        $events = $this->get();

        if ($this->format === 'csv') {
            return $this->exportToCsv($events);
        }

        // Default to JSON
        return json_encode($events, JSON_PRETTY_PRINT);
    }

    /**
     * Apply the configured filters to the events.
     */
    protected function applyFilters(array $events): array
    {
        return collect($events)
            ->when($this->from, function ($collection) {
                return $collection->filter(function ($event) {
                    $timestamp = Carbon::parse($event['timestamp']);

                    return $timestamp->greaterThanOrEqualTo($this->from);
                });
            })
            ->when($this->to, function ($collection) {
                return $collection->filter(function ($event) {
                    $timestamp = Carbon::parse($event['timestamp']);

                    return $timestamp->lessThanOrEqualTo($this->to);
                });
            })
            ->when($this->types, function ($collection) {
                return $collection->filter(function ($event) {
                    return in_array($event['type'], $this->types);
                });
            })
            ->when($this->severities, function ($collection) {
                return $collection->filter(function ($event) {
                    return in_array($event['severity'], $this->severities);
                });
            })
            // Make sure the scan_id is included in the results
            ->map(function ($event) {
                // Ensure scan_id is pulled from details if it exists there
                if (! isset($event['scan_id']) && isset($event['details']['scan_id'])) {
                    $event['scan_id'] = $event['details']['scan_id'];
                }

                return $event;
            })
            ->values()
            ->all();
    }

    /**
     * Export events to CSV format.
     */
    protected function exportToCsv(array $events): string
    {
        if (empty($events)) {
            return 'timestamp,type,severity,description,details'.PHP_EOL;
        }

        $csv = fopen('php://temp', 'r+');

        // Header row
        fputcsv($csv, ['timestamp', 'type', 'severity', 'description', 'details']);

        // Data rows
        foreach ($events as $event) {
            fputcsv($csv, [
                $event['timestamp'],
                $event['type'],
                $event['severity'],
                $event['description'],
                json_encode($event['details'] ?? []),
            ]);
        }

        rewind($csv);
        $output = stream_get_contents($csv);
        fclose($csv);

        return $output;
    }

    /**
     * Get real events from the security services.
     */
    protected function getRealEvents(): array
    {
        if (! $this->serviceManager) {
            return [];
        }

        $events = [];

        // Process scanner services (malware detection)
        foreach ($this->serviceManager->getScanners() as $service) {
            if ($service->isEnabled() && $service->isConfigured()) {
                // Get service-specific configuration
                $serviceName = strtolower(preg_replace('/Service$/', '', class_basename(get_class($service))));
                $scanPaths = config("perimeter.{$serviceName}.scan_paths", [base_path()]);
                $excludePatterns = config("perimeter.{$serviceName}.exclude_patterns", []);

                // Scan for malware
                $malwareResults = $service->scanPaths($scanPaths, $excludePatterns);

                foreach ($malwareResults as $result) {
                    $events[] = [
                        'timestamp' => $result['timestamp'] ?? now()->toIso8601String(),
                        'type' => 'malware',
                        'severity' => 'critical',
                        'description' => "Detected {$result['threat']} in file",
                        'scan_id' => $result['scan_id'] ?? null,
                        'service' => $serviceName,
                        'details' => [
                            'file' => $result['file'],
                            'threat' => $result['threat'],
                            'service' => $serviceName,
                        ],
                    ];
                }
            }
        }

        // Process monitoring services (behavioral detection)
        foreach ($this->serviceManager->getMonitors() as $service) {
            if ($service->isEnabled() && $service->isConfigured()) {
                $serviceName = strtolower(preg_replace('/Service$/', '', class_basename(get_class($service))));
                $behavioralResults = $service->getRecentEvents(20);

                foreach ($behavioralResults as $result) {
                    $events[] = [
                        'timestamp' => $result['timestamp'] ?? now()->toIso8601String(),
                        'type' => 'behavioral',
                        'severity' => $result['priority'] ?? 'medium',
                        'description' => $result['description'],
                        'scan_id' => $result['scan_id'] ?? null,
                        'service' => $serviceName,
                        'details' => [
                            'rule' => $result['rule'] ?? 'unknown',
                            'process' => $result['process'] ?? 'unknown',
                            'user' => $result['user'] ?? 'unknown',
                            'details' => $result['details'] ?? [],
                            'service' => $serviceName,
                        ],
                    ];
                }
            }
        }

        // Process vulnerability scanners
        foreach ($this->serviceManager->getVulnerabilityScanners() as $service) {
            if ($service->isEnabled() && $service->isConfigured()) {
                $serviceName = strtolower(preg_replace('/Service$/', '', class_basename(get_class($service))));
                $vulnerabilityResults = $service->scanDependencies();

                foreach ($vulnerabilityResults as $result) {
                    $severity = strtolower($result['severity'] ?? 'medium');
                    $events[] = [
                        'timestamp' => $result['timestamp'] ?? now()->toIso8601String(),
                        'type' => 'vulnerability',
                        'severity' => $severity,
                        'description' => $result['title'],
                        'scan_id' => $result['scan_id'] ?? null,
                        'service' => $serviceName,
                        'details' => [
                            'package' => $result['packageName'] ?? 'unknown',
                            'version' => $result['version'] ?? 'unknown',
                            'cve' => $result['cve'] ?? 'Unknown',
                            'fix_version' => $result['fixedVersion'] ?? 'Unknown',
                            'service' => $serviceName,
                        ],
                    ];
                }
            }
        }

        // Process intrusion prevention services
        foreach ($this->serviceManager->getIntrusionPreventionServices() as $service) {
            if ($service->isEnabled() && $service->isConfigured()) {
                $serviceName = strtolower(preg_replace('/Service$/', '', class_basename(get_class($service))));
                $intrusionEvents = $service->getRecentEvents(20);

                foreach ($intrusionEvents as $result) {
                    $severity = isset($result['repeated']) && $result['repeated'] > 3 ? 'high' : 'medium';
                    $events[] = [
                        'timestamp' => $result['timestamp'] ?? now()->toIso8601String(),
                        'type' => 'intrusion',
                        'severity' => $severity,
                        'description' => $result['description'] ?? 'Intrusion attempt blocked',
                        'scan_id' => $result['scan_id'] ?? null,
                        'service' => $serviceName,
                        'details' => array_merge($result, ['service' => $serviceName]),
                    ];
                }
            }
        }

        // Process firewall services
        foreach ($this->serviceManager->getFirewalls() as $service) {
            if ($service->isEnabled() && $service->isConfigured()) {
                $serviceName = strtolower(preg_replace('/Service$/', '', class_basename(get_class($service))));
                $firewallEvents = $service->getRecentEvents(20);

                foreach ($firewallEvents as $result) {
                    $events[] = [
                        'timestamp' => $result['timestamp'] ?? now()->toIso8601String(),
                        'type' => 'firewall',
                        'severity' => $result['severity'] ?? 'medium',
                        'description' => $result['description'] ?? 'Firewall event',
                        'scan_id' => $result['scan_id'] ?? null,
                        'service' => $serviceName,
                        'details' => array_merge($result, ['service' => $serviceName]),
                    ];
                }
            }
        }

        return $events;
    }

    /**
     * Get sample events for demonstration purposes.
     * This method is only for internal testing and debugging.
     * It should NEVER be used in production reports.
     */
    protected function getSampleEvents(): array
    {
        // This method exists only for internal testing and development purposes
        // It is no longer used in production code to prevent false positives

        return [
            [
                'timestamp' => now()->subDays(5)->toIso8601String(),
                'type' => 'malware',
                'severity' => 'critical',
                'description' => '[SAMPLE DATA - NOT REAL] Detected Trojan.PHP.Agent in uploaded file',
                'details' => [
                    'file' => '/tmp/uploads/document.php',
                    'user' => 'anonymous',
                    'ip' => '192.168.1.100',
                    'sample_data' => true,
                ],
            ],
            [
                'timestamp' => now()->subDays(4)->toIso8601String(),
                'type' => 'vulnerability',
                'severity' => 'high',
                'description' => '[SAMPLE DATA - NOT REAL] Detected CVE-2025-1234 in package example/package',
                'details' => [
                    'package' => 'example/package',
                    'version' => '1.2.3',
                    'cve' => 'CVE-2025-1234',
                    'fix_version' => '1.2.4',
                    'sample_data' => true,
                ],
            ],
            [
                'timestamp' => now()->subDays(3)->toIso8601String(),
                'type' => 'behavioral',
                'severity' => 'critical',
                'description' => '[SAMPLE DATA - NOT REAL] Privilege escalation attempt detected',
                'details' => [
                    'process' => 'artisan',
                    'user' => 'www-data',
                    'command' => 'chmod 777 /etc/passwd',
                    'sample_data' => true,
                ],
            ],
        ];
    }
}
