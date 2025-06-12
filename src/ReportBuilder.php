<?php

namespace Prahsys\Perimeter;

use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

class ReportBuilder
{
    /**
     * From timestamp.
     *
     * @var \Carbon\Carbon|null
     */
    protected ?Carbon $from = null;

    /**
     * To timestamp.
     *
     * @var \Carbon\Carbon|null
     */
    protected ?Carbon $to = null;

    /**
     * Event types to include.
     *
     * @var array|null
     */
    protected ?array $types = null;

    /**
     * Severity levels to include.
     *
     * @var array|null
     */
    protected ?array $severities = null;

    /**
     * Output format.
     *
     * @var string
     */
    protected string $format = 'json';

    /**
     * Set the from timestamp.
     *
     * @param \Carbon\Carbon|string $from
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
     * @param \Carbon\Carbon|string $to
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
     * @param array $types
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
     * @param array $severities
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
     * @param string $format
     * @return $this
     */
    public function format(string $format)
    {
        $this->format = $format;

        return $this;
    }

    /**
     * Get the events matching the criteria.
     *
     * @return array
     */
    public function get(): array
    {
        // In a real implementation, this would query a log store
        // For this demo, we return sample data
        $events = $this->getSampleEvents();

        // Apply filters
        $events = $this->applyFilters($events);

        return $events;
    }

    /**
     * Export the report to the configured format.
     *
     * @return string
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
     *
     * @param array $events
     * @return array
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
            ->values()
            ->all();
    }

    /**
     * Export events to CSV format.
     *
     * @param array $events
     * @return string
     */
    protected function exportToCsv(array $events): string
    {
        if (empty($events)) {
            return 'timestamp,type,severity,description,details' . PHP_EOL;
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
     * Get sample events for demonstration purposes.
     *
     * @return array
     */
    protected function getSampleEvents(): array
    {
        return [
            [
                'timestamp' => '2025-05-01T12:34:56Z',
                'type' => 'malware',
                'severity' => 'critical',
                'description' => 'Detected Trojan.PHP.Agent in uploaded file',
                'details' => [
                    'file' => '/tmp/uploads/document.php',
                    'user' => 'anonymous',
                    'ip' => '192.168.1.100',
                ],
            ],
            [
                'timestamp' => '2025-05-02T09:12:34Z',
                'type' => 'vulnerability',
                'severity' => 'high',
                'description' => 'Detected CVE-2025-1234 in package example/package',
                'details' => [
                    'package' => 'example/package',
                    'version' => '1.2.3',
                    'cve' => 'CVE-2025-1234',
                    'fix_version' => '1.2.4',
                ],
            ],
            [
                'timestamp' => '2025-05-03T15:45:12Z',
                'type' => 'behavioral',
                'severity' => 'critical',
                'description' => 'Privilege escalation attempt detected',
                'details' => [
                    'process' => 'artisan',
                    'user' => 'www-data',
                    'command' => 'chmod 777 /etc/passwd',
                ],
            ],
            [
                'timestamp' => '2025-05-04T08:22:15Z',
                'type' => 'malware',
                'severity' => 'warning',
                'description' => 'Potential unwanted program detected',
                'details' => [
                    'file' => '/var/www/html/public/js/analytics.js',
                    'signature' => 'PUP.JS.Miner',
                ],
            ],
            [
                'timestamp' => '2025-05-05T14:33:21Z',
                'type' => 'vulnerability',
                'severity' => 'medium',
                'description' => 'Outdated package with known vulnerabilities',
                'details' => [
                    'package' => 'example/framework',
                    'version' => '2.0.1',
                    'recommendation' => 'Update to 2.1.0 or later',
                ],
            ],
        ];
    }
}