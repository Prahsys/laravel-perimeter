<?php

namespace Prahsys\Perimeter\Commands;

use Carbon\Carbon;
use Illuminate\Console\Command;
use Prahsys\Perimeter\Facades\Perimeter;

class PerimeterReport extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:report
                            {--scan-id= : Filter by specific scan ID}
                            {--from= : Start date for filtering scans (Y-m-d format)}
                            {--to= : End date for filtering scans (Y-m-d format)}
                            {--type= : Filter by event type (comma-separated: malware,vulnerability,behavioral)}
                            {--severity= : Filter by severity (comma-separated: critical,high,medium,low)}
                            {--format=text : Output format (text, json, csv)}
                            {--output= : Output file path}
                            {--scans-only : Show only scan summary without event details}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate security reports based on scan history';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        // Get report parameters
        $scanId = $this->option('scan-id');
        $from = $this->option('from');
        $to = $this->option('to');
        $type = $this->option('type');
        $severity = $this->option('severity');
        $format = $this->option('format');
        $output = $this->option('output');
        $scansOnly = $this->option('scans-only');

        // If showing scans only, display scan summary and return
        if ($scansOnly) {
            $this->displayScanSummary($from, $to, $type);

            return 0;
        }

        // If scan ID is provided, show details for that specific scan
        if ($scanId) {
            $this->displayScanDetails($scanId, $format, $output);

            return 0;
        }

        // Regular event reporting flow
        $report = Perimeter::report();

        // Set up the report with the service manager for more extensibility
        $serviceManager = app()->make('Prahsys\Perimeter\Services\ServiceManager');
        $report->setServiceManager($serviceManager);

        if ($from) {
            $report->from($from);
        }

        if ($to) {
            $report->to($to);
        }

        if ($type) {
            $report->type(explode(',', $type));
        }

        if ($severity) {
            $report->severity(explode(',', $severity));
        }

        // Set the output format
        $report->format($format === 'text' ? 'json' : $format);

        // Get the report data from database only (no live scanning)
        $eventClass = config('perimeter.storage.models.security_event', \Prahsys\Perimeter\Models\SecurityEvent::class);
        $query = $eventClass::query();

        // Apply filters if provided
        if ($from) {
            $query->where('timestamp', '>=', \Carbon\Carbon::parse($from));
        }
        if ($to) {
            $query->where('timestamp', '<=', \Carbon\Carbon::parse($to));
        }
        if ($type) {
            $query->whereIn('type', explode(',', $type));
        }
        if ($severity) {
            $query->whereIn('severity', explode(',', $severity));
        }

        $events = $query->orderBy('timestamp', 'desc')->get()->toArray();

        // Export to file if output path is specified
        if ($output && $format !== 'text') {
            $content = $report->export();
            file_put_contents($output, $content);
            $this->info("Report exported to {$output}");

            return 0;
        }

        // Display the report data based on format
        if ($format === 'json') {
            $this->output->write(json_encode($events, JSON_PRETTY_PRINT));

            return 0;
        } elseif ($format === 'csv') {
            $this->output->write($report->export());

            return 0;
        }

        // Text format (default)
        $this->displayTextReport($events);

        return 0;
    }

    /**
     * Display report in text format.
     */
    protected function displayTextReport(array $events): void
    {
        if (empty($events)) {
            $this->line('No security issues were detected during recent scans.');
            $this->newLine();

            $this->line('To perform a new security scan, run:');
            $this->line('  <fg=yellow>php artisan perimeter:audit</>');
            $this->newLine();
            $this->line('To check service health, run:');
            $this->line('  <fg=yellow>php artisan perimeter:health</>');

            return;
        }

        $this->line('<fg=white;bg=blue>SECURITY EVENTS REPORT</>');
        $this->newLine();

        // Suggest using the scan-focused report
        $this->info('TIP: For a more organized view, try the scan-focused report:');
        $this->line('  <fg=yellow>php artisan perimeter:report --scans-only</>');
        $this->newLine();

        // Group events by type
        $groupedEvents = [];
        foreach ($events as $event) {
            $type = $event['type'] ?? 'unknown';
            $groupedEvents[$type][] = $event;
        }

        // Display events by type
        foreach ($groupedEvents as $type => $typeEvents) {
            $this->line('<fg=white;bg=green>'.strtoupper($type).' EVENTS ('.count($typeEvents).')</>');
            $this->newLine();

            $headers = ['Timestamp', 'Severity', 'Description', 'Details'];
            $rows = [];

            foreach ($typeEvents as $event) {
                $severityColor = $this->getSeverityColor($event['severity']);
                $details = json_encode($event['details'] ?? [], JSON_PRETTY_PRINT);
                $details = strlen($details) > 50 ? substr($details, 0, 47).'...' : $details;

                $rows[] = [
                    $event['timestamp'],
                    "<fg={$severityColor}>{$event['severity']}</>",
                    $event['description'],
                    $details,
                ];
            }

            $this->table($headers, $rows);
            $this->newLine();
        }
    }

    /**
     * Display a summary of security scans.
     */
    protected function displayScanSummary(?string $from = null, ?string $to = null, ?string $type = null): void
    {
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);

        // Start building the query
        $query = $scanClass::query();

        // Apply date filters
        if ($from) {
            $query->where('started_at', '>=', \Carbon\Carbon::parse($from));
        }

        if ($to) {
            $query->where('started_at', '<=', \Carbon\Carbon::parse($to));
        }

        // Apply type filter
        if ($type) {
            $types = explode(',', $type);
            $query->whereIn('scan_type', $types);
        }

        // Order by started_at, newest first
        $query->orderBy('started_at', 'desc');

        // Get the scans
        $scans = $query->get();

        $this->output->title('Security Scan Summary');
        $this->newLine();

        if ($scans->isEmpty()) {
            $this->info('No security scans found matching the criteria.');
            $this->line('Run <fg=yellow>php artisan perimeter:audit</> to perform a new security scan.');

            return;
        }

        $headers = ['ID', 'Type', 'Started At', 'Status', 'Issues', 'Duration'];
        $rows = [];

        foreach ($scans as $scan) {
            $duration = 'N/A';
            if ($scan->completed_at && $scan->started_at) {
                $duration = $scan->started_at->diffInSeconds($scan->completed_at).'s';
            }

            $statusColor = match ($scan->status) {
                'completed' => 'green',
                'running' => 'blue',
                'failed' => 'red',
                default => 'yellow',
            };

            $issuesColor = $scan->issues_found > 0 ? 'red' : 'green';

            $rows[] = [
                $scan->id,
                $scan->scan_type,
                $scan->started_at->format('Y-m-d H:i:s'),
                "<fg={$statusColor}>{$scan->status}</>",
                "<fg={$issuesColor}>{$scan->issues_found}</>",
                $duration,
            ];
        }

        $this->table($headers, $rows);
        $this->newLine();

        $this->info('Total scans: '.$scans->count());
        $this->info('Total issues found: '.$scans->sum('issues_found'));
        $this->newLine();

        $this->line('To view details of a specific scan, run:');
        $this->line('  <fg=yellow>php artisan perimeter:report --scan-id=ID</>');
        $this->line('To perform a new security scan, run:');
        $this->line('  <fg=yellow>php artisan perimeter:audit</>');
    }

    /**
     * Display details for a specific scan.
     */
    protected function displayScanDetails(string $scanId, string $format, ?string $output = null): void
    {
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);
        $scan = $scanClass::find($scanId);

        if (! $scan) {
            $this->error("Scan with ID {$scanId} not found.");

            return;
        }

        // Get related events
        $events = $scan->events()->orderBy('timestamp', 'desc')->get();

        // Prepare scan details
        $scanDetails = [
            'id' => $scan->id,
            'scan_type' => $scan->scan_type,
            'started_at' => $scan->started_at->format('Y-m-d H:i:s'),
            'completed_at' => $scan->completed_at ? $scan->completed_at->format('Y-m-d H:i:s') : null,
            'status' => $scan->status,
            'issues_found' => $scan->issues_found,
            'scan_details' => $scan->scan_details,
            'command' => $scan->command,
            'command_options' => $scan->command_options,
            'events' => $events->map(function ($event) {
                return $event->toReportFormat();
            })->all(),
        ];

        // Export to file if output path is specified
        if ($output && $format !== 'text') {
            if ($format === 'json') {
                file_put_contents($output, json_encode($scanDetails, JSON_PRETTY_PRINT));
            } elseif ($format === 'csv') {
                // For CSV, we'll flatten and export just the events
                $csv = fopen($output, 'w');

                // Header row
                fputcsv($csv, ['scan_id', 'timestamp', 'type', 'severity', 'description', 'details']);

                // Data rows
                foreach ($events as $event) {
                    $reportFormat = $event->toReportFormat();
                    fputcsv($csv, [
                        $scan->id,
                        $reportFormat['timestamp'],
                        $reportFormat['type'],
                        $reportFormat['severity'],
                        $reportFormat['description'],
                        json_encode($reportFormat['details'] ?? []),
                    ]);
                }

                fclose($csv);
            }

            $this->info("Scan details exported to {$output}");

            return;
        }

        // Display as JSON if requested
        if ($format === 'json') {
            $this->output->write(json_encode($scanDetails, JSON_PRETTY_PRINT));

            return;
        }

        // Default: display in text format
        $this->line('<fg=white;bg=blue>SECURITY SCAN DETAILS</>');
        $this->newLine();

        $statusColor = match ($scan->status) {
            'completed' => 'green',
            'running' => 'blue',
            'failed' => 'red',
            default => 'yellow',
        };

        $this->line("<fg=white>Scan ID:</> {$scan->id}");
        $this->line("<fg=white>Type:</> {$scan->scan_type}");
        $this->line("<fg=white>Started:</> {$scan->started_at->format('Y-m-d H:i:s')}");

        if ($scan->completed_at) {
            $this->line("<fg=white>Completed:</> {$scan->completed_at->format('Y-m-d H:i:s')}");
            $duration = $scan->started_at->diffInSeconds($scan->completed_at);
            $this->line("<fg=white>Duration:</> {$duration} seconds");
        }

        $this->line("<fg=white>Status:</> <fg={$statusColor}>{$scan->status}</>");
        $this->line("<fg=white>Issues found:</> {$scan->issues_found}");

        if ($scan->command) {
            $this->line("<fg=white>Command:</> {$scan->command}");
        }

        $this->newLine();

        if ($events->isEmpty()) {
            // If no events found in database but issues were reported, try to extract from scan_details
            if ($scan->issues_found > 0 && ! empty($scan->scan_details) && isset($scan->scan_details['issues'])) {
                $this->line('<fg=white;bg=green>ISSUES FROM SCAN ('.$scan->issues_found.')</>');
                $this->newLine();

                $headers = ['Severity', 'Type', 'Description', 'Location', 'Service', 'Scan ID', 'Timestamp'];
                $rows = [];

                foreach ($scan->scan_details['issues'] as $issue) {
                    $severity = $issue['severity'] ?? 'medium';
                    $severityColor = $this->getSeverityColor($severity);
                    $description = $issue['description'] ?? 'Unknown issue';
                    $type = $issue['type'] ?? 'system';
                    $location = $issue['location'] ?? 'N/A';
                    $service = $issue['service'] ?? ($scan->scan_type ?? 'system');
                    $timestamp = $issue['timestamp'] ?? now()->format('Y-m-d H:i:s');

                    // Extract details for display
                    $details = [];
                    if (isset($issue['details'])) {
                        $details = $issue['details'];
                    }

                    $rows[] = [
                        "<fg={$severityColor}>{$severity}</>",
                        $type,
                        $description,
                        $location,
                        $service,
                        $scan->id,
                        $timestamp,
                    ];
                }

                $this->table($headers, $rows);
                $this->newLine();
            } else {
                $this->info('No security events were recorded for this scan.');
            }
        } else {
            // Show all events in a single consolidated table
            $this->line('<fg=white;bg=green>SECURITY EVENTS ('.$events->count().')</>');
            $this->newLine();

            $headers = ['Severity', 'Type', 'Description', 'Location', 'Service', 'Scan ID', 'Timestamp'];
            $rows = [];

            foreach ($events as $event) {
                $reportFormat = $event->toReportFormat();
                $severityColor = $this->getSeverityColor($reportFormat['severity']);

                $location = $reportFormat['location'] ??
                           ($reportFormat['details']['file'] ??
                           ($reportFormat['details']['package'] ??
                           ($reportFormat['details']['process'] ?? 'N/A')));

                $service = $reportFormat['service'] ?? 'unknown';
                $scanId = $reportFormat['scan_id'] ?? 'runtime';

                $rows[] = [
                    "<fg={$severityColor}>{$reportFormat['severity']}</>",
                    $reportFormat['type'],
                    $reportFormat['description'],
                    $location,
                    $service,
                    $scanId,
                    Carbon::parse($reportFormat['timestamp'])->format('Y-m-d H:i:s'),
                ];
            }

            $this->table($headers, $rows);
            $this->newLine();
        }
    }

    /**
     * Get color for severity level.
     */
    protected function getSeverityColor(string $severity): string
    {
        switch (strtolower($severity)) {
            case 'critical':
                return 'red';
            case 'high':
                return 'bright-red';
            case 'medium':
                return 'yellow';
            case 'low':
                return 'green';
            default:
                return 'white';
        }
    }

    /**
     * Get the version command for a given service.
     */
    protected function getVersionCommand(string $serviceName): ?array
    {
        $commands = [
            'clamav' => ['clamdscan', '--version'],
            'falco' => ['falco', '--version'],
            'trivy' => ['trivy', '--version'],
            'ufw' => ['ufw', '--version'],
            'fail2ban' => ['fail2ban-client', '--version'],
        ];

        return $commands[$serviceName] ?? null;
    }
}
