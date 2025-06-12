<?php

namespace Prahsys\Perimeter\Commands;

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
                            {--from= : Start date for filtering events (Y-m-d format)}
                            {--to= : End date for filtering events (Y-m-d format)}
                            {--type= : Filter by event type (comma-separated: malware,vulnerability,behavioral)}
                            {--severity= : Filter by severity (comma-separated: critical,high,medium,low)}
                            {--format=text : Output format (text, json, csv)}
                            {--compliance= : Generate compliance report for specified framework (soc2, pci, hipaa)}
                            {--output= : Output file path}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate security reports';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        // Check if we should generate a compliance report
        $compliance = $this->option('compliance');
        if ($compliance) {
            return $this->generateComplianceReport($compliance);
        }

        // Regular security event report
        $from = $this->option('from');
        $to = $this->option('to');
        $type = $this->option('type');
        $severity = $this->option('severity');
        $format = $this->option('format');
        $output = $this->option('output');

        $report = Perimeter::report();

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

        // Get the report data
        $events = $report->get();

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
     *
     * @param array $events
     * @return void
     */
    protected function displayTextReport(array $events): void
    {
        if (empty($events)) {
            $this->info('No security events found matching the criteria.');
            return;
        }

        $this->line('<fg=white;bg=blue>SECURITY EVENTS REPORT</>');
        $this->newLine();

        // Group events by type
        $groupedEvents = [];
        foreach ($events as $event) {
            $type = $event['type'] ?? 'unknown';
            $groupedEvents[$type][] = $event;
        }

        // Display events by type
        foreach ($groupedEvents as $type => $typeEvents) {
            $this->line('<fg=white;bg=green>' . strtoupper($type) . ' EVENTS (' . count($typeEvents) . ')</>');
            $this->newLine();

            $headers = ['Timestamp', 'Severity', 'Description', 'Details'];
            $rows = [];

            foreach ($typeEvents as $event) {
                $severityColor = $this->getSeverityColor($event['severity']);
                $details = json_encode($event['details'] ?? [], JSON_PRETTY_PRINT);
                $details = strlen($details) > 50 ? substr($details, 0, 47) . '...' : $details;

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
     * Generate a compliance report.
     *
     * @param string $framework
     * @return int
     */
    protected function generateComplianceReport(string $framework): int
    {
        $this->info("Generating {$framework} compliance report...");
        $this->newLine();

        $report = app('perimeter.reporting')->generateComplianceReport($framework);
        $format = $this->option('format');
        $output = $this->option('output');

        // Export to file if output path is specified
        if ($output && $format === 'json') {
            file_put_contents($output, json_encode($report, JSON_PRETTY_PRINT));
            $this->info("Compliance report exported to {$output}");
            return 0;
        }

        // Display report based on format
        if ($format === 'json') {
            $this->output->write(json_encode($report, JSON_PRETTY_PRINT));
            return 0;
        }

        // Text format (default)
        $this->displayComplianceReport($report);

        return 0;
    }

    /**
     * Display compliance report in text format.
     *
     * @param array $report
     * @return void
     */
    protected function displayComplianceReport(array $report): void
    {
        $framework = strtoupper($report['framework']);
        $timestamp = $report['timestamp'];
        $summary = $report['summary'] ?? [];

        $this->line("<fg=white;bg=blue>{$framework} COMPLIANCE REPORT</>");
        $this->line("Generated: {$timestamp}");
        $this->newLine();

        // Display summary
        if (!empty($summary)) {
            $this->line('<fg=white;bg=green>SUMMARY</>');
            $this->newLine();

            foreach ($summary as $key => $value) {
                $this->line(ucfirst(str_replace('_', ' ', $key)) . ': ' . $value);
            }

            $this->newLine();
        }

        // Display requirements
        if (isset($report['requirements'])) {
            $this->line('<fg=white;bg=green>REQUIREMENTS</>');
            $this->newLine();

            $this->displayRequirements($report['requirements']);
        }
    }

    /**
     * Display compliance requirements recursively.
     *
     * @param array $requirements
     * @param string $prefix
     * @return void
     */
    protected function displayRequirements(array $requirements, string $prefix = ''): void
    {
        foreach ($requirements as $key => $value) {
            $name = ucfirst(str_replace('_', ' ', $key));

            if (is_array($value) && isset($value['status'])) {
                $status = $value['status'];
                $details = $value['details'] ?? '';
                $statusColor = $this->getStatusColor($status);

                $this->line("{$prefix}{$name}: <fg={$statusColor}>{$status}</> - {$details}");
            } elseif (is_array($value)) {
                $this->line("{$prefix}<fg=yellow>{$name}:</>");
                $this->displayRequirements($value, $prefix . '  ');
            } else {
                $this->line("{$prefix}{$name}: {$value}");
            }
        }
    }

    /**
     * Get color for severity level.
     *
     * @param string $severity
     * @return string
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
     * Get color for compliance status.
     *
     * @param string $status
     * @return string
     */
    protected function getStatusColor(string $status): string
    {
        switch ($status) {
            case 'compliant':
                return 'green';
            case 'review_needed':
                return 'yellow';
            case 'non_compliant':
                return 'red';
            case 'not_applicable':
                return 'blue';
            default:
                return 'white';
        }
    }
}