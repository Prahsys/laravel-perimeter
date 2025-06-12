<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Prahsys\Perimeter\Facades\Perimeter;

class PerimeterAudit extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:audit {--format=text : Output format (text, json)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Perform a comprehensive security audit of the application';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $this->info('Starting Perimeter Security Audit...');
        $this->newLine();

        $auditResult = Perimeter::audit();
        $format = $this->option('format');

        if ($format === 'json') {
            $this->output->write(json_encode($auditResult->toArray(), JSON_PRETTY_PRINT));
            return 0;
        }

        // Display security score
        $score = $auditResult->getSecurityScore();
        $scoreColor = $this->getScoreColor($score);
        
        $this->line('<fg=white;bg=default>Security Score:</> <fg=' . $scoreColor . '>' . $score . '%</>');
        $this->newLine();
        
        // Display critical issues
        $criticalIssues = $auditResult->getCriticalIssues();
        
        if (!empty($criticalIssues)) {
            $this->line('<fg=white;bg=red>CRITICAL SECURITY ISSUES</>');
            $this->newLine();
            
            $headers = ['Type', 'Severity', 'Description', 'Location'];
            $rows = [];
            
            foreach ($criticalIssues as $issue) {
                $rows[] = [
                    $issue['type'],
                    $issue['severity'],
                    $issue['description'],
                    $issue['location'] ?? 'N/A',
                ];
            }
            
            $this->table($headers, $rows);
            $this->newLine();
        }
        
        // Display scan results summary
        $malwareResults = $auditResult->getMalwareResults();
        $vulnerabilityResults = $auditResult->getVulnerabilityResults();
        $behavioralResults = $auditResult->getBehavioralResults();
        
        $this->line('<fg=white;bg=blue>SCAN RESULTS SUMMARY</>');
        $this->newLine();
        
        $this->line('Malware Scans: ' . count($malwareResults) . ' issues found');
        $this->line('Vulnerability Scans: ' . count($vulnerabilityResults) . ' issues found');
        $this->line('Behavioral Analysis: ' . count($behavioralResults) . ' issues found');
        $this->newLine();
        
        if ($auditResult->hasIssues()) {
            $this->line('Run <fg=yellow>php artisan perimeter:report</> for detailed reports');
        } else {
            $this->info('No security issues found. System appears secure.');
        }

        return 0;
    }

    /**
     * Get color for security score.
     *
     * @param int $score
     * @return string
     */
    protected function getScoreColor(int $score): string
    {
        if ($score >= 90) {
            return 'green';
        } elseif ($score >= 70) {
            return 'yellow';
        } else {
            return 'red';
        }
    }
}