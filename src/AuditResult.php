<?php

namespace Prahsys\Perimeter;

class AuditResult
{
    /**
     * Create a new audit result instance.
     *
     * @param array $malwareResults
     * @param array $vulnerabilityResults
     * @param array $behavioralResults
     * @return void
     */
    public function __construct(
        protected array $malwareResults = [],
        protected array $vulnerabilityResults = [],
        protected array $behavioralResults = []
    ) {
        //
    }

    /**
     * Get the malware scan results.
     *
     * @return array
     */
    public function getMalwareResults(): array
    {
        return $this->malwareResults;
    }

    /**
     * Get the vulnerability scan results.
     *
     * @return array
     */
    public function getVulnerabilityResults(): array
    {
        return $this->vulnerabilityResults;
    }

    /**
     * Get the behavioral analysis results.
     *
     * @return array
     */
    public function getBehavioralResults(): array
    {
        return $this->behavioralResults;
    }

    /**
     * Get all results combined.
     *
     * @return array
     */
    public function getAllResults(): array
    {
        return [
            'malware' => $this->malwareResults,
            'vulnerabilities' => $this->vulnerabilityResults,
            'behavioral' => $this->behavioralResults,
        ];
    }

    /**
     * Calculate a security score from 0-100.
     *
     * @return int
     */
    public function getSecurityScore(): int
    {
        $score = 100;

        // Deduct for malware findings
        $malwareDeduction = count($this->malwareResults) * 25;
        $score -= min($malwareDeduction, 50);

        // Deduct for critical and high vulnerabilities
        $criticalVulns = 0;
        $highVulns = 0;

        foreach ($this->vulnerabilityResults as $result) {
            if ($result['severity'] === 'CRITICAL') {
                $criticalVulns++;
            } elseif ($result['severity'] === 'HIGH') {
                $highVulns++;
            }
        }

        $vulnDeduction = ($criticalVulns * 10) + ($highVulns * 5);
        $score -= min($vulnDeduction, 40);

        // Deduct for behavioral anomalies
        $behavioralDeduction = count($this->behavioralResults) * 5;
        $score -= min($behavioralDeduction, 30);

        return max(0, $score);
    }

    /**
     * Check if the audit detected any issues.
     *
     * @return bool
     */
    public function hasIssues(): bool
    {
        return !empty($this->malwareResults) ||
               !empty($this->vulnerabilityResults) ||
               !empty($this->behavioralResults);
    }

    /**
     * Get the most critical issues first.
     *
     * @param int $limit
     * @return array
     */
    public function getCriticalIssues(int $limit = 5): array
    {
        $issues = [];

        // Add malware as highest priority
        foreach ($this->malwareResults as $result) {
            $issues[] = [
                'type' => 'malware',
                'severity' => 'critical',
                'description' => $result['threat'],
                'location' => $result['file'],
            ];
        }

        // Add critical and high vulnerabilities
        foreach ($this->vulnerabilityResults as $result) {
            if ($result['severity'] === 'CRITICAL' || $result['severity'] === 'HIGH') {
                $issues[] = [
                    'type' => 'vulnerability',
                    'severity' => strtolower($result['severity']),
                    'description' => $result['title'],
                    'location' => $result['packageName'] . '@' . $result['version'],
                    'cve' => $result['cve'] ?? null,
                ];
            }
        }

        // Add critical behavioral issues
        foreach ($this->behavioralResults as $result) {
            if ($result['priority'] === 'critical') {
                $issues[] = [
                    'type' => 'behavioral',
                    'severity' => $result['priority'],
                    'description' => $result['description'],
                    'process' => $result['process'] ?? null,
                ];
            }
        }

        // Sort by severity (critical first)
        usort($issues, function ($a, $b) {
            if ($a['severity'] === $b['severity']) {
                return 0;
            }
            return ($a['severity'] === 'critical') ? -1 : 1;
        });

        // Return limited number
        return array_slice($issues, 0, $limit);
    }

    /**
     * Convert to array representation.
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'score' => $this->getSecurityScore(),
            'timestamp' => now()->toIso8601String(),
            'issues' => [
                'malware' => count($this->malwareResults),
                'vulnerabilities' => count($this->vulnerabilityResults),
                'behavioral' => count($this->behavioralResults),
            ],
            'criticalIssues' => $this->getCriticalIssues(),
            'results' => $this->getAllResults(),
        ];
    }
}