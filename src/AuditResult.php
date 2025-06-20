<?php

namespace Prahsys\Perimeter;

class AuditResult
{
    /**
     * Create a new audit result instance.
     *
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
     */
    public function getMalwareResults(): array
    {
        return $this->malwareResults;
    }

    /**
     * Get the vulnerability scan results.
     */
    public function getVulnerabilityResults(): array
    {
        return $this->vulnerabilityResults;
    }

    /**
     * Get the behavioral analysis results.
     */
    public function getBehavioralResults(): array
    {
        return $this->behavioralResults;
    }

    /**
     * Get all results combined.
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
     * Get a summary of security findings.
     *
     * @return array An array with counts of findings by type and severity
     */
    public function getSecuritySummary(): array
    {
        // Count issues by severity
        $severityCounts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        // Count malware findings
        foreach ($this->malwareResults as $result) {
            $severity = strtolower($result['severity'] ?? 'critical');
            $severityCounts[$severity]++;
        }

        // Count vulnerability findings
        foreach ($this->vulnerabilityResults as $result) {
            $severity = strtolower($result['severity'] ?? 'medium');
            $severityCounts[$severity]++;
        }

        // Count behavioral findings
        foreach ($this->behavioralResults as $result) {
            $severity = strtolower($result['priority'] ?? $result['severity'] ?? 'medium');
            $severityCounts[$severity]++;
        }

        return [
            'total_issues' => count($this->malwareResults) + count($this->vulnerabilityResults) + count($this->behavioralResults),
            'by_severity' => $severityCounts,
            'by_type' => [
                'malware' => count($this->malwareResults),
                'vulnerabilities' => count($this->vulnerabilityResults),
                'behavioral' => count($this->behavioralResults),
            ],
        ];
    }

    /**
     * Check if the audit detected any issues.
     */
    public function hasIssues(): bool
    {
        return ! empty($this->malwareResults) ||
               ! empty($this->vulnerabilityResults) ||
               ! empty($this->behavioralResults);
    }

    /**
     * Get the most critical issues first.
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
                'service' => $result['service'] ?? 'clamav',
            ];
        }

        // Add critical and high vulnerabilities
        foreach ($this->vulnerabilityResults as $result) {
            if ($result['severity'] === 'CRITICAL' || $result['severity'] === 'HIGH') {
                $issues[] = [
                    'type' => 'vulnerability',
                    'severity' => strtolower($result['severity']),
                    'description' => $result['title'],
                    'location' => $result['packageName'].'@'.$result['version'],
                    'service' => $result['service'] ?? 'trivy',
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
                    'location' => $result['process'] ?? null,
                    'service' => $result['service'] ?? 'falco',
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
     */
    public function toArray(): array
    {
        return [
            'timestamp' => now()->toIso8601String(),
            'summary' => $this->getSecuritySummary(),
            'criticalIssues' => $this->getCriticalIssues(),
            'results' => $this->getAllResults(),
        ];
    }
}
