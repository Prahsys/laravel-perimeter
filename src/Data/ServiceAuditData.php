<?php

namespace Prahsys\Perimeter\Data;

class ServiceAuditData
{
    /**
     * The service identifier (e.g., "clamav", "ufw")
     */
    public string $service;

    /**
     * The human-readable service name
     */
    public string $displayName;

    /**
     * Array of SecurityEventData objects
     */
    public array $issues = [];

    /**
     * Status of the audit (e.g., "secure", "issues_found", "disabled", "not_installed", "not_configured")
     */
    public string $status = 'secure';

    /**
     * Additional metadata specific to the service
     */
    public array $metadata = [];

    /**
     * Create a new ServiceAuditData instance.
     */
    public function __construct()
    {
        // Default empty constructor for flexible initialization
    }

    /**
     * Convert the DTO to an array.
     */
    public function toArray(): array
    {
        return [
            'service' => $this->service,
            'display_name' => $this->displayName,
            'issues' => array_map(
                fn ($issue) => $issue instanceof SecurityEventData ? $issue->toArray() : $issue,
                $this->issues
            ),
            'status' => $this->status,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Create a new instance from an array.
     */
    public static function fromArray(array $data): self
    {
        $instance = new self;
        $instance->service = $data['service'] ?? '';
        $instance->displayName = $data['display_name'] ?? '';
        $instance->status = $data['status'] ?? 'secure';
        $instance->metadata = $data['metadata'] ?? [];

        // Map issues to SecurityEventData objects if they're not already
        $instance->issues = [];
        foreach ($data['issues'] ?? [] as $issue) {
            if ($issue instanceof SecurityEventData) {
                $instance->issues[] = $issue;
            } elseif (is_array($issue)) {
                $instance->issues[] = SecurityEventData::fromArray($issue);
            }
        }

        return $instance;
    }

    /**
     * Check if the audit has any issues.
     */
    public function hasIssues(): bool
    {
        return ! empty($this->issues);
    }

    /**
     * Get the count of issues by severity.
     */
    public function getIssueCountBySeverity(): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($this->issues as $issue) {
            $severity = $issue instanceof SecurityEventData
                ? $issue->severity
                : ($issue['severity'] ?? 'info');

            $counts[$severity] = ($counts[$severity] ?? 0) + 1;
        }

        return $counts;
    }
}
