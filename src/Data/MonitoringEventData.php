<?php

namespace Prahsys\Perimeter\Data;

use DateTimeInterface;
use Spatie\LaravelData\Data;

class MonitoringEventData extends Data
{
    /**
     * Create a new MonitoringEventData instance.
     */
    public function __construct(
        public string $service,
        public string $event_type,
        public string $severity,
        public string $description,
        public DateTimeInterface $timestamp,
        public ?string $source = null,
        public ?string $user = null,
        public array $details = []
    ) {}

    /**
     * Create a new instance from a SecurityEventData object.
     */
    public static function fromSecurityEventData(string $service, SecurityEventData $eventData): self
    {
        return new self(
            service: $service,
            event_type: $eventData->type,
            severity: $eventData->severity,
            description: $eventData->description,
            timestamp: $eventData->timestamp,
            source: $eventData->location,
            user: $eventData->user,
            details: $eventData->details
        );
    }

    /**
     * Get a color code for the severity level for console output.
     */
    public function getSeverityColor(): string
    {
        return match (strtolower($this->severity)) {
            'emergency', 'critical', 'high' => 'red',
            'warning', 'medium' => 'yellow',
            'info', 'low' => 'green',
            default => 'white',
        };
    }
}
