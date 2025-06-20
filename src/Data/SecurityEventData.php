<?php

namespace Prahsys\Perimeter\Data;

use DateTime;
use DateTimeInterface;
use Prahsys\Perimeter\Contracts\SecurityEventInterface;
use Spatie\LaravelData\Data;

class SecurityEventData extends Data implements SecurityEventInterface
{
    /**
     * Create a new SecurityEventData instance.
     *
     * @param  \DateTimeInterface|string|null  $timestamp
     */
    public function __construct(
        public DateTimeInterface|string $timestamp,
        public string $type,
        public string $severity,
        public string $description,
        public ?string $location = null,
        public string|int|null $user = null,
        public ?string $service = null,
        public ?int $scan_id = null,
        public array $details = []
    ) {
        // Ensure timestamp is a DateTimeInterface
        if (! ($this->timestamp instanceof DateTimeInterface)) {
            $this->timestamp = $this->parseTimestamp($this->timestamp);
        }
    }

    /**
     * Parse the timestamp.
     */
    protected function parseTimestamp(DateTimeInterface|string|null $timestamp): DateTimeInterface
    {
        if ($timestamp instanceof DateTimeInterface) {
            return $timestamp;
        }

        if (is_string($timestamp)) {
            try {
                return new DateTime($timestamp);
            } catch (\Exception $e) {
                // Fall back to current time if parsing fails
                return now();
            }
        }

        // Default to current time
        return now();
    }

    /**
     * Get the event timestamp.
     */
    public function getTimestamp(): DateTimeInterface
    {
        return $this->timestamp;
    }

    /**
     * Get the event type.
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Get the event severity.
     */
    public function getSeverity(): string
    {
        return $this->severity;
    }

    /**
     * Get the event description.
     */
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * Get the event location.
     */
    public function getLocation(): ?string
    {
        return $this->location;
    }

    /**
     * Get the user associated with the event.
     */
    public function getUser(): string|int|null
    {
        return $this->user;
    }

    /**
     * Get the service that generated the event.
     */
    public function getService(): ?string
    {
        return $this->service;
    }

    /**
     * Get the scan ID associated with the event.
     */
    public function getScanId(): ?int
    {
        return $this->scan_id;
    }

    /**
     * Get the event details.
     */
    public function getDetails(): array
    {
        return $this->details;
    }

    /**
     * Convert the event to an array.
     */
    public function toArray(): array
    {
        $data = parent::toArray();

        // Ensure timestamp is formatted correctly
        $data['timestamp'] = $this->timestamp->format('Y-m-d\TH:i:s\+00:00');

        return $data;
    }

    /**
     * Convert the event to a model array format.
     */
    public function toModelArray(): array
    {
        return [
            'timestamp' => $this->timestamp,
            'type' => $this->type,
            'severity' => $this->severity,
            'description' => $this->description,
            'location' => $this->location,
            'user' => $this->user,
            'service' => $this->service,
            'scan_id' => $this->scan_id,
            'details' => $this->details,
        ];
    }
}
