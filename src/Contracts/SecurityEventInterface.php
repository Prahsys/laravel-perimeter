<?php

namespace Prahsys\Perimeter\Contracts;

interface SecurityEventInterface
{
    /**
     * Get the event timestamp.
     */
    public function getTimestamp(): \DateTimeInterface;

    /**
     * Get the event type.
     */
    public function getType(): string;

    /**
     * Get the event severity.
     */
    public function getSeverity(): string;

    /**
     * Get the event description.
     */
    public function getDescription(): string;

    /**
     * Get the event location.
     */
    public function getLocation(): ?string;

    /**
     * Get the user associated with the event.
     */
    public function getUser(): string|int|null;

    /**
     * Get the service that generated the event.
     */
    public function getService(): ?string;

    /**
     * Get the scan ID associated with the event.
     */
    public function getScanId(): ?int;

    /**
     * Get the event details.
     */
    public function getDetails(): array;

    /**
     * Convert the event to an array.
     */
    public function toArray(): array;
}
