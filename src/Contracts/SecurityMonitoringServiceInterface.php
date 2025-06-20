<?php

namespace Prahsys\Perimeter\Contracts;

interface SecurityMonitoringServiceInterface extends SecurityServiceInterface
{
    /**
     * Start monitoring with the service.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool;

    /**
     * Stop monitoring with the service.
     */
    public function stopMonitoring(): bool;

    /**
     * Get recent security events from the service.
     *
     * @param  int  $limit  Maximum number of events to return
     * @return array<\Prahsys\Perimeter\Data\SecurityEventData>
     */
    public function getMonitoringEvents(int $limit = 10): array;

    /**
     * Check if the service is currently monitoring.
     */
    public function isMonitoring(): bool;

    /**
     * Get monitoring options.
     */
    public function getMonitoringOptions(): array;
}
