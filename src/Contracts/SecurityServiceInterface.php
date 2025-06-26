<?php

namespace Prahsys\Perimeter\Contracts;

use Illuminate\Console\OutputStyle;
use Prahsys\Perimeter\Data\ServiceStatusData;

interface SecurityServiceInterface
{
    /**
     * Check if the service is enabled in configuration.
     */
    public function isEnabled(): bool;

    /**
     * Check if the service is installed on the system.
     */
    public function isInstalled(): bool;

    /**
     * Check if the service is properly configured.
     */
    public function isConfigured(): bool;

    /**
     * Install or update the service.
     */
    public function install(array $options = []): bool;

    /**
     * Get the current configuration.
     */
    public function getConfig(): array;

    /**
     * Set the configuration.
     */
    public function setConfig(array $config): void;

    /**
     * Get the current status of the service.
     */
    public function getStatus(): ServiceStatusData;

    /**
     * Run audit checks specific to this service and output results.
     *
     * @param  \Illuminate\Console\OutputStyle|null  $output  Optional output interface to print to
     * @param  \Prahsys\Perimeter\Services\ArtifactManager|null  $artifactManager  Optional artifact manager for saving audit data
     * @return \Prahsys\Perimeter\Data\ServiceAuditData Audit results with any issues found
     */
    public function runServiceAudit(?OutputStyle $output = null, ?\Prahsys\Perimeter\Services\ArtifactManager $artifactManager = null): \Prahsys\Perimeter\Data\ServiceAuditData;

    /**
     * Convert a service-specific result to a SecurityEventData instance.
     *
     * @param  array  $data  Service-specific result data (may include 'scan_id' key)
     */
    public function resultToSecurityEventData(array $data): \Prahsys\Perimeter\Data\SecurityEventData;

    /**
     * Get the service name for this security service.
     *
     * @return string The name of the service
     */
    public function getServiceName(): string;
}
