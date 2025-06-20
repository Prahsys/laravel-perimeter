<?php

namespace Prahsys\Perimeter\Data;

use Spatie\LaravelData\Data;

class ServiceStatusData extends Data
{
    /**
     * Create a new ServiceStatusData instance.
     */
    public function __construct(
        public string $name,
        public bool $enabled,
        public bool $installed,
        public bool $configured,
        public bool $running = false,
        public string $message = '',
        public array $details = []
    ) {}

    /**
     * Get the service name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Check if the service is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Check if the service is installed on the system.
     */
    public function isInstalled(): bool
    {
        return $this->installed;
    }

    /**
     * Check if the service is properly configured.
     */
    public function isConfigured(): bool
    {
        return $this->configured;
    }

    /**
     * Check if the service is currently running.
     */
    public function isRunning(): bool
    {
        return $this->running;
    }

    /**
     * Get the status message.
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * Get additional status details.
     */
    public function getDetails(): array
    {
        return $this->details;
    }

    /**
     * Check if the service is healthy (enabled, installed, configured, and running).
     * Disabled services are considered N/A for health status.
     */
    public function isHealthy(): bool
    {
        // For enabled services, they must be installed, configured, and running
        return $this->enabled && $this->installed && $this->configured && $this->running;
    }

    /**
     * Check if the service health status is applicable.
     * For disabled services, health status is not applicable.
     */
    public function isHealthStatusApplicable(): bool
    {
        return $this->enabled;
    }
}
