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
        public array $details = [],
        public ?bool $functional = null  // Service can operate even if daemon not running
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
     * Check if the service is healthy (enabled, installed, configured, and functional).
     * Services can be healthy even if daemon is not running if they can operate in alternative mode.
     * Disabled services are considered N/A for health status.
     */
    public function isHealthy(): bool
    {
        if (! $this->enabled) {
            return false;
        }

        // Basic requirements: installed and configured
        if (! $this->installed || ! $this->configured) {
            return false;
        }

        // If functional status is explicitly set, use that instead of running status
        // This allows services like ClamAV to be healthy in direct mode even when daemon isn't running
        if ($this->functional !== null) {
            return $this->functional;
        }

        // Default behavior: require daemon to be running
        return $this->running;
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
