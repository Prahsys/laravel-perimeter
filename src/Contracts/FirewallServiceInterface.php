<?php

namespace Prahsys\Perimeter\Contracts;

interface FirewallServiceInterface extends SecurityServiceInterface
{
    /**
     * Get recent firewall events.
     */
    public function getRecentEvents(int $limit = 10): array;

    /**
     * Reset the firewall to default configuration.
     */
    public function reset(): bool;
}
