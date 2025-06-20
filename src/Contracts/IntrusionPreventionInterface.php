<?php

namespace Prahsys\Perimeter\Contracts;

interface IntrusionPreventionInterface extends SecurityServiceInterface
{
    /**
     * Get a list of jails (rule sets).
     */
    public function getJails(): array;

    /**
     * Get detailed status for a specific jail.
     */
    public function getJailStatus(string $jail): array;

    /**
     * Get currently banned IPs.
     */
    public function getBannedIPs(?string $jail = null): array;

    /**
     * Unban a specific IP address.
     */
    public function unbanIP(string $ip, ?string $jail = null): bool;

    /**
     * Get recent security events.
     */
    public function getRecentEvents(int $limit = 10): array;
}
