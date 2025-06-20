<?php

namespace Prahsys\Perimeter\Contracts;

interface SystemAuditInterface extends SecurityServiceInterface
{
    /**
     * Get the last time an audit was run.
     *
     * @return int Unix timestamp or 0 if never run
     */
    public function getLastAuditTime(): int;

    /**
     * Get a count of issues by severity.
     */
    public function getIssueCountBySeverity(): array;
}
