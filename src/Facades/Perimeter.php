<?php

namespace Prahsys\Perimeter\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Prahsys\Perimeter\ScanResult scan(mixed $file)
 * @method static void monitor(?int $duration = null)
 * @method static \Prahsys\Perimeter\AuditResult audit()
 * @method static \Prahsys\Perimeter\ReportBuilder report()
 * @method static \Prahsys\Perimeter\Perimeter onThreatDetected(callable $callback)
 * @method static \Prahsys\Perimeter\Perimeter onAnomalyDetected(callable $callback)
 * @method static \Prahsys\Perimeter\Perimeter onVulnerabilityFound(callable $callback)
 *
 * @see \Prahsys\Perimeter\Perimeter
 */
class Perimeter extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'perimeter';
    }
}