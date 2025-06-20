<?php

namespace Prahsys\Perimeter\Services;

use Prahsys\Perimeter\ReportBuilder;

class ReportingService
{
    /**
     * The service manager instance.
     *
     * @var \Prahsys\Perimeter\Services\ServiceManager|null
     */
    protected $serviceManager = null;

    /**
     * Create a new reporting service instance.
     *
     * @return void
     */
    public function __construct(protected array $config = [])
    {
        // Get the service manager from the container
        $this->serviceManager = app()->make('Prahsys\Perimeter\Services\ServiceManager');
    }

    /**
     * Create a new report builder instance.
     */
    public function createReportBuilder(): ReportBuilder
    {
        $builder = new ReportBuilder;

        // Pass the service manager to the builder
        $builder->setServiceManager($this->serviceManager);

        return $builder;
    }

    /**
     * Get supported export formats.
     */
    public function getSupportedFormats(): array
    {
        return $this->config['formats'] ?? ['json', 'csv'];
    }

    /**
     * Get data retention period in days.
     */
    public function getRetentionDays(): int
    {
        return $this->config['retention_days'] ?? 90;
    }
}
