<?php

namespace Prahsys\Perimeter;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\ReportingService;
use Prahsys\Perimeter\Services\TrivyService;

class Perimeter
{
    /**
     * Event callbacks
     *
     * @var array
     */
    protected $callbacks = [
        'threatDetected' => [],
        'anomalyDetected' => [],
        'vulnerabilityFound' => [],
    ];

    /**
     * Create a new Perimeter instance.
     *
     * @param \Prahsys\Perimeter\Services\ClamAVService $clamAVService
     * @param \Prahsys\Perimeter\Services\FalcoService $falcoService
     * @param \Prahsys\Perimeter\Services\TrivyService $trivyService
     * @param \Prahsys\Perimeter\Services\ReportingService $reportingService
     * @return void
     */
    public function __construct(
        protected ClamAVService $clamAVService,
        protected FalcoService $falcoService,
        protected TrivyService $trivyService,
        protected ReportingService $reportingService
    ) {
        //
    }

    /**
     * Scan a file for threats.
     *
     * @param \Illuminate\Http\UploadedFile|string $file
     * @return \Prahsys\Perimeter\ScanResult
     */
    public function scan($file)
    {
        if ($file instanceof UploadedFile) {
            $filePath = $file->path();
        } else {
            $filePath = $file;
        }

        $result = $this->clamAVService->scanFile($filePath);

        if ($result->hasThreat()) {
            $this->triggerCallbacks('threatDetected', $result);
            $this->logThreat($result);
        }

        return $result;
    }

    /**
     * Start real-time monitoring.
     *
     * @param int|null $duration Duration in seconds, or null for indefinite
     * @return void
     */
    public function monitor(?int $duration = null)
    {
        $this->falcoService->startMonitoring($duration);
    }

    /**
     * Perform a comprehensive security audit.
     *
     * @return \Prahsys\Perimeter\AuditResult
     */
    public function audit()
    {
        // Run malware scans
        $malwareResults = $this->clamAVService->scanPaths(
            config('perimeter.clamav.scan_paths', [base_path()]),
            config('perimeter.clamav.exclude_patterns', [])
        );

        // Run vulnerability scans
        $vulnerabilityResults = $this->trivyService->scanDependencies();

        // Combine results
        $auditResult = new AuditResult(
            $malwareResults,
            $vulnerabilityResults,
            []  // Behavioral results are added separately when using real-time monitoring
        );

        return $auditResult;
    }

    /**
     * Create a report builder instance.
     *
     * @return \Prahsys\Perimeter\ReportBuilder
     */
    public function report()
    {
        return $this->reportingService->createReportBuilder();
    }

    /**
     * Register a callback for when a threat is detected.
     *
     * @param callable $callback
     * @return $this
     */
    public function onThreatDetected(callable $callback)
    {
        $this->callbacks['threatDetected'][] = $callback;

        return $this;
    }

    /**
     * Register a callback for when an anomaly is detected.
     *
     * @param callable $callback
     * @return $this
     */
    public function onAnomalyDetected(callable $callback)
    {
        $this->callbacks['anomalyDetected'][] = $callback;

        return $this;
    }

    /**
     * Register a callback for when a vulnerability is found.
     *
     * @param callable $callback
     * @return $this
     */
    public function onVulnerabilityFound(callable $callback)
    {
        $this->callbacks['vulnerabilityFound'][] = $callback;

        return $this;
    }

    /**
     * Trigger registered callbacks for an event.
     *
     * @param string $event
     * @param mixed $data
     * @return void
     */
    protected function triggerCallbacks(string $event, $data)
    {
        foreach ($this->callbacks[$event] as $callback) {
            call_user_func($callback, $data);
        }
    }

    /**
     * Log a threat with the appropriate severity level.
     *
     * @param \Prahsys\Perimeter\ScanResult $result
     * @return void
     */
    protected function logThreat($result)
    {
        $threat = $result->getThreat();
        $severity = $this->getLogLevel($threat);
        $channels = config('perimeter.logging.channels', ['stack']);

        foreach ($channels as $channel) {
            Log::channel($channel)->log($severity, "Security threat detected: {$threat}", [
                'type' => 'malware',
                'file' => $result->getFilePath(),
                'threat' => $threat,
                'timestamp' => now()->toIso8601String(),
            ]);
        }
    }

    /**
     * Get the appropriate log level for a threat.
     *
     * @param string $threat
     * @return string
     */
    protected function getLogLevel(string $threat)
    {
        $lowerThreat = strtolower($threat);
        
        // Map threats to configured log levels
        $malwareLevels = config('perimeter.logging.levels.malware', [
            'ransomware' => 'emergency',
            'trojan' => 'critical',
            'virus' => 'critical',
            'adware' => 'warning',
            'test' => 'info',
        ]);

        // Check for keywords in the threat name
        foreach ($malwareLevels as $keyword => $level) {
            if (str_contains($lowerThreat, $keyword)) {
                return $level;
            }
        }

        // Default to critical if we can't determine the type
        return 'critical';
    }
}