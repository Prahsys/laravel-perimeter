<?php

namespace Prahsys\Perimeter;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Models\SecurityEvent;
use Prahsys\Perimeter\Services\ReportingService;

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
     * @return void
     */
    public function __construct(
        protected Services\ServiceManager $serviceManager,
        protected ReportingService $reportingService
    ) {
        // Service manager is already set up in the ReportingService constructor
    }

    /**
     * Get the primary scanner service.
     *
     * @return \Prahsys\Perimeter\Contracts\ScannerServiceInterface
     */
    protected function getScannerService()
    {
        $scanners = $this->serviceManager->getScanners();

        return $scanners->first();
    }

    /**
     * Get the primary monitor service.
     *
     * @return \Prahsys\Perimeter\Contracts\MonitorServiceInterface
     */
    protected function getMonitorService()
    {
        $monitors = $this->serviceManager->getMonitors();

        return $monitors->first();
    }

    /**
     * Get the primary vulnerability scanner service.
     *
     * @return \Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface
     */
    protected function getVulnerabilityScanner()
    {
        $scanners = $this->serviceManager->getVulnerabilityScanners();

        return $scanners->first();
    }

    /**
     * Get the primary firewall service.
     *
     * @return \Prahsys\Perimeter\Contracts\FirewallServiceInterface
     */
    protected function getFirewallService()
    {
        $firewalls = $this->serviceManager->getFirewalls();

        return $firewalls->first();
    }

    /**
     * Get the primary intrusion prevention service.
     *
     * @return \Prahsys\Perimeter\Contracts\IntrusionPreventionInterface
     */
    protected function getIntrusionPreventionService()
    {
        $services = $this->serviceManager->getIntrusionPreventionServices();

        return $services->first();
    }

    /**
     * Get the primary system audit service.
     *
     * @return \Prahsys\Perimeter\Contracts\SystemAuditInterface
     */
    protected function getSystemAuditService()
    {
        $services = $this->serviceManager->getSystemAuditServices();

        return $services->first();
    }

    /**
     * Scan a file for threats.
     *
     * @param  \Illuminate\Http\UploadedFile|string  $file
     * @return \Prahsys\Perimeter\ScanResult
     */
    public function scan($file)
    {
        $scannerService = $this->getScannerService();

        if (! $scannerService) {
            throw new \RuntimeException('No scanner service available');
        }

        if ($file instanceof UploadedFile) {
            $filePath = $file->path();
        } else {
            $filePath = $file;
        }

        // Start a new scan record
        $scan = null;
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);
        $scan = $scanClass::start('malware', 'perimeter:scan', ['file' => $filePath]);

        $result = $scannerService->scanFile($filePath);

        if ($result->hasThreat()) {
            $this->triggerCallbacks('threatDetected', $result);
            $this->logThreat($result);

            // Create event data
            $data = [
                'timestamp' => now(),
                'severity' => $this->getThreatSeverity($result->getThreat()),
                'threat' => $result->getThreat(),
                'file' => $filePath,
            ];

            // Add file hash if available
            if (method_exists($result, 'getFileHash')) {
                $data['hash'] = $result->getFileHash();
            }

            $data['scan_id'] = $scan !== null ? $scan->id : null;
            $eventData = $scannerService->resultToSecurityEventData($data);

            // Store in database
            $this->storeSecurityEvent($eventData);

            // Complete the scan if storage is enabled
            if ($scan !== null) {
                $scan->complete(1, [
                    'threat' => $result->getThreat(),
                    'file' => $filePath,
                ]);
            }
        } elseif ($scan !== null) {
            // Complete the scan with no issues
            $scan->complete(0);
        }

        return $result;
    }

    /**
     * Start real-time monitoring.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     * @return void
     */
    public function monitor(?int $duration = null)
    {
        $monitorService = $this->getMonitorService();
        if (! $monitorService) {
            throw new \RuntimeException('No monitor service available');
        }
        $monitorService->startMonitoring($duration);
    }

    /**
     * Perform a comprehensive security audit.
     *
     * @return \Prahsys\Perimeter\AuditResult
     */
    public function audit()
    {
        // Start a new scan record
        $scanClass = config('perimeter.storage.models.security_scan', \Prahsys\Perimeter\Models\SecurityScan::class);
        $scan = $scanClass::start('audit', 'perimeter:audit', [
            'scan_paths' => config('perimeter.clamav.scan_paths', [base_path()]),
            'exclude_patterns' => config('perimeter.clamav.exclude_patterns', []),
        ]);

        // Run malware scans
        $scannerService = $this->getScannerService();
        $malwareResults = $scannerService->scanPaths(
            config('perimeter.clamav.scan_paths', [base_path()]),
            config('perimeter.clamav.exclude_patterns', [])
        );

        // Store malware results in database
        foreach ($malwareResults as $result) {
            $eventData = $scannerService->resultToSecurityEventData([
                'timestamp' => now(),
                'severity' => $this->getThreatSeverity($result['threat']),
                'threat' => $result['threat'],
                'file' => $result['file'],
                'scan_id' => $scan->id,
            ]);

            $this->storeSecurityEvent($eventData);
        }

        // Run vulnerability scans
        $vulnerabilityScanner = $this->getVulnerabilityScanner();
        $vulnerabilityResults = $vulnerabilityScanner->scanDependencies();

        // Store vulnerability results in database
        foreach ($vulnerabilityResults as $result) {
            $result['scan_id'] = $scan->id;
            $eventData = $vulnerabilityScanner->resultToSecurityEventData($result);
            $this->storeSecurityEvent($eventData);
        }

        // Get behavioral analysis results if monitor service is enabled
        $behavioralResults = [];
        $monitorService = $this->getMonitorService();
        if ($monitorService && $monitorService->isEnabled() && $monitorService->isConfigured()) {
            $behavioralResults = $monitorService->getRecentEvents();

            // Store behavioral results in database
            foreach ($behavioralResults as $result) {
                $result['scan_id'] = $scan->id;
                $eventData = $monitorService->resultToSecurityEventData($result);
                $this->storeSecurityEvent($eventData);
            }
        }

        // Complete the scan record if storage is enabled
        if ($scan !== null) {
            $totalIssues = count($malwareResults) + count($vulnerabilityResults) + count($behavioralResults);
            $scan->complete($totalIssues, [
                'malware_count' => count($malwareResults),
                'vulnerability_count' => count($vulnerabilityResults),
                'behavioral_count' => count($behavioralResults),
            ]);
        }

        // Combine results
        $auditResult = new AuditResult(
            $malwareResults,
            $vulnerabilityResults,
            $behavioralResults
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
     * Trigger registered callbacks for an event.
     *
     * @param  mixed  $data
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
     */
    protected function logThreat(ScanResult $result): void
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
     */
    protected function getLogLevel(string $threat): string
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

    /**
     * Get the appropriate severity level for a threat.
     */
    protected function getThreatSeverity(string $threat): string
    {
        $logLevel = $this->getLogLevel($threat);

        // Map log levels to severity levels
        $severityMap = [
            'emergency' => 'critical',
            'alert' => 'critical',
            'critical' => 'critical',
            'error' => 'high',
            'warning' => 'medium',
            'notice' => 'medium',
            'info' => 'low',
            'debug' => 'low',
        ];

        return $severityMap[$logLevel] ?? 'high';
    }

    /**
     * Store a security event in the database.
     */
    protected function storeSecurityEvent(SecurityEventData $eventData): ?SecurityEvent
    {
        $eventClass = config('perimeter.storage.models.security_event', \Prahsys\Perimeter\Models\SecurityEvent::class);

        return $eventClass::create($eventData->toModelArray());
    }

    /**
     * Register a callback for when a threat is detected.
     *
     * @param  callable  $callback
     * @return $this
     */
    public function onThreatDetected(callable $callback)
    {
        $this->callbacks['threatDetected'][] = $callback;

        return $this;
    }

    /**
     * Get intrusion prevention service status.
     *
     * @return \Prahsys\Perimeter\Data\ServiceStatusData
     */
    public function getIntrusionPreventionStatus()
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->getStatus();
    }

    /**
     * Get list of active jails from intrusion prevention service.
     *
     * @return array
     */
    public function getIntrusionPreventionJails()
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->getJails();
    }

    /**
     * Get status of a specific jail.
     *
     * @param  string  $jail
     * @return array
     */
    public function getJailStatus(string $jail)
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->getJailStatus($jail);
    }

    /**
     * Get banned IPs for a specific jail.
     *
     * @param  string  $jail
     * @return array
     */
    public function getBannedIPs(string $jail)
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->getBannedIPs($jail);
    }

    /**
     * Unban an IP from a jail.
     *
     * @param  string  $ip
     * @param  string  $jail
     * @return bool
     */
    public function unbanIP(string $ip, string $jail)
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->unbanIP($ip, $jail);
    }

    /**
     * Get recent intrusion events.
     *
     * @param  int  $limit
     * @return array
     */
    public function getIntrusionEvents(int $limit = 10)
    {
        $service = $this->getIntrusionPreventionService();
        if (! $service) {
            throw new \RuntimeException('No intrusion prevention service available');
        }

        return $service->getRecentEvents($limit);
    }

    /**
     * Check if running in a Docker/container environment
     */
    public function isRunningInContainer(): bool
    {
        // Check for Docker
        if (file_exists('/.dockerenv')) {
            return true;
        }

        // Check for container-specific cgroup paths
        if (file_exists('/proc/1/cgroup')) {
            $content = @file_get_contents('/proc/1/cgroup');
            if ($content && (strpos($content, '/docker') !== false ||
                            strpos($content, '/lxc') !== false ||
                            strpos($content, '/kubepods') !== false)) {
                return true;
            }
        }

        // Check other container indicators
        if (file_exists('/run/.containerenv')) {
            return true;
        }

        // Check for environment variables commonly set in containers
        if (! empty(getenv('KUBERNETES_SERVICE_HOST')) ||
            ! empty(getenv('DOCKER_CONTAINER')) ||
            ! empty(getenv('DOCKER_HOST'))) {
            return true;
        }

        // Check if hostname is a docker container ID (they're typically 12 hex chars)
        $hostname = gethostname();
        if (strlen($hostname) === 12 && ctype_xdigit($hostname)) {
            return true;
        }

        // Check for supervisor without systemd (common in containers)
        if (file_exists('/usr/bin/supervisord') && ! file_exists('/bin/systemctl')) {
            return true;
        }

        return false;
    }
}
