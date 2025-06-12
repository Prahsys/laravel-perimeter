# SOC 2 Compliance with Laravel Perimeter

This document outlines how Laravel Perimeter helps organizations maintain SOC 2 compliance by implementing comprehensive security monitoring and controls.

## SOC 2 Requirements Addressed

### Common Criteria (CC)

| Control ID | Description | Laravel Perimeter Coverage |
|------------|-------------|----------------------------|
| CC6.1 | Logical Access Security | Perimeter middleware provides real-time protection against malicious file uploads and suspicious input patterns. |
| CC6.8 | Malicious Software Prevention | ClamAV integration provides robust malware detection and prevention for uploaded files and system directories. |
| CC7.1 | System Operations | Falco integration provides real-time behavioral monitoring of system activities to detect anomalies. |
| CC7.2 | Security Incident Identification | Events are logged to configurable logging channels with appropriate severity levels for incident identification. |
| CC8.1 | Change Management | Trivy integration identifies vulnerabilities in dependencies that could be introduced during changes. |

## Implementation Guidance

### 1. Malware Protection (CC6.8)

Laravel Perimeter integrates with ClamAV to provide:

- **Real-time scanning** of uploaded files through middleware protection
- **Scheduled scanning** of application directories to detect potential threats
- **Threat severity grading** to prioritize critical issues
- **Proper logging** of all detection events for audit purposes

Implementation:

```php
// Add to routes that accept file uploads
Route::middleware(['perimeter.protect'])->group(function () {
    Route::post('/upload', [UploadController::class, 'store']);
});

// Configure scheduled scans in your App\Console\Kernel class
protected function schedule(Schedule $schedule)
{
    $schedule->command('perimeter:audit')->daily();
}
```

### 2. Behavioral Monitoring (CC7.1, CC7.2)

Falco integration provides:

- **Runtime security** to detect suspicious processes
- **Container monitoring** for containerized environments
- **File access anomaly detection** to identify potential security breaches
- **Network activity monitoring** to detect unusual connections

Implementation:

```php
// Run real-time monitoring (via supervisor or similar)
// supervisor config example:
// [program:perimeter-monitor]
// command=php /path/to/artisan perimeter:monitor --realtime
// autostart=true
// autorestart=true
// user=www-data
// redirect_stderr=true
// stdout_logfile=/var/log/perimeter-monitor.log

// For point-in-time checks
$schedule->command('perimeter:monitor')->hourly();
```

### 3. Vulnerability Management (CC8.1)

Trivy integration helps with:

- **Dependency scanning** to identify known vulnerabilities in composer and npm packages
- **License compliance checking** to ensure proper software licensing
- **Regular reporting** of vulnerability status

Implementation:

```php
// Schedule regular vulnerability scanning
$schedule->command('perimeter:report --type=vulnerability --format=json --output=/path/to/reports/vulnerabilities.json')->daily();
```

### 4. Compliance Reporting

Generate comprehensive reports for auditors:

```php
// Generate SOC 2 compliance report
php artisan perimeter:report --compliance=soc2 --format=json --output=/path/to/reports/soc2-compliance.json
```

## Logging and Notification

Configure logging channels in your Laravel application's `config/logging.php`:

```php
'channels' => [
    'slack' => [
        'driver' => 'slack',
        'url' => env('LOG_SLACK_WEBHOOK_URL'),
        'username' => 'Laravel Perimeter',
        'emoji' => ':shield:',
        'level' => 'critical', // Only critical and above go to Slack
    ],
    
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'info', // Capture all security events
    ],
]
```

Then configure Laravel Perimeter to use these channels:

```dotenv
PERIMETER_LOG_CHANNELS=stack,slack,security
```

## Audit Trail for SOC 2 Evidence

All security events are timestamped and logged with appropriate context information, providing an audit trail for SOC 2 auditors. Export reports regularly:

```php
// Schedule weekly reports for audit evidence
$schedule->command('perimeter:report --from="' . now()->startOfWeek()->format('Y-m-d') . '" --to="' . now()->endOfWeek()->format('Y-m-d') . '" --format=csv --output=/path/to/reports/weekly-security-events.csv')->weekly();
```

## Conclusion

Laravel Perimeter provides a comprehensive security monitoring solution that addresses many SOC 2 compliance requirements. By implementing the recommendations in this document, organizations can strengthen their security posture and maintain compliance with SOC 2 standards.