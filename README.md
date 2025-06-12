# Laravel Perimeter

Comprehensive system-level security monitoring for Laravel applications, integrating malware protection, runtime behavioral analysis, vulnerability detection, and compliance reporting.

## Overview

Laravel Perimeter provides comprehensive system-level security monitoring at the infrastructure boundary, combining multiple security tools into a single package with Laravel-native interfaces and unified logging.

## Core Components

### 1. File Protection (ClamAV Integration)
- Malware scanning with OnAccess real-time protection
- Scheduled and on-demand scanning
- Configurable threat severity grading
- Quarantine management

### 2. Runtime Protection (Falco Integration)
- Behavioral anomaly detection
- Container runtime security
- Suspicious process monitoring
- File access anomaly detection
- Network activity monitoring

### 3. Vulnerability Scanning (Trivy Integration)
- PHP dependency vulnerability detection (composer.lock)
- JavaScript dependency scanning (package-lock.json)
- Known CVE detection in dependencies
- License compliance checking
- Configuration file security scanning

### 4. Laravel-Specific Security
- Suspicious query detection
- Authentication anomaly monitoring
- File upload validation
- Session hijacking detection
- API rate limit abuse detection

### 5. Reporting & Data Export
- Raw security event data export (JSON/CSV)
- Time-range filtering
- Event type filtering
- Severity threshold filtering
- Configurable output formats

## Installation & Usage

```bash
# Install package
composer require prahsys/laravel-perimeter

# Publish configuration
php artisan vendor:publish --tag=perimeter-config

# Run initial setup (installs system dependencies)
php artisan perimeter:install

# Configure .env
PERIMETER_ENABLED=true
PERIMETER_LOG_CHANNELS=stack,axiom
PERIMETER_REALTIME_SCAN=true

# Add to scheduler (app/Console/Kernel.php)
$schedule->command('perimeter:scan vulnerabilities')->daily();
$schedule->command('perimeter:report --compliance=soc2')->weekly();

# Start real-time monitoring (via supervisor)
php artisan perimeter:monitor --realtime
```

## Artisan Commands

### Core Commands
```bash
# Comprehensive security audit
php artisan perimeter:audit
# Outputs: Security score, vulnerabilities, compliance status

# Real-time monitoring
php artisan perimeter:monitor --realtime
# Monitors: File changes, process behavior, network activity

# Generate security report
php artisan perimeter:report --from=2025-01-01 --to=2025-06-01
# Outputs: JSON/CSV with all security events in date range

# Filter by event type
php artisan perimeter:report --type=malware,vulnerabilities --format=csv

# Filter by severity
php artisan perimeter:report --severity=critical,high --format=json

# Health check
php artisan perimeter:health
# Verifies: All security components are operational

# Initial setup
php artisan perimeter:install
# Installs: ClamAV, Falco, Trivy, and configures everything
```

## Integration Features

### 1. Middleware Protection
```php
Route::middleware(['perimeter.protect'])->group(function () {
    // Protected routes with real-time security monitoring
});
```

### 2. File Upload Scanning
```php
use Prahsys\Perimeter\Facades\Perimeter;

public function upload(Request $request)
{
    $file = $request->file('document');
    
    $scan = Perimeter::scan($file);
    if ($scan->hasThreat()) {
        abort(422, 'Security threat detected: ' . $scan->getThreat());
    }
    
    // Process safe file
}
```

### 3. Logging Integration
```php
// All security events use Laravel's logging system
// Configure alerts in config/logging.php:

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

### 4. Reporting & Callbacks
```php
// Get raw security data with filters
$events = Perimeter::report()
    ->from(now()->subMonth())
    ->to(now())
    ->severity(['critical', 'high'])
    ->type(['malware', 'vulnerability'])
    ->get();

// Register custom event callbacks
Perimeter::onThreatDetected(function ($threat) {
    // Custom handling logic
});

Perimeter::onVulnerabilityFound(function ($vulnerability) {
    // Custom handling logic
});

// Export for auditors
$report = Perimeter::report()
    ->from($auditPeriodStart)
    ->format('csv')
    ->export();
```

## Dashboard Features
- Real-time threat monitoring
- Security metrics and trends
- Compliance status overview
- Incident timeline
- Vulnerability reports
- Audit trail viewer

## Data Storage & Integration

The package stores security events in Laravel's default log files and optionally in any log channels you configure. No database migrations or models are created. 

For persistent storage, users can:
1. Configure a database log channel in Laravel
2. Listen to Perimeter events and store in their own models
3. Use the callback system to integrate with existing audit tables

Example integration:
```php
// In AppServiceProvider
Perimeter::onThreatDetected(function ($event) {
    // Store in your own audit table
    AuditLog::create([
        'type' => 'security_threat',
        'severity' => $event->severity,
        'details' => $event->toArray(),
    ]);
});
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.