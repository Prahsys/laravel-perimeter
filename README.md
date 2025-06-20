# Laravel Perimeter

Comprehensive system-level security monitoring for Laravel applications, integrating malware protection, runtime behavioral analysis, vulnerability detection, intrusion prevention, and firewall management.

## Overview

Laravel Perimeter provides comprehensive security monitoring at the infrastructure boundary by seamlessly integrating multiple industry-standard security tools into a unified package with Laravel-native interfaces, standardized APIs, and consolidated logging. It creates a multi-layered security perimeter around your application to detect and respond to various security threats.

## Core Components

### 1. File Protection (ClamAV Integration)
- Malware scanning with OnAccess real-time protection
- Scheduled and on-demand scanning with configurable paths
- Signature-based detection with regular database updates
- Integration with Laravel's file upload system
- Configurable exclusion patterns for performance optimization

### 2. Runtime Protection (Falco Integration)
- Behavioral anomaly detection with kernel-level monitoring
- Container runtime security for containerized environments
- Suspicious process execution monitoring
- File access anomaly detection
- Network activity monitoring and alerting
- Custom security rules for Laravel-specific threats
- Point-in-time or continuous real-time monitoring modes

### 3. Vulnerability Scanning (Trivy Integration)
- Full system vulnerability scanning of OS packages and system libraries (debian, ubuntu, alpine, etc.)
- PHP dependency vulnerability detection (composer.lock)
- JavaScript dependency scanning (package-lock.json, yarn.lock)
- Known CVE detection with CVSS scoring
- Configurable severity thresholds (CRITICAL, HIGH, MEDIUM, LOW)
- License compliance checking
- Configuration file security analysis
- Container image scanning support

### 4. Intrusion Prevention (Fail2ban Integration)
- Automatic detection and blocking of suspicious IPs
- Protection for SSH, web applications, and API endpoints
- Custom jail configurations for Laravel-specific attack patterns
- Ban action monitoring and management
- Integration with system firewall rules

### 5. Firewall Management (UFW Integration)
- Network-level protection with simplified rule management
- Service-based security policies
- Port access control and monitoring
- Policy enforcement and validation

### 6. Laravel Integration
- File upload protection via middleware
- Security event broadcasting
- Integration with Laravel's logging system
- Compatible with Laravel scheduler for automated scanning
- Unified interfaces for all security components

### 7. Reporting & Data Export
- Comprehensive security event collection and standardization
- Raw security event data export (JSON/CSV)
- Time-range filtering with from/to date parameters
- Event type filtering (malware, vulnerability, behavioral)
- Severity threshold filtering (critical, high, medium, low)
- Configurable output formats (text, json, csv)
- Security status overview for compliance documentation

## Installation

### 1. Install the Package

```bash
composer require prahsys/laravel-perimeter
```

### 2. Publish the Configuration

```bash
php artisan vendor:publish --tag=perimeter-config
```

This will create a `config/perimeter.php` file in your application.

### 3. Run the Installation Command

This command will help you install and configure the required system dependencies:

```bash
# Complete installation (requires sudo/root privileges)
sudo php artisan perimeter:install

# Individual component installation is also available
php artisan perimeter:install-clamav    # Malware protection
php artisan perimeter:install-falco     # Runtime monitoring
php artisan perimeter:install-trivy     # Vulnerability scanning
php artisan perimeter:install-fail2ban  # Intrusion prevention
php artisan perimeter:install-ufw       # Firewall management
```

Each service is installed with optimized configurations for Laravel applications:

- **ClamAV**: Installs with real-time protection capabilities and optimized scan settings
- **Falco**: Installed without a kernel driver for non-interactive installation, providing comprehensive runtime monitoring with minimal system impact
- **Trivy**: Configured for comprehensive system and dependency scanning with automated vulnerability database updates
- **Fail2ban**: Set up with Laravel-specific jail configurations for web application protection
- **UFW**: Configured with secure default policies and Laravel-friendly port rules

The installation command will:

- Install the necessary security tools based on your system type
- Configure each service for optimal operation with Laravel
- Set up your `.env` file with appropriate Perimeter settings
- Create necessary directories for rules and custom configurations
- Set appropriate permissions for security operations

### 4. Configure Environment Variables

The installer will add these to your `.env` file, but you can customize them:

```dotenv
# Core configuration
PERIMETER_ENABLED=true
PERIMETER_LOG_CHANNELS=stack

# Service enablement
PERIMETER_CLAMAV_ENABLED=true
PERIMETER_FALCO_ENABLED=true
PERIMETER_TRIVY_ENABLED=true
PERIMETER_FAIL2BAN_ENABLED=true
PERIMETER_UFW_ENABLED=true

# Feature flags
PERIMETER_REALTIME_SCAN=true
PERIMETER_UPLOAD_PROTECTION=true
```

## Basic Usage

### 1. Protect File Uploads

Add the Perimeter middleware to routes that handle file uploads:

```php
// routes/web.php or routes/api.php
Route::middleware(['perimeter.protect'])->group(function () {
    Route::post('/upload', [UploadController::class, 'store']);
});
```

The middleware will:
- Scan uploaded files for malware
- Block files with detected threats
- Log security events for audit purposes
- Apply configurable threat response policies

### 2. Scan Files Programmatically

```php
use Prahsys\Perimeter\Facades\Perimeter;

public function upload(Request $request)
{
    $file = $request->file('document');
    
    $scan = Perimeter::scan($file);
    if ($scan->hasThreat()) {
        return response()->json([
            'error' => 'Security threat detected: ' . $scan->getThreat()
        ], 422);
    }
    
    // Process safe file...
}
```

### 3. Schedule Regular Security Checks

Add these to your `app/Console/Kernel.php` file:

```php
protected function schedule(Schedule $schedule)
{
    // Daily comprehensive security audit
    $schedule->command('perimeter:audit')->daily();
    
    // Weekly vulnerability scan with specific focus
    $schedule->command('perimeter:report --type=vulnerability')->weekly();
    
    // Hourly behavioral monitoring checks
    $schedule->command('perimeter:monitor')->hourly();
    
    // Weekly security health verification
    $schedule->command('perimeter:health')->weekly();
}
```

### 4. Set Up Real-time Monitoring

Perimeter provides comprehensive real-time security monitoring through two primary services:

#### Behavioral Monitoring with Falco

Falco provides kernel-level behavioral analysis to detect suspicious activities:

```bash
# Start behavioral monitoring in real-time mode
php artisan perimeter:monitor --service=falco --realtime

# Or run as a system service (recommended for production)
sudo systemctl enable falco
sudo systemctl start falco
```

Falco monitoring provides:
- Kernel-level visibility into all system calls
- Rule-based detection of suspicious processes
- Detection of privilege escalation attempts
- Monitoring of file access patterns for data exfiltration
- Network connection monitoring
- JSON-formatted, standardized security events

#### Malware Detection with ClamAV

ClamAV provides real-time file system monitoring for malware:

```bash
# Enable real-time malware monitoring
php artisan perimeter:monitor --service=clamav --realtime
```

ClamAV monitoring provides:
- Real-time scanning of files as they are accessed
- Detection of malware, trojans, and other threats
- On-access protection for uploads and other file operations
- Signature-based detection with daily database updates
- Low false-positive rate suitable for production systems

#### Centralized Monitoring Dashboard

For continuous monitoring in production, use Supervisor:

```ini
[program:perimeter-monitor]
command=php /path/to/your/artisan perimeter:monitor --realtime
autostart=true
autorestart=true
user=www-data
redirect_stderr=true
stdout_logfile=/var/log/perimeter-monitor.log
```

The combined monitoring system:
- Stores all security events in a standardized format
- Provides audit-ready logs for compliance requirements
- Timestamps and categorizes all security events
- Associates events with specific scans for traceability
- Tracks service origin for each event (falco, clamav, etc.)
- Enables filtering by severity, type, and timeframe

### 5. Respond to Security Events

```php
// Register custom event handlers
use Prahsys\Perimeter\Facades\Perimeter;
use App\Notifications\SecurityAlertNotification;

// In your service provider
Perimeter::onThreatDetected(function ($securityEvent) {
    // Notify security team via Slack
    Notification::route('slack', config('security.slack_webhook'))
        ->notify(new SecurityAlertNotification($securityEvent));
    
    // Log to specialized security log
    Log::channel('security')->critical('Security threat detected', [
        'event' => $securityEvent->toArray()
    ]);
});
```

## Command Reference

### Security Audit

Perform a comprehensive security assessment across all protection layers:

```bash
php artisan perimeter:audit
```

This command:
- Checks all security components for proper operation
- Scans the application for malware
- Scans system packages and dependencies for vulnerabilities
- Analyzes recent behavioral events
- Checks firewall and intrusion prevention status
- Generates a comprehensive security assessment

Options:
- `--format=json` - Output in JSON format for automated processing
- `--scan-paths=/custom/path` - Specify custom paths to scan

### Health Check

Verify that all security components are properly installed and operational:

```bash
php artisan perimeter:health
```

This command quickly verifies:
- Service installation status
- Service configuration status
- Service operational status
- Environment configuration
- Required permissions

### Monitoring

Monitor security events across all protection layers:

```bash
# Point-in-time check of recent security events
php artisan perimeter:monitor

# Real-time continuous monitoring
php artisan perimeter:monitor --realtime

# Service-specific monitoring
php artisan perimeter:monitor --service=falco
```

Options:
- `--realtime` - Run in real-time monitoring mode
- `--duration=3600` - Duration in seconds for real-time mode (default: 1 hour)
- `--service=name` - Focus on a specific security service (clamav, falco, fail2ban)

### Reporting

Generate detailed security reports with flexible filtering:

```bash
php artisan perimeter:report
```

Options:
- `--scan-id=123` - Filter by specific scan ID
- `--from=2025-01-01` - Start date for filtering events
- `--to=2025-06-01` - End date for filtering events
- `--type=malware,vulnerability,behavioral` - Filter by event type
- `--severity=critical,high,medium,low` - Filter by severity
- `--format=json` - Output format (text, json, csv)
- `--output=/path/to/file.json` - Output file path
- `--scans-only` - Show only scan summary without event details

### System Maintenance

```bash
# Prune old security events and scan records
php artisan perimeter:prune

# Update security databases (ClamAV signatures, Trivy vulnerabilities)
php artisan perimeter:update-databases
```

## Advanced Integration Features

### 1. Logging Integration

All security events use Laravel's logging system, enabling seamless integration with your existing logging infrastructure:

```php
// Configure security alerts in config/logging.php:
'channels' => [
    // Send critical security alerts to Slack
    'slack' => [
        'driver' => 'slack',
        'url' => env('LOG_SLACK_WEBHOOK_URL'),
        'username' => 'Laravel Perimeter',
        'emoji' => ':shield:',
        'level' => 'critical', // Only critical and above go to Slack
    ],
    
    // Dedicated security log for compliance
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'info', // Capture all security events
        'days' => 90, // Retain logs for compliance purposes
    ],
    
    // Specialized channel for malware detections
    'malware' => [
        'driver' => 'daily',
        'path' => storage_path('logs/malware.log'),
        'level' => 'notice',
    ],
]
```

### 2. Event Handling & Callbacks

Register custom handlers for security events to integrate with your application's notification systems:

```php
// In your AppServiceProvider or dedicated SecurityServiceProvider
use Prahsys\Perimeter\Facades\Perimeter;

public function boot()
{
    // Handle malware detections
    Perimeter::onThreatDetected(function ($securityEvent) {
        // Notify security team
        SecurityTeam::notifyMalwareDetection($securityEvent);
        
        // Quarantine the file
        Storage::move(
            $securityEvent->location, 
            "quarantine/{$securityEvent->details['hash']}"
        );
    });
    
    // Handle vulnerability detections
    Perimeter::onVulnerabilityFound(function ($vulnerability) {
        // Create ticket in issue tracker
        Jira::createSecurityTicket([
            'title' => "Security vulnerability: {$vulnerability->description}",
            'severity' => $vulnerability->severity,
            'details' => $vulnerability->details,
        ]);
    });
    
    // Handle behavioral anomalies
    Perimeter::onAnomalyDetected(function ($anomaly) {
        // Log IP address for further investigation
        if (isset($anomaly->details['source_ip'])) {
            SuspiciousActivity::record($anomaly->details['source_ip']);
        }
    });
}
```

### 3. Programmatic Reporting

Generate security reports programmatically for integration with dashboards or compliance systems:

```php
use Prahsys\Perimeter\Facades\Perimeter;

// Get raw security data with flexible filters
$events = Perimeter::report()
    ->from(now()->subMonth())
    ->to(now())
    ->severity(['critical', 'high'])
    ->type(['malware', 'vulnerability'])
    ->get();

// Generate formatted reports for auditors
$report = Perimeter::report()
    ->from($auditPeriodStart)
    ->to($auditPeriodEnd)
    ->format('csv')
    ->export();

// Generate JSON for API consumption
return Perimeter::report()
    ->from(request('start_date'))
    ->to(request('end_date'))
    ->type(request('event_types', []))
    ->format('json')
    ->get();
```

## Data Storage & Integration

The package provides robust data storage and standardized data structures for security events, making it easy to integrate with existing monitoring and compliance systems.

### Database Storage

Security events are stored in dedicated database tables with optimized schemas:

- **perimeter_security_events**: Stores standardized security events from all sources
  - Includes type, severity, timestamps, descriptions, and structured details
  - Supports JSON column for flexible event-specific data
  - Indexed for efficient querying and reporting

- **perimeter_security_scans**: Stores metadata about security scan operations
  - Tracks scan types, timestamps, durations, and results
  - Links to related security events
  - Provides audit trail of security operations

The package automatically migrates these tables during installation. You can customize the table prefix in the configuration to match your database naming conventions.

### Data Transfer Objects

All security events use standardized Data Transfer Objects (DTOs) that provide consistent representations across different security tools:

```php
use Prahsys\Perimeter\Data\SecurityEventData;

// Create from malware scan results
$eventData = SecurityEventData::fromMalwareScan([
    'timestamp' => now(),
    'severity' => 'critical',
    'threat' => 'malware-signature',
    'file' => '/path/to/file.php',
    'hash' => 'sha256:1234...',
]);

// Create from behavioral analysis
$eventData = SecurityEventData::fromBehavioralAnalysis([
    'rule' => 'privilege_escalation',
    'priority' => 'critical',
    'description' => 'Suspicious activity detected',
    'process' => 'php',
    'user' => 'www-data',
]);

// Create from vulnerability scan
$eventData = SecurityEventData::fromVulnerabilityScan([
    'package' => 'vulnerable/package',
    'version' => '1.2.3',
    'cve' => 'CVE-2025-1234',
    'severity' => 'high',
    'description' => 'Remote code execution vulnerability',
]);
```

### Security Assessment

The package provides detailed security assessments with actionable information through:

1. **Comprehensive Issue Tracking**: Clear categorization of issues by type and severity
2. **Component Health Status**: Verification that all security components are properly functioning
3. **Protection Coverage**: Assessment of which security layers are active and properly configured
4. **Actionable Findings**: Specific, concrete security issues that need attention
5. **Compliance Information**: Relevant data points for security compliance requirements

This detailed approach provides security professionals with clear, actionable insights about your application's security posture.

Example of security assessment output:

```
Security Assessment Summary
===========================
Components: 5 of 5 operational
Critical Issues: 0
High Issues: 2 (1 vulnerability, 1 suspicious behavior)
Medium Issues: 3 (all configuration related)
Low Issues: 1 (outdated security database)

Recent Activity
--------------
• Last scan: 2025-06-18 19:00:00
• Security events in last 24h: 3 (all medium severity)
• Most recent event: "Suspicious login attempt" (2025-06-18 18:45:12)

Required Actions
--------------
• Update package "vulnerable/package" to version 2.0.1
• Review suspicious access to /etc/passwd by www-data user
• Configure fail2ban to protect Laravel login endpoints
```

## Development Environment

### Using Docker for Development

The package includes a Docker environment for local development and testing that closely mimics a production environment. This setup allows you to develop and test all security features without needing a full VM or physical machine.

#### Docker Setup Instructions

1. Make sure Docker and Docker Compose are installed on your machine
2. Run the following commands:

```bash
# Build and start the Docker environment
docker-compose up -d

# Check that the package is properly installed
docker-compose exec app php artisan list | grep perimeter

# Check status of security services
docker-compose exec app php artisan perimeter:health

# Run the package's tests
docker-compose exec app cd /package && composer test
```

This Docker configuration:
- Creates a fully configured Laravel application for testing
- Installs this package from the local directory with proper volume mounting
- Properly configures all security components
- Sets up necessary permissions and directory structures
- Uses SQLite for a lightweight database with minimal configuration
- Exposes the application on port 8000 for browser testing

#### How Security Services Run in Docker

The security services (ClamAV, Falco, Fail2ban, Trivy, UFW) are configured to work properly in the container with standard configurations and include:

- Proper service startup and monitoring
- Configuration management
- Log collection and rotation
- Full functionality testing
- Status checking and reporting

This approach enables reliable testing across different environments with consistent behavior.

#### Testing Security Services

The Docker environment allows for comprehensive testing of all security components:

```bash
# Check health status of all components
docker-compose exec app php artisan perimeter:health

# Run a security audit
docker-compose exec app php artisan perimeter:audit

# Test real-time monitoring (will run for 60 seconds)
docker-compose exec app php artisan perimeter:monitor --realtime --duration=60

# Generate a security report
docker-compose exec app php artisan perimeter:report

# Check individual service logs
docker-compose exec app cat /var/log/clamav/daemon.log
docker-compose exec app cat /var/log/fail2ban/daemon.log
docker-compose exec app cat /var/log/falco/daemon.log

# Check supervisor status
docker-compose exec app supervisorctl status
```

## Troubleshooting

If you encounter issues during installation or operation, follow these steps:

### 1. Check Component Health

The first step is to verify all components are properly installed and configured:

```bash
php artisan perimeter:health
```

This provides a detailed status report of all security components with specific error messages.

### 2. Check Logs

Review the Laravel and component-specific logs:

```bash
# Laravel logs
tail -f storage/logs/laravel.log

# Component logs
tail -f /var/log/clamav/daemon.log
tail -f /var/log/fail2ban/daemon.log
tail -f /var/log/falco/daemon.log
```

### 3. Common Issues

- **Permission Problems**: Security services often require elevated permissions. Ensure proper user/group settings.
- **Missing Dependencies**: Some components require additional system packages. Check the installation output.
- **Container Limitations**: Some features may be limited in containerized environments without privileged access.
- **Database Issues**: Ensure migrations have run properly: `php artisan migrate:status`

### 4. Sample Outputs

The package includes reference outputs for all security tools in the `resources/examples/` directory. These examples show what properly functioning services should produce and can help with troubleshooting.

## Documentation

For more detailed information, check out these documentation files:

- [RUNBOOKS.md](./docs/RUNBOOKS.md) - Incident response procedures and runbooks
- [DEBUGGING.md](./DEBUGGING.md) - Detailed debugging procedures for all components
- [Example outputs](./resources/examples/) - Sample outputs from security tools

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
