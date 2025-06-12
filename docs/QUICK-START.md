# Laravel Perimeter Quick Start Guide

This quick start guide will help you get up and running with Laravel Perimeter in your Laravel application.

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
php artisan perimeter:install
```

The installation command will:

- Install ClamAV (or provide instructions)
- Install Falco (or provide instructions)
- Install Trivy (or provide instructions)
- Configure your `.env` file with Perimeter settings
- Create necessary directories for rules and custom configurations

### 4. Configure Environment Variables

The installer will add these to your `.env` file, but you can customize them:

```dotenv
PERIMETER_ENABLED=true
PERIMETER_LOG_CHANNELS=stack
PERIMETER_CLAMAV_ENABLED=true
PERIMETER_FALCO_ENABLED=true
PERIMETER_TRIVY_ENABLED=true
PERIMETER_REALTIME_SCAN=true
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
    // Daily security audit
    $schedule->command('perimeter:audit')->daily();
    
    // Weekly vulnerability scan
    $schedule->command('perimeter:report --type=vulnerability')->weekly();
    
    // Point-in-time behavioral checks
    $schedule->command('perimeter:monitor')->hourly();
}
```

### 4. Set Up Real-time Monitoring

For continuous security monitoring, set up a supervisor config:

```ini
[program:perimeter-monitor]
command=php /path/to/your/artisan perimeter:monitor --realtime
autostart=true
autorestart=true
user=www-data
redirect_stderr=true
stdout_logfile=/var/log/perimeter-monitor.log
```

## Command Reference

### Security Audit

Perform a comprehensive security audit:

```bash
php artisan perimeter:audit
```

Options:
- `--format=json` - Output in JSON format

### Monitoring

Check for security events:

```bash
# Point-in-time check
php artisan perimeter:monitor

# Real-time monitoring
php artisan perimeter:monitor --realtime
```

Options:
- `--realtime` - Run in real-time monitoring mode
- `--duration=3600` - Duration in seconds for real-time mode (default: 1 hour)

### Reporting

Generate security reports:

```bash
php artisan perimeter:report
```

Options:
- `--from=2025-01-01` - Start date for filtering events
- `--to=2025-06-01` - End date for filtering events
- `--type=malware,vulnerability` - Filter by event type
- `--severity=critical,high` - Filter by severity
- `--format=json` - Output format (text, json, csv)
- `--compliance=soc2` - Generate compliance report for specified framework
- `--output=/path/to/file.json` - Output file path

### Health Check

Verify that all security components are operational:

```bash
php artisan perimeter:health
```

## Next Steps

1. Check out the [SOC2-COMPLIANCE.md](./SOC2-COMPLIANCE.md) document for guidance on using Laravel Perimeter for SOC 2 compliance.
2. Review the [RUNBOOKS.md](./RUNBOOKS.md) for incident response procedures.
3. Visit our [GitHub repository](https://github.com/prahsys/laravel-perimeter) for updates and to contribute.

## Troubleshooting

If you encounter any issues during installation or usage:

1. Run `php artisan perimeter:health` to check component status
2. Check your logs at `storage/logs/laravel.log` for error messages
3. Ensure system dependencies are properly installed
4. Make sure proper permissions are set for the `perimeter-rules` directory

For additional help, please open an issue on our GitHub repository.