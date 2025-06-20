<?php

namespace Tests\Unit;

use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Services\FalcoService;
use Tests\TestCase;

class SecurityMonitoringServiceTest extends TestCase
{
    public function test_falco_service_implements_security_monitoring_interface()
    {
        $service = new FalcoService(['enabled' => true]);

        $this->assertInstanceOf(SecurityMonitoringServiceInterface::class, $service);
    }

    public function test_get_monitoring_events_returns_security_event_data_objects()
    {
        $service = $this->createMock(FalcoService::class);
        $service->method('isEnabled')->willReturn(true);
        $service->method('isConfigured')->willReturn(true);

        // Mock getRawEvents to return test data
        $rawEvents = [
            [
                'rule' => 'test_rule',
                'priority' => 'warning',
                'description' => 'Test security event',
                'process' => 'test_process',
                'user' => 'test_user',
                'timestamp' => now()->toIso8601String(),
            ],
        ];

        // Create a real SecurityEventData object for return
        $securityEvent = new SecurityEventData(
            timestamp: now(),
            type: 'behavioral',
            severity: 'warning',
            description: 'Test security event',
            location: 'process:test_process',
            user: 'test_user',
            details: [
                'rule' => 'test_rule',
                'process' => 'test_process',
            ]
        );

        // Setup the mocked methods
        $service->method('getRawEvents')->willReturn($rawEvents);
        $service->method('resultToSecurityEventData')->willReturn($securityEvent);

        // Make the method we're testing accessible
        $reflectedMethod = new \ReflectionMethod(FalcoService::class, 'getMonitoringEvents');

        // Call the method
        $result = $reflectedMethod->invoke($service);

        // Verify the results
        $this->assertIsArray($result);
        $this->assertCount(1, $result);
        $this->assertInstanceOf(SecurityEventData::class, $result[0]);
        $this->assertEquals('warning', $result[0]->severity);
        $this->assertEquals('Test security event', $result[0]->description);
    }

    public function test_get_monitoring_options_returns_expected_structure()
    {
        $config = [
            'enabled' => true,
            'log_path' => '/var/log/test.log',
            'severity_filter' => 'info',
        ];

        $service = new FalcoService($config);

        $options = $service->getMonitoringOptions();

        $this->assertIsArray($options);
        $this->assertArrayHasKey('service', $options);
        $this->assertArrayHasKey('description', $options);
        $this->assertArrayHasKey('supports_realtime', $options);
        $this->assertArrayHasKey('log_path', $options);
        $this->assertArrayHasKey('severity_filter', $options);
        $this->assertArrayHasKey('event_types', $options);

        $this->assertEquals('falco', $options['service']);
        $this->assertEquals('/var/log/test.log', $options['log_path']);
        $this->assertEquals('info', $options['severity_filter']);
        $this->assertTrue($options['supports_realtime']);
    }
}
