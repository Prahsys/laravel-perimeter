<?php

use Prahsys\Perimeter\Contracts\SecurityMonitoringServiceInterface;
use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Services\FalcoService;

test('falco service implements security monitoring interface', function () {
    $service = new FalcoService(['enabled' => true]);
    expect($service)->toBeInstanceOf(SecurityMonitoringServiceInterface::class);
});

test('get monitoring options returns expected structure', function () {
    $config = [
        'enabled' => true,
        'log_path' => '/var/log/test.log',
        'severity_filter' => 'info',
    ];

    $service = new FalcoService($config);

    $options = $service->getMonitoringOptions();

    expect($options)->toBeArray();
    expect($options)->toHaveKeys([
        'service', 'description', 'supports_realtime', 
        'log_path', 'severity_filter', 'event_types'
    ]);

    expect($options['service'])->toBe('falco');
    expect($options['log_path'])->toBe('/var/log/test.log');
    expect($options['severity_filter'])->toBe('info');
    expect($options['supports_realtime'])->toBeTrue();
});
