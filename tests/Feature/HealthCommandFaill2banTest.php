<?php

namespace Prahsys\Perimeter\Tests\Feature;

use Mockery;
use Prahsys\Perimeter\Data\ServiceStatusData;
use Prahsys\Perimeter\Services\Fail2banService;

test('health command shows fail2ban status', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);

    // Mock the methods that the health command will call
    $mockService->shouldReceive('isEnabled')->andReturn(true);
    $mockService->shouldReceive('isInstalled')->andReturn(true);
    $mockService->shouldReceive('isConfigured')->andReturn(true);

    // Create a ServiceStatusData object for the mock
    $statusData = new ServiceStatusData(
        name: 'fail2ban',
        enabled: true,
        installed: true,
        configured: true,
        running: true,
        message: 'Fail2ban is active',
        details: [
            'version' => '1.0.2',
            'jails' => ['sshd', 'apache-auth'],
        ]
    );

    // Add mock for the getStatus and getJails methods
    $mockService->shouldReceive('getStatus')->andReturn($statusData);
    $mockService->shouldReceive('getJails')->andReturn(['sshd', 'apache-auth']);

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);

    // Execute the health command
    $this->artisan('perimeter:health')
        ->expectsOutput('Checking Perimeter security components health...')
        ->expectsOutput('Fail2Ban is active and properly configured')
        ->expectsOutput('  • Active jails: sshd, apache-auth')
        ->assertExitCode(0);
});

test('health command shows fail2ban not installed', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);

    // Mock the methods that the health command will call
    $mockService->shouldReceive('isEnabled')->andReturn(true);
    $mockService->shouldReceive('isInstalled')->andReturn(false);
    $mockService->shouldReceive('isConfigured')->andReturn(false);

    // Create a ServiceStatusData object for the mock
    $statusData = new ServiceStatusData(
        name: 'fail2ban',
        enabled: true,
        installed: false,
        configured: false,
        running: false,
        message: 'Fail2ban is not installed',
        details: []
    );

    // Add mock for the getStatus method
    $mockService->shouldReceive('getStatus')->andReturn($statusData);

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);

    // Execute the health command
    $this->artisan('perimeter:health')
        ->expectsOutput('Checking Perimeter security components health...')
        ->expectsOutput('Fail2Ban is not installed or not functioning properly.')
        ->assertExitCode(1);
});

test('health command shows fail2ban not configured', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);

    // Mock the methods that the health command will call
    $mockService->shouldReceive('isEnabled')->andReturn(true);
    $mockService->shouldReceive('isInstalled')->andReturn(true);
    $mockService->shouldReceive('isConfigured')->andReturn(false);

    // Create a ServiceStatusData object for the mock
    $statusData = new ServiceStatusData(
        name: 'fail2ban',
        enabled: true,
        installed: true,
        configured: false,
        running: false,
        message: 'Fail2ban is not configured properly',
        details: []
    );

    // Add mock for the getStatus method
    $mockService->shouldReceive('getStatus')->andReturn($statusData);

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);

    // Execute the health command
    $this->artisan('perimeter:health')
        ->expectsOutput('Checking Perimeter security components health...')
        ->expectsOutput('Fail2Ban is installed but not running.')
        ->assertExitCode(1);
});
