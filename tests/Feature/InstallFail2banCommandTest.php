<?php

namespace Prahsys\Perimeter\Tests\Feature;

use Mockery;
use PHPUnit\Framework\MockObject\MockObject;
use Prahsys\Perimeter\Commands\InstallFail2ban;
use Prahsys\Perimeter\Data\ServiceStatusData;
use Prahsys\Perimeter\Services\Fail2banService;

test('command checks for installation status', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);
    $mockService->shouldReceive('isInstalled')->once()->andReturn(false);
    $mockService->shouldReceive('isConfigured')->once()->andReturn(false);

    // We'll expect that it tries to check for root and then fails
    $mockService->shouldNotReceive('install');

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);

    // Execute the command
    $this->artisan('perimeter:install-fail2ban')
        ->expectsOutput('Checking for Fail2Ban installation...')
        ->expectsOutput('ERROR: This command must be run with sudo or as root to install system packages.')
        ->assertExitCode(1);
});

test('command skips if already installed', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);
    $mockService->shouldReceive('isInstalled')->once()->andReturn(true);
    $mockService->shouldReceive('isConfigured')->once()->andReturn(true);

    // We won't try to install since it's already installed and configured
    $mockService->shouldNotReceive('install');

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);

    // Execute the command
    $this->artisan('perimeter:install-fail2ban')
        ->expectsOutput('Checking for Fail2Ban installation...')
        ->expectsOutput('Fail2Ban is already installed and configured.')
        ->assertExitCode(0);
});

test('command forces reinstall', function () {
    // Create a mock of the Fail2banService
    $mockService = Mockery::mock(Fail2banService::class);
    $mockService->shouldReceive('isInstalled')->once()->andReturn(true);
    $mockService->shouldReceive('isConfigured')->once()->andReturn(true);

    // Command class has isRunningAsRoot method, let's mock it
    /** @var MockObject|InstallFail2ban $command */
    $command = $this->getMockBuilder(InstallFail2ban::class)
        ->onlyMethods(['isRunningAsRoot'])
        ->getMock();

    // Mock the isRunningAsRoot method to return true
    $command->method('isRunningAsRoot')
        ->willReturn(true);

    // We expect the install method to be called because of the --force option
    $mockService->shouldReceive('install')
        ->once()
        ->with(Mockery::on(function ($options) {
            return isset($options['configure']) && isset($options['start']);
        }))
        ->andReturn(true);

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

    // Mock the status response after installation
    $mockService->shouldReceive('getStatus')
        ->once()
        ->andReturn($statusData);

    // Bind the mock to the container
    $this->app->instance(Fail2banService::class, $mockService);
    $this->app->instance(InstallFail2ban::class, $command);

    // Execute the command with the force option
    $this->artisan('perimeter:install-fail2ban --force')
        ->expectsOutput('Checking for Fail2Ban installation...')
        ->expectsOutput('Installing Fail2Ban...')
        ->expectsOutput('Fail2Ban has been successfully installed!')
        ->assertExitCode(0);
});
