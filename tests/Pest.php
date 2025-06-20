<?php

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "uses()" function to bind a different classes or traits.
|
*/

use Prahsys\Perimeter\Contracts\FirewallServiceInterface;
use Prahsys\Perimeter\Contracts\MonitorServiceInterface;
use Prahsys\Perimeter\Contracts\ScannerServiceInterface;
use Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface;
use Prahsys\Perimeter\ScanResult;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\ReportingService;
use Prahsys\Perimeter\Services\TrivyService;
use Prahsys\Perimeter\Services\UfwService;

uses(
    Prahsys\Perimeter\Tests\TestCase::class,
)->beforeEach(function () {
    // Mock ClamAV service
    $this->app->singleton(ClamAVService::class, function () {
        $mock = \Mockery::mock(ClamAVService::class, ScannerServiceInterface::class);
        $mock->shouldReceive('isEnabled')->andReturn(true);
        $mock->shouldReceive('isInstalled')->andReturn(true);
        $mock->shouldReceive('isConfigured')->andReturn(true);
        $mock->shouldReceive('scanFile')->andReturn(ScanResult::clean('/path/to/file'));
        $mock->shouldReceive('scanPaths')->andReturn([]);
        $mock->shouldReceive('getConfig')->andReturn([]);
        $mock->shouldReceive('setConfig');
        $mock->shouldReceive('install')->andReturn(true);

        return $mock;
    });
    $this->app->singleton(ScannerServiceInterface::class, function ($app) {
        return $app->make(ClamAVService::class);
    });

    // Mock Trivy service
    $this->app->singleton(TrivyService::class, function () {
        $mock = \Mockery::mock(TrivyService::class, VulnerabilityScannerInterface::class);
        $mock->shouldReceive('isEnabled')->andReturn(true);
        $mock->shouldReceive('isInstalled')->andReturn(true);
        $mock->shouldReceive('isConfigured')->andReturn(true);
        $mock->shouldReceive('scanFile')->andReturn([]);
        $mock->shouldReceive('scanDependencies')->andReturn([]);
        $mock->shouldReceive('getConfig')->andReturn([]);
        $mock->shouldReceive('setConfig');
        $mock->shouldReceive('install')->andReturn(true);

        return $mock;
    });
    $this->app->singleton(VulnerabilityScannerInterface::class, function ($app) {
        return $app->make(TrivyService::class);
    });

    // Mock Falco service
    $this->app->singleton(FalcoService::class, function () {
        $mock = \Mockery::mock(FalcoService::class, MonitorServiceInterface::class);
        $mock->shouldReceive('isEnabled')->andReturn(true);
        $mock->shouldReceive('isInstalled')->andReturn(true);
        $mock->shouldReceive('isConfigured')->andReturn(true);
        $mock->shouldReceive('startMonitoring')->andReturn(true);
        $mock->shouldReceive('stopMonitoring')->andReturn(true);
        $mock->shouldReceive('getRecentEvents')->andReturn([]);
        $mock->shouldReceive('getConfig')->andReturn([]);
        $mock->shouldReceive('setConfig');
        $mock->shouldReceive('install')->andReturn(true);

        return $mock;
    });
    $this->app->singleton(MonitorServiceInterface::class, function ($app) {
        return $app->make(FalcoService::class);
    });

    // Mock UFW service
    $this->app->singleton(UfwService::class, function () {
        $mock = \Mockery::mock(UfwService::class, FirewallServiceInterface::class);
        $mock->shouldReceive('isEnabled')->andReturn(true);
        $mock->shouldReceive('isInstalled')->andReturn(true);
        $mock->shouldReceive('isConfigured')->andReturn(true);
        $mock->shouldReceive('getStatus')->andReturn(
            new \Prahsys\Perimeter\Data\ServiceStatusData(
                name: 'ufw',
                enabled: true,
                installed: true,
                configured: true,
                running: true,
                message: 'UFW is active and configured properly',
                details: ['active' => true, 'rules' => []]
            )
        );
        $mock->shouldReceive('addRule')->andReturn(true);
        $mock->shouldReceive('deleteRule')->andReturn(true);
        $mock->shouldReceive('getRecentEvents')->andReturn([]);
        $mock->shouldReceive('reset')->andReturn(true);
        $mock->shouldReceive('getConfig')->andReturn([]);
        $mock->shouldReceive('setConfig');
        $mock->shouldReceive('install')->andReturn(true);

        return $mock;
    });
    $this->app->singleton(FirewallServiceInterface::class, function ($app) {
        return $app->make(UfwService::class);
    });

    // Mock Reporting service
    $this->app->singleton(ReportingService::class, function () {
        $mock = \Mockery::mock(ReportingService::class);
        $mock->shouldReceive('setClamAVService')->andReturnSelf();
        $mock->shouldReceive('setFalcoService')->andReturnSelf();
        $mock->shouldReceive('setTrivyService')->andReturnSelf();

        return $mock;
    });
})->afterEach(function () {
    \Mockery::close();
})->in(__DIR__);

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

expect()->extend('toBeOne', function () {
    return $this->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

function getExamplesPath(): string
{
    return dirname(__DIR__).'/resources/examples';
}
