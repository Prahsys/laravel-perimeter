<?php

use Illuminate\Http\UploadedFile;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\ScanResult;

uses(\Illuminate\Foundation\Testing\RefreshDatabase::class);

test('it can scan a file', function () {
    $file = UploadedFile::fake()->create('document.pdf', 100);

    $result = Perimeter::scan($file);

    expect($result)->toBeInstanceOf(ScanResult::class);
    expect($result->hasThreat())->toBeFalse();
    expect($result->getThreat())->toBeNull();
});

test('it can detect threats in a file', function () {
    // Create a standalone Perimeter instance with mocked services for this test

    // Mock the scanner service
    $mockScannerService = \Mockery::mock(\Prahsys\Perimeter\Contracts\ScannerServiceInterface::class);
    $mockScannerService->shouldReceive('scanFile')
        ->andReturn(ScanResult::infected('/path/to/file', 'Trojan.PHP.Agent'));
    $mockScannerService->shouldReceive('resultToSecurityEventData')
        ->andReturn(new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: now(),
            type: 'malware',
            severity: 'critical',
            description: 'Detected Trojan.PHP.Agent in file',
            location: '/path/to/file',
            user: null,
            details: ['threat' => 'Trojan.PHP.Agent']
        ));

    // Mock the service manager
    $mockServiceManager = \Mockery::mock(\Prahsys\Perimeter\Services\ServiceManager::class);
    $mockServiceManager->shouldReceive('getScanners')
        ->andReturn(collect([$mockScannerService]));

    // We need to handle all the calls made in the Perimeter constructor
    $mockServiceManager->shouldReceive('getMonitors')->andReturn(collect([]));
    $mockServiceManager->shouldReceive('getVulnerabilityScanners')->andReturn(collect([]));

    // Create a mock reporting service
    $mockReportingService = \Mockery::mock(\Prahsys\Perimeter\Services\ReportingService::class);
    $mockReportingService->shouldReceive('setClamAVService')->andReturnSelf();
    $mockReportingService->shouldReceive('setFalcoService')->andReturnSelf();
    $mockReportingService->shouldReceive('setTrivyService')->andReturnSelf();

    // Create the Perimeter instance with our mocks
    $perimeter = new \Prahsys\Perimeter\Perimeter(
        $mockServiceManager,
        $mockReportingService
    );

    // Replace the facade instance
    \Prahsys\Perimeter\Facades\Perimeter::swap($perimeter);

    $file = UploadedFile::fake()->create('document.php', 100);

    $result = Perimeter::scan($file);

    expect($result)->toBeInstanceOf(ScanResult::class);
    expect($result->hasThreat())->toBeTrue();
    expect($result->getThreat())->toBe('Trojan.PHP.Agent');
});

test('it can register and trigger threat callbacks', function () {
    // Create a standalone Perimeter instance with mocked services for this test

    // Mock the scanner service
    $mockScannerService = \Mockery::mock(\Prahsys\Perimeter\Contracts\ScannerServiceInterface::class);
    $mockScannerService->shouldReceive('scanFile')
        ->andReturn(ScanResult::infected('/path/to/file', 'Trojan.PHP.Agent'));
    $mockScannerService->shouldReceive('resultToSecurityEventData')
        ->andReturn(new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: now(),
            type: 'malware',
            severity: 'critical',
            description: 'Detected Trojan.PHP.Agent in file',
            location: '/path/to/file',
            user: null,
            details: ['threat' => 'Trojan.PHP.Agent']
        ));

    // Mock the service manager
    $mockServiceManager = \Mockery::mock(\Prahsys\Perimeter\Services\ServiceManager::class);
    $mockServiceManager->shouldReceive('getScanners')
        ->andReturn(collect([$mockScannerService]));

    // We need to handle all the calls made in the Perimeter constructor
    $mockServiceManager->shouldReceive('getMonitors')->andReturn(collect([]));
    $mockServiceManager->shouldReceive('getVulnerabilityScanners')->andReturn(collect([]));

    // Create a mock reporting service
    $mockReportingService = \Mockery::mock(\Prahsys\Perimeter\Services\ReportingService::class);
    $mockReportingService->shouldReceive('setClamAVService')->andReturnSelf();
    $mockReportingService->shouldReceive('setFalcoService')->andReturnSelf();
    $mockReportingService->shouldReceive('setTrivyService')->andReturnSelf();

    // Create the Perimeter instance with our mocks
    $perimeter = new \Prahsys\Perimeter\Perimeter(
        $mockServiceManager,
        $mockReportingService
    );

    // Replace the facade instance
    \Prahsys\Perimeter\Facades\Perimeter::swap($perimeter);

    $callbackCalled = false;
    $detectedThreat = null;

    Perimeter::onThreatDetected(function ($result) use (&$callbackCalled, &$detectedThreat) {
        $callbackCalled = true;
        $detectedThreat = $result->getThreat();
    });

    $file = UploadedFile::fake()->create('document.php', 100);
    Perimeter::scan($file);

    expect($callbackCalled)->toBeTrue();
    expect($detectedThreat)->toBe('Trojan.PHP.Agent');
});
