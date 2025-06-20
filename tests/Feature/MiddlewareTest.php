<?php

use Illuminate\Http\UploadedFile;
use Prahsys\Perimeter\Exceptions\ThreatDetectedException;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\Http\Middleware\PerimeterProtection;
use Prahsys\Perimeter\ScanResult;

beforeEach(function () {
    // Set up route with middleware
    $this->app['router']->post('/test-upload', function () {
        return response()->json(['success' => true]);
    })->middleware(PerimeterProtection::class);
});

test('it allows safe file uploads', function () {
    $file = UploadedFile::fake()->create('document.pdf', 100);

    $response = $this->postJson('/test-upload', [
        'file' => $file,
    ]);

    $response->assertStatus(200);
    $response->assertJson(['success' => true]);
});

test('it blocks malicious file uploads', function () {
    // The key issue is that the middleware uses the Perimeter facade
    // So we need to mock the Perimeter class itself

    // Create an infected scan result
    $infectedResult = ScanResult::infected('/path/to/file', 'Trojan.PHP.Agent');

    // Create the mocks we need
    $scannerServiceMock = \Mockery::mock(\Prahsys\Perimeter\Contracts\ScannerServiceInterface::class);
    $serviceManagerMock = \Mockery::mock(\Prahsys\Perimeter\Services\ServiceManager::class);
    $reportingServiceMock = \Mockery::mock(\Prahsys\Perimeter\Services\ReportingService::class);

    // Setup scanner service mock
    $scannerServiceMock->shouldReceive('resultToSecurityEventData')
        ->andReturn(new \Prahsys\Perimeter\Data\SecurityEventData(
            timestamp: now(),
            type: 'malware',
            severity: 'critical',
            description: 'Detected Trojan.PHP.Agent in file',
            location: '/path/to/file',
            user: null,
            details: ['threat' => 'Trojan.PHP.Agent']
        ));

    // Setup service manager mock
    $serviceManagerMock->shouldReceive('getScanners')->andReturn(collect([$scannerServiceMock]));
    $serviceManagerMock->shouldReceive('getMonitors')->andReturn(collect([]));
    $serviceManagerMock->shouldReceive('getVulnerabilityScanners')->andReturn(collect([]));

    // Setup reporting service mock - no longer expecting setClamAVService call
    // The test was expecting setClamAVService to be called, but it's not in our
    // refactored code path
    $reportingServiceMock->shouldReceive('setClamAVService')->withAnyArgs()->zeroOrMoreTimes();
    $reportingServiceMock->shouldReceive('setFalcoService')->withAnyArgs()->zeroOrMoreTimes();
    $reportingServiceMock->shouldReceive('setTrivyService')->withAnyArgs()->zeroOrMoreTimes();

    // Create a partial mock of the Perimeter class that doesn't call the constructor
    $perimeterMock = \Mockery::mock(\Prahsys\Perimeter\Perimeter::class, [
        $serviceManagerMock, $reportingServiceMock,
    ])->makePartial();

    // Set up expectations for the scan method
    $perimeterMock->shouldReceive('scan')
        ->once()  // This method should be called exactly once
        ->andReturn($infectedResult); // Return an infected result

    // We need to allow mocking protected methods and stub the necessary methods
    $perimeterMock->shouldAllowMockingProtectedMethods()
        ->shouldReceive('getScannerService')->andReturn($scannerServiceMock)
        ->shouldReceive('triggerCallbacks')->withAnyArgs()->zeroOrMoreTimes()
        ->shouldReceive('logThreat')->withAnyArgs()->zeroOrMoreTimes()
        ->shouldReceive('storeSecurityEvent')->withAnyArgs()->zeroOrMoreTimes();

    // Replace the Perimeter instance in the container
    // Note: Perimeter facade uses the class name as accessor, not 'perimeter'
    $this->app->instance(\Prahsys\Perimeter\Perimeter::class, $perimeterMock);

    // Create a fake file that should trigger detection
    $file = UploadedFile::fake()->create('malicious.php', 100);

    // Create a request with the file
    $request = \Illuminate\Http\Request::create(
        '/test-upload',
        'POST',
        [], // parameters
        [], // cookies
        ['file' => $file], // files
        [], // server
        null // content
    );

    // Create middleware and run the test
    $middleware = new PerimeterProtection;

    // Expect the exception to be thrown
    expect(fn () => $middleware->handle($request, function () {}))
        ->toThrow(ThreatDetectedException::class, 'Security threat detected', 'ThreatDetectedException was not thrown');
});
