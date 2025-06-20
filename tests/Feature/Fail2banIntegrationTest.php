<?php

use Prahsys\Perimeter\Contracts\IntrusionPreventionInterface;
use Prahsys\Perimeter\Facades\Perimeter;

// Helper function to set up the mocked service for testing
function setupMockService($method, $args, $returns)
{
    // Create a mock service
    $mockService = \Mockery::mock(IntrusionPreventionInterface::class);

    // Setup expected calls
    $mockService->shouldReceive($method)
        ->with(...$args)
        ->once()
        ->andReturn($returns);

    // Mock the service manager
    $mockServiceManager = Mockery::mock(\Prahsys\Perimeter\Services\ServiceManager::class);
    $mockServiceManager->shouldReceive('getIntrusionPreventionServices')
        ->andReturn(collect([$mockService]));

    // We need to handle all the calls made in the Perimeter constructor
    $mockServiceManager->shouldReceive('getScanners')->andReturn(collect([]));
    $mockServiceManager->shouldReceive('getMonitors')->andReturn(collect([]));
    $mockServiceManager->shouldReceive('getVulnerabilityScanners')->andReturn(collect([]));

    // Create a mock reporting service
    $mockReportingService = Mockery::mock(\Prahsys\Perimeter\Services\ReportingService::class);
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

    return $mockService;
}

test('perimeter facade can get intrusion prevention status', function () {
    // Create a ServiceStatusData object for the mock
    $statusData = new \Prahsys\Perimeter\Data\ServiceStatusData(
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

    // Setup mock with expected behavior
    $mockService = setupMockService('getStatus', [], $statusData);

    // Call the facade method
    $status = Perimeter::getIntrusionPreventionStatus();

    // Assert the result
    expect($status->running)->toBeTrue();
    expect($status->details['version'])->toBe('1.0.2');
    expect($status->details['jails'])->toBe(['sshd', 'apache-auth']);
});

test('perimeter facade can get intrusion prevention jails', function () {
    // Setup mock with expected behavior
    $mockService = setupMockService('getJails', [], ['sshd', 'apache-auth']);

    // Call the facade method
    $jails = Perimeter::getIntrusionPreventionJails();

    // Assert the result
    expect($jails)->toBe(['sshd', 'apache-auth']);
});

test('perimeter facade can get jail status', function () {
    // Setup mock with expected behavior
    $mockService = setupMockService('getJailStatus', ['sshd'], [
        'jail' => 'sshd',
        'currently_failed' => 5,
        'total_failed' => 27,
        'banned_ips' => ['192.168.1.100', '203.0.113.25'],
    ]);

    // Call the facade method
    $status = Perimeter::getJailStatus('sshd');

    // Assert the result
    expect($status['jail'])->toBe('sshd');
    expect($status['currently_failed'])->toBe(5);
    expect($status['total_failed'])->toBe(27);
    expect($status['banned_ips'])->toBe(['192.168.1.100', '203.0.113.25']);
});

test('perimeter facade can get banned ips', function () {
    // Setup mock with expected behavior
    $mockService = setupMockService('getBannedIPs', ['sshd'],
        ['192.168.1.100', '203.0.113.25']);

    // Call the facade method
    $ips = Perimeter::getBannedIPs('sshd');

    // Assert the result
    expect($ips)->toBe(['192.168.1.100', '203.0.113.25']);
});

test('perimeter facade can unban ip', function () {
    // Setup mock with expected behavior
    $mockService = setupMockService('unbanIP', ['192.168.1.100', 'sshd'], true);

    // Call the facade method
    $result = Perimeter::unbanIP('192.168.1.100', 'sshd');

    // Assert the result
    expect($result)->toBeTrue();
});

test('perimeter facade can get intrusion events', function () {
    // Sample events
    $events = [
        [
            'timestamp' => '2025-06-16T13:25:45+00:00',
            'component' => 'actions',
            'level' => 'notice',
            'message' => '[sshd] Unban 192.168.1.100',
            'jail' => 'sshd',
            'action' => 'unban',
            'ip' => '192.168.1.100',
        ],
        [
            'timestamp' => '2025-06-16T11:44:15+00:00',
            'component' => 'actions',
            'level' => 'notice',
            'message' => '[sshd] Ban 203.0.113.25',
            'jail' => 'sshd',
            'action' => 'ban',
            'ip' => '203.0.113.25',
        ],
    ];

    // Setup mock with expected behavior
    $mockService = setupMockService('getRecentEvents', [10], $events);

    // Call the facade method
    $result = Perimeter::getIntrusionEvents(10);

    // Assert the result
    expect($result)->toBe($events);
});

// Clean up after each test
afterEach(function () {
    \Mockery::close();
});
