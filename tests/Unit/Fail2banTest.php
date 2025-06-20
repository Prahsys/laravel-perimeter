<?php

use Illuminate\Support\Facades\File;
use Prahsys\Perimeter\Contracts\IntrusionPreventionInterface;
use Prahsys\Perimeter\Parsers\Fail2banOutputParser;
use Prahsys\Perimeter\Services\Fail2banService;

test('fail2ban service implements intrusion prevention interface', function () {
    $service = new Fail2banService(['enabled' => true]);
    expect($service)->toBeInstanceOf(IntrusionPreventionInterface::class);
});

test('fail2ban parser can parse status output from example file', function () {
    // Load the example output
    $examplePath = __DIR__.'/../../resources/examples/fail2ban/status.txt';
    expect(File::exists($examplePath))->toBeTrue('Example file not found');

    $output = File::get($examplePath);
    $result = Fail2banOutputParser::parseStatus($output);

    expect($result['running'])->toBeTrue();
    expect($result['version'])->toBe('1.0.2');
    expect($result['jails'])->toBe(['sshd', 'apache-auth', 'php-url-fopen', 'nginx-http-auth']);
});

test('fail2ban parser can parse sshd jail status from example file', function () {
    // Load the example output
    $examplePath = __DIR__.'/../../resources/examples/fail2ban/jail-status-sshd.txt';
    expect(File::exists($examplePath))->toBeTrue('Example file not found');

    $output = File::get($examplePath);
    $result = Fail2banOutputParser::parseJailStatus($output);

    expect($result['jail'])->toBe('sshd');
    expect($result['currently_failed'])->toBe(5);
    expect($result['total_failed'])->toBe(27);
    expect($result['banned_ips'])->toBe(['192.168.1.100', '203.0.113.25']);
});

test('fail2ban parser can parse apache jail status from example file', function () {
    // Load the example output
    $examplePath = __DIR__.'/../../resources/examples/fail2ban/jail-status-apache.txt';
    expect(File::exists($examplePath))->toBeTrue('Example file not found');

    $output = File::get($examplePath);
    $result = Fail2banOutputParser::parseJailStatus($output);

    expect($result['jail'])->toBe('apache-auth');
    expect($result['currently_failed'])->toBe(1);
    expect($result['total_failed'])->toBe(8);
    expect($result['file_list'])->toBe(['/var/log/apache2/error.log']);
    expect($result['banned_ips'])->toBe(['198.51.100.23']);
});

test('fail2ban parser can parse log events from example file', function () {
    // Load the example output
    $examplePath = __DIR__.'/../../resources/examples/fail2ban/log.txt';
    expect(File::exists($examplePath))->toBeTrue('Example file not found');

    $output = File::get($examplePath);

    // Get the most recent 10 events
    $events = Fail2banOutputParser::parseLogEvents($output, 10);

    // Verify we found some events
    expect($events)->not->toBeEmpty('No events parsed from log file');

    // Check for specific events
    $hasSshdBan = false;
    $hasApacheBan = false;

    foreach ($events as $event) {
        if ($event['component'] === 'actions' &&
            $event['level'] === 'notice' &&
            $event['jail'] === 'sshd' &&
            $event['action'] === 'ban' &&
            $event['ip'] === '203.0.113.25') {
            $hasSshdBan = true;
        }

        if ($event['component'] === 'actions' &&
            $event['level'] === 'notice' &&
            $event['jail'] === 'apache-auth' &&
            $event['action'] === 'ban' &&
            $event['ip'] === '198.51.100.23') {
            $hasApacheBan = true;
        }
    }

    // Check that we found both ban events
    expect($hasSshdBan)->toBeTrue('Missing sshd ban event');
    expect($hasApacheBan)->toBeTrue('Missing apache-auth ban event');
});

test('fail2ban service methods can be mocked for testing', function () {
    $mockConfig = [
        'enabled' => true,
        'log_path' => '/var/log/fail2ban.log',
        'jail_config_path' => '/etc/fail2ban/jail.local',
        'enabled_jails' => ['sshd', 'apache-auth'],
        'ban_time' => 3600,
        'max_retry' => 5,
        'find_time' => 600,
    ];

    // Create a partial mock of the service
    $service = Mockery::mock(Fail2banService::class, [$mockConfig])->makePartial();

    // Mock the necessary methods
    $service->shouldReceive('isInstalled')->andReturn(true);

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

    $service->shouldReceive('getStatus')->andReturn($statusData);
    $service->shouldReceive('getJails')->andReturn(['sshd', 'apache-auth']);
    $service->shouldReceive('isConfigured')->andReturn(true);

    // Test the mocked methods
    expect($service->isEnabled())->toBeTrue();
    expect($service->isInstalled())->toBeTrue();
    expect($service->isConfigured())->toBeTrue();
    expect($service->getJails())->toBe(['sshd', 'apache-auth']);

    // Test that the config works
    expect($service->getConfig())->toBe($mockConfig);

    // Clean up Mockery after the test
    Mockery::close();
});
