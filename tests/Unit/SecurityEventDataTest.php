<?php

use Prahsys\Perimeter\Data\SecurityEventData;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\TrivyService;

test('it creates dto from malware scan', function () {
    $malwareScanResult = [
        'timestamp' => '2025-06-16T12:00:00+00:00',
        'threat' => 'Virus.Test.EICAR',
        'file' => '/path/to/infected/file.txt',
        'hash' => 'abc123',
        'severity' => 'critical',
    ];

    $service = new ClamAVService;
    $data = $service->resultToSecurityEventData($malwareScanResult, 'scan-123');

    expect($data->getTimestamp()->format('Y-m-d\TH:i:s\+00:00'))->toBe('2025-06-16T12:00:00+00:00');
    expect($data->getType())->toBe('malware');
    expect($data->getSeverity())->toBe('critical');
    expect($data->getDescription())->toBe('Detected Virus.Test.EICAR in file');
    expect($data->getLocation())->toBe('/path/to/infected/file.txt');
    expect($data->getUser())->toBeNull();

    $details = $data->getDetails();
    expect($details['threat'])->toBe('Virus.Test.EICAR');
    expect($details['file'])->toBe('/path/to/infected/file.txt');
    expect($details['hash'])->toBe('abc123');
    expect($details['scan_id'])->toBe('scan-123');
});

test('it creates dto from vulnerability scan', function () {
    $vulnerabilityScanResult = [
        'timestamp' => '2025-06-16T12:00:00+00:00',
        'severity' => 'HIGH',
        'title' => 'Remote Code Execution in Example Package',
        'packageName' => 'example/vulnerable-package',
        'version' => '1.0.0',
        'cve' => 'CVE-2025-1234',
        'fixedVersion' => '1.0.1',
    ];

    $service = new TrivyService;
    $data = $service->resultToSecurityEventData($vulnerabilityScanResult, 'scan-123');

    expect($data->getTimestamp()->format('Y-m-d\TH:i:s\+00:00'))->toBe('2025-06-16T12:00:00+00:00');
    expect($data->getType())->toBe('vulnerability');
    expect($data->getSeverity())->toBe('high'); // Should be lowercased
    expect($data->getDescription())->toBe('Remote Code Execution in Example Package');
    expect($data->getLocation())->toBe('example/vulnerable-package');
    expect($data->getUser())->toBeNull();

    $details = $data->getDetails();
    expect($details['package'])->toBe('example/vulnerable-package');
    expect($details['version'])->toBe('1.0.0');
    expect($details['cve'])->toBe('CVE-2025-1234');
    expect($details['fixed_version'])->toBe('1.0.1');
    expect($details['scan_id'])->toBe('scan-123');
});

test('it creates dto from behavioral analysis', function () {
    $behavioralResult = [
        'timestamp' => '2025-06-16T12:00:00+00:00',
        'priority' => 'critical',
        'description' => 'Privilege escalation detected',
        'process' => 'suspicious_binary',
        'user' => 'www-data',
        'rule' => 'privilege_escalation',
        'details' => [
            'command' => 'chmod +s /bin/bash',
            'container_id' => 'abc123',
        ],
    ];

    $service = new FalcoService;
    $data = $service->resultToSecurityEventData($behavioralResult, 'scan-123');

    expect($data->getTimestamp()->format('Y-m-d\TH:i:s\+00:00'))->toBe('2025-06-16T12:00:00+00:00');
    expect($data->getType())->toBe('behavioral');
    expect($data->getSeverity())->toBe('critical');
    expect($data->getDescription())->toBe('Privilege escalation detected');
    expect($data->getLocation())->toBe('process:suspicious_binary');
    expect($data->getUser())->toBe('www-data');

    $details = $data->getDetails();
    expect($details['rule'])->toBe('privilege_escalation');
    expect($details['process'])->toBe('suspicious_binary');
    expect($details['details']['command'])->toBe('chmod +s /bin/bash');
    expect($details['details']['container_id'])->toBe('abc123');
    expect($details['scan_id'])->toBe('scan-123');
});

test('it creates dto with missing data', function () {
    $incompleteResult = [
        'threat' => 'Unknown Malware',
    ];

    $service = new ClamAVService;
    $data = $service->resultToSecurityEventData($incompleteResult);

    // Should fill in defaults
    expect($data->getTimestamp())->toBeInstanceOf(\DateTime::class);
    expect($data->getType())->toBe('malware');
    expect($data->getSeverity())->toBe('critical');
    expect($data->getDescription())->toBe('Detected Unknown Malware in file');
    expect($data->getLocation())->toBeNull();
    expect($data->getUser())->toBeNull();

    $details = $data->getDetails();
    expect($details['threat'])->toBe('Unknown Malware');
    expect($details['file'])->toBeNull();
    expect($details['hash'])->toBeNull();
    expect($details['scan_id'])->toBeNull();
});

test('it converts to array', function () {
    $data = new SecurityEventData(
        '2025-06-16T12:00:00+00:00',
        'test_type',
        'high',
        'Test description',
        '/test/location',
        'test_user',
        ['key' => 'value']
    );

    $array = $data->toArray();

    expect($array)->toBeArray();
    expect($array['timestamp'])->toBe('2025-06-16T12:00:00+00:00');
    expect($array['type'])->toBe('test_type');
    expect($array['severity'])->toBe('high');
    expect($array['description'])->toBe('Test description');
    expect($array['location'])->toBe('/test/location');
    expect($array['user'])->toBe('test_user');
    expect($array['details'])->toBe(['key' => 'value']);
});

test('it converts to model array', function () {
    $data = new SecurityEventData(
        '2025-06-16T12:00:00+00:00',
        'test_type',
        'high',
        'Test description',
        '/test/location',
        'test_user',
        ['key' => 'value', 'scan_id' => 'test-scan']
    );

    $array = $data->toModelArray();

    expect($array)->toBeArray();
    expect($array['timestamp'])->toBeInstanceOf(\DateTime::class);
    expect($array['type'])->toBe('test_type');
    expect($array['severity'])->toBe('high');
    expect($array['description'])->toBe('Test description');
    expect($array['location'])->toBe('/test/location');
    expect($array['user'])->toBe('test_user');
    expect($array['details'])->toBe(['key' => 'value', 'scan_id' => 'test-scan']);
    expect($array['scan_id'])->toBe('test-scan');
});
