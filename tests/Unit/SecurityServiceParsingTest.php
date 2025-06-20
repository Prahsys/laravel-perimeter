<?php

use Illuminate\Support\Facades\File;
use Prahsys\Perimeter\Parsers\ClamAVOutputParser;
use Prahsys\Perimeter\Parsers\FalcoOutputParser;
use Prahsys\Perimeter\Parsers\TrivyOutputParser;
use Prahsys\Perimeter\ScanResult;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\TrivyService;

test('clamav scan result to dto', function () {
    // Create a ScanResult with a threat
    $scanResult = new ScanResult('/path/to/file.txt', true, 'Eicar-Test-Signature');

    // Create data object from scan result
    $service = new ClamAVService;
    $data = $service->resultToSecurityEventData([
        'timestamp' => now(),
        'threat' => $scanResult->getThreat(),
        'file' => $scanResult->getFilePath(),
        'hash' => $scanResult->getFileHash(),
        'scan_id' => 123,
    ]);

    // Assert the data object has the correct values
    expect($data->getType())->toBe('malware');
    expect($data->getDescription())->toBe('Detected Eicar-Test-Signature in file');
    expect($data->getLocation())->toBe('/path/to/file.txt');
    expect($data->getScanId())->toBe(123);
});

test('clamav infected scan output to dto', function () {
    // Load the infected scan output example
    $scanOutput = File::get(getExamplesPath().'/clamav/infected_scan.txt');
    expect($scanOutput)->not->toBeEmpty();

    // Parse the output using our parser
    $results = ClamAVOutputParser::parseInfectedFiles($scanOutput);

    // Convert each result to a DTO
    $dtos = [];
    foreach ($results as $result) {
        $service = new ClamAVService;
        $result['scan_id'] = 123;
        $dtos[] = $service->resultToSecurityEventData($result);
    }

    // We should have 3 infected files
    expect($dtos)->toHaveCount(3);

    // Assert the first DTO
    expect($dtos[0]->getType())->toBe('malware');
    expect($dtos[0]->getDescription())->toBe('Detected Win.Malware.Trojan-1 in file');
    expect($dtos[0]->getLocation())->toBe('/uploads/malicious.exe');
    expect($dtos[0]->getScanId())->toBe(123);

    // Assert the second DTO
    expect($dtos[1]->getType())->toBe('malware');
    expect($dtos[1]->getDescription())->toBe('Detected PHP.Shell.Backdoor-4 in file');
    expect($dtos[1]->getLocation())->toBe('/var/www/html/uploads/backdoor.php');
    expect($dtos[1]->getScanId())->toBe(123);
});

test('falco detected events to dto', function () {
    // Load the detected events example
    $eventsOutput = File::get(getExamplesPath().'/falco/detected_events.txt');
    expect($eventsOutput)->not->toBeEmpty();

    // Parse the output using our parser
    $results = FalcoOutputParser::parseTextEvents($eventsOutput);

    // Convert each result to a DTO
    $dtos = [];
    foreach ($results as $result) {
        $service = new FalcoService;
        $result['scan_id'] = 123;
        $dtos[] = $service->resultToSecurityEventData($result);
    }

    // We should have at least one event
    expect($dtos)->not->toBeEmpty();

    // Assert the first DTO - Critical shell spawned
    expect($dtos[0]->getType())->toBe('behavioral');
    expect($dtos[0]->getSeverity())->toBe('critical');
    expect($dtos[0]->getDescription())->toBe('A shell was spawned in a container with an attached terminal');
    expect($dtos[0]->getLocation())->toBe('process:bash');
    expect($dtos[0]->getUser())->toBe('root');
    expect($dtos[0]->getScanId())->toBe(123);
});

test('falco json events to dto', function () {
    // Load the JSON events example
    $jsonData = File::get(getExamplesPath().'/falco/monitor_events.json');
    expect($jsonData)->not->toBeEmpty();

    // Parse the JSON data using our parser
    $events = FalcoOutputParser::parseJsonEvents($jsonData);
    expect($events)->not->toBeEmpty();

    // Convert each event to a DTO
    $dtos = [];
    foreach ($events as $event) {
        $service = new FalcoService;
        $event['scan_id'] = 123;
        $dtos[] = $service->resultToSecurityEventData($event);
    }

    // We should have 3 events as per the JSON file
    expect($dtos)->toHaveCount(3);

    // Assert the first DTO - Terminal shell in container
    expect($dtos[0]->getType())->toBe('behavioral');
    expect($dtos[0]->getSeverity())->toBe('critical');
    expect($dtos[0]->getDescription())->toBe('A shell was spawned in a container with an attached terminal');
    expect($dtos[0]->getLocation())->toBe('process:bash');
    expect($dtos[0]->getUser())->toBe('root');
    expect($dtos[0]->getScanId())->toBe(123);

    $details = $dtos[0]->getDetails();
    expect($details['rule'])->toBe('Terminal shell in container');
    expect($details['process'])->toBe('bash');
    expect($details['details']['container_id'])->toBe('3dc26b7c86f8');
    expect($details['details']['container_name'])->toBe('prahsys-laravel-perimeter');
    expect($details['details']['command'])->toBe('bash');
});

test('trivy vulnerability json to dto', function () {
    // Load the JSON vulnerability findings
    $jsonData = File::get(getExamplesPath().'/trivy/vulnerability_findings.json');
    expect($jsonData)->not->toBeEmpty();

    // Parse vulnerabilities using our parser
    $vulnerabilities = TrivyOutputParser::parseVulnerabilities($jsonData);

    // Convert each vulnerability to a DTO
    $dtos = [];
    foreach ($vulnerabilities as $vulnerability) {
        $service = new TrivyService;
        $vulnerability['scan_id'] = 123;
        $dtos[] = $service->resultToSecurityEventData($vulnerability);
    }

    // Assert we have 3 vulnerabilities as per the example file
    expect($dtos)->toHaveCount(3);

    // Assert the first DTO - symfony/http-kernel vulnerability
    $firstDto = $dtos[0];
    expect($firstDto->getType())->toBe('vulnerability');
    expect($firstDto->getSeverity())->toBe('critical');
    expect($firstDto->getDescription())->toBe('Symfony HttpKernel: Request forgery through unvalidated redirects');
    expect($firstDto->getLocation())->toBe('symfony/http-kernel');
    expect($firstDto->getScanId())->toBe(123);

    $details = $firstDto->getDetails();
    expect($details['package'])->toBe('symfony/http-kernel');
    expect($details['version'])->toBe('5.4.8');
    expect($details['cve'])->toBe('CVE-2023-25575');
    expect($details['fixed_version'])->toBe('5.4.21');

    // Assert the third DTO - Laravel framework vulnerability
    $thirdDto = $dtos[2];
    expect($thirdDto->getType())->toBe('vulnerability');
    expect($thirdDto->getSeverity())->toBe('critical');
    expect($thirdDto->getDescription())->toBe('Laravel Framework: URL validation vulnerability');
    expect($thirdDto->getLocation())->toBe('laravel/framework');
    expect($thirdDto->getScanId())->toBe(123);

    $details = $thirdDto->getDetails();
    expect($details['package'])->toBe('laravel/framework');
    expect($details['version'])->toBe('8.83.5');
    expect($details['cve'])->toBe('CVE-2021-43808');
    expect($details['fixed_version'])->toBe('8.83.27');
});
