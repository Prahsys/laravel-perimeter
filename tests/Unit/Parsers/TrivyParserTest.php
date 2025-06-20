<?php

use Illuminate\Support\Facades\File;
use Prahsys\Perimeter\Parsers\TrivyOutputParser;

test('trivy parser extracts vulnerabilities', function () {
    // Load the JSON vulnerability findings
    $jsonData = File::get(getExamplesPath().'/trivy/vulnerability_findings.json');
    expect($jsonData)->not->toBeEmpty();

    // Parse with the parser
    $vulnerabilities = TrivyOutputParser::parseVulnerabilities($jsonData);

    // We should have 3 vulnerabilities
    expect($vulnerabilities)->toHaveCount(3);

    // Check the first vulnerability
    expect($vulnerabilities[0]['packageName'])->toBe('symfony/http-kernel');
    expect($vulnerabilities[0]['version'])->toBe('5.4.8');
    expect($vulnerabilities[0]['severity'])->toBe('CRITICAL');
    expect($vulnerabilities[0]['cve'])->toBe('CVE-2023-25575');
    expect($vulnerabilities[0]['fixedVersion'])->toBe('5.4.21');

    // Check the third vulnerability
    expect($vulnerabilities[2]['packageName'])->toBe('laravel/framework');
    expect($vulnerabilities[2]['version'])->toBe('8.83.5');
    expect($vulnerabilities[2]['severity'])->toBe('CRITICAL');
    expect($vulnerabilities[2]['title'])->toBe('Laravel Framework: URL validation vulnerability');
});

test('trivy parser handles empty json', function () {
    $emptyJson = '{"SchemaVersion": 2, "Results": []}';
    $vulnerabilities = TrivyOutputParser::parseVulnerabilities($emptyJson);
    expect($vulnerabilities)->toBeEmpty();

    $invalidJson = 'not json';
    $vulnerabilities = TrivyOutputParser::parseVulnerabilities($invalidJson);
    expect($vulnerabilities)->toBeEmpty();
});
