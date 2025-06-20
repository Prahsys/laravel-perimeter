<?php

use Illuminate\Support\Facades\File;
use Prahsys\Perimeter\Parsers\ClamAVOutputParser;

test('clamav parser extracts infected files', function () {
    // Load the infected scan output example
    $scanOutput = File::get(getExamplesPath().'/clamav/infected_scan.txt');
    expect($scanOutput)->not->toBeEmpty();

    // Parse with the parser
    $results = ClamAVOutputParser::parseInfectedFiles($scanOutput);

    // We should have 3 infected files
    expect($results)->toHaveCount(3);

    // Check the first result
    expect($results[0]['file'])->toBe('/uploads/malicious.exe');
    expect($results[0]['threat'])->toBe('Win.Malware.Trojan-1');

    // Check the second result
    expect($results[1]['file'])->toBe('/var/www/html/uploads/backdoor.php');
    expect($results[1]['threat'])->toBe('PHP.Shell.Backdoor-4');
});

test('clamav parser extracts scan summary', function () {
    // Load the infected scan output example
    $scanOutput = File::get(getExamplesPath().'/clamav/infected_scan.txt');
    expect($scanOutput)->not->toBeEmpty();

    // Parse with the parser
    $summary = ClamAVOutputParser::parseScanSummary($scanOutput);

    // We should have key metrics
    expect($summary)->toHaveKey('known_viruses');
    expect($summary)->toHaveKey('infected_files');
    expect($summary['infected_files'])->toBe('3');
    expect($summary['known_viruses'])->toBe('8707525');
});
