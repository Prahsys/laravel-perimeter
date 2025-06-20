<?php

use Illuminate\Support\Facades\Artisan;

it('can run the perimeter:report command', function () {

    // Check that the report command exists and responds to help
    $helpOutput = shell_exec('php artisan perimeter:report --help');
    expect($helpOutput)->not->toBeEmpty();

    // Check for basic options in the help text
    expect($helpOutput)->toContain('report');

    // Run report with no arguments
    $output = shell_exec('php artisan perimeter:report');

    // Should produce some output
    expect($output)->not->toBeEmpty();
});
