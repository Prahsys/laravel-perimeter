<?php

use Illuminate\Support\Facades\Artisan;

it('can run the perimeter:monitor command', function () {

    // Check that the monitor command exists and responds to help
    $helpOutput = shell_exec('php artisan perimeter:monitor --help');
    expect($helpOutput)->not->toBeEmpty();

    // Check for basic options in the help text
    expect($helpOutput)->toContain('monitor');

    // Run with a minimal duration to avoid hanging the test
    $output = shell_exec('php artisan perimeter:monitor --duration=2');

    // Should produce some output
    expect($output)->not->toBeEmpty();
});
