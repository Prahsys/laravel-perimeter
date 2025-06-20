<?php

use Illuminate\Support\Facades\Artisan;

it('can run the perimeter:audit command in Docker', function () {

    // Run the audit command and check for basic output
    $output = shell_exec('php artisan perimeter:audit');

    // Verify the command produces some output
    expect($output)->not->toBeEmpty();

    // The audit command should have some basic information
    expect($output)->toContain('Security Audit');
});
