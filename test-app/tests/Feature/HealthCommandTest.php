<?php

it('can run the perimeter:health command in Docker', function () {

    // Run the health command and check for basic output
    $output = shell_exec('php artisan perimeter:health');

    // Verify the command produces some output
    expect($output)->not->toBeEmpty();
});
