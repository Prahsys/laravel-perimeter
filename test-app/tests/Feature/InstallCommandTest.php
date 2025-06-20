<?php

it('can display service-specific install commands', function () {
    // List all available commands
    $output = shell_exec('php artisan list | grep perimeter:install');

    // Verify the command produces some output
    expect($output)->not->toBeEmpty();

});
