<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Prahsys\Perimeter\PerimeterServiceProvider;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;

    protected function setUp(): void
    {
        parent::setUp();

        // Ensure logs directory exists
        $logDir = storage_path('logs');
        if (! is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        // Set up logging configuration
        config([
            'logging.default' => 'stack',
            'logging.channels.stack' => [
                'driver' => 'stack',
                'channels' => ['single'],
            ],
            'logging.channels.single' => [
                'driver' => 'single',
                'path' => storage_path('logs/laravel.log'),
                'level' => 'debug',
            ],
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [
            PerimeterServiceProvider::class,
        ];
    }
}
