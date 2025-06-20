<?php

namespace Prahsys\Perimeter\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;
use Prahsys\Perimeter\Perimeter;
use Prahsys\Perimeter\PerimeterServiceProvider;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        //        $logDir = storage_path('logs');
        $logDir = __DIR__.'/../storage/logs/'; // Adjust path as needed
        $logPath = $logDir.'laravel.log';
        // Ensure storage/logs path exists
        if (! is_dir(dirname($logDir))) {
            echo "Creating storage/logs directory...\n$logDir\n";
            mkdir($logDir, 0777, true);
        }

        config([
            'logging.default' => 'stack', // or 'single'
            'logging.channels.stack' => [
                'driver' => 'stack',
                'channels' => ['single'],
            ],
            'logging.channels.single' => [
                'driver' => 'single',
                'path' => $logPath,
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

    protected function getPackageAliases($app)
    {
        return [
            'Perimeter' => Perimeter::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Use in-memory database for testing
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Disable database storage for security events in testing
        $app['config']->set('perimeter.storage.enabled', false);
    }
}
