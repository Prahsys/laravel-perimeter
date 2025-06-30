<?php

namespace Prahsys\Perimeter;

use Illuminate\Support\ServiceProvider;
use Prahsys\Perimeter\Commands\InstallClamAV;
use Prahsys\Perimeter\Commands\InstallFail2ban;
use Prahsys\Perimeter\Commands\InstallFalco;
use Prahsys\Perimeter\Commands\InstallTrivy;
use Prahsys\Perimeter\Commands\InstallUfw;
use Prahsys\Perimeter\Commands\PerimeterAudit;
use Prahsys\Perimeter\Commands\PerimeterHealth;
use Prahsys\Perimeter\Commands\PerimeterInstall;
use Prahsys\Perimeter\Commands\PerimeterMonitor;
use Prahsys\Perimeter\Commands\PerimeterPrune;
use Prahsys\Perimeter\Commands\PerimeterReport;
use Prahsys\Perimeter\Commands\PerimeterSeedTestData;
use Prahsys\Perimeter\Commands\PerimeterTerminate;
use Prahsys\Perimeter\Contracts\FirewallServiceInterface;
use Prahsys\Perimeter\Contracts\IntrusionPreventionInterface;
use Prahsys\Perimeter\Contracts\MonitorServiceInterface;
use Prahsys\Perimeter\Contracts\ScannerServiceInterface;
use Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\Fail2banService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\ReportingService;
use Prahsys\Perimeter\Services\TrivyService;
use Prahsys\Perimeter\Services\UfwService;

class PerimeterServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/perimeter.php', 'perimeter'
        );

        // Register Spatie's LaravelData package if it hasn't been registered
        if (! $this->app->bound('laravel-data.pipeline')) {
            $this->app->register(\Spatie\LaravelData\LaravelDataServiceProvider::class);
        }

        // Register the ServiceManager
        $this->app->singleton(Services\ServiceManager::class, function ($app) {
            $manager = new Services\ServiceManager;

            // Register services from the services configuration
            $services = config('perimeter.services', []);
            foreach ($services as $className => $config) {
                // Skip disabled services
                if (isset($config['enabled']) && $config['enabled'] === false) {
                    continue;
                }

                // Register the service class with its configuration
                $manager->registerClass($className, $config);
            }

            return $manager;
        });

        // Register service interfaces

        // Register concrete implementations first
        $this->app->singleton(ClamAVService::class, function ($app) {
            return $app->make(Services\ServiceManager::class)->get('clamav');
        });

        $this->app->singleton(FalcoService::class, function ($app) {
            return $app->make(Services\ServiceManager::class)->get('falco');
        });

        $this->app->singleton(TrivyService::class, function ($app) {
            return $app->make(Services\ServiceManager::class)->get('trivy');
        });

        $this->app->singleton(UfwService::class, function ($app) {
            return $app->make(Services\ServiceManager::class)->get('ufw');
        });

        $this->app->singleton(Fail2banService::class, function ($app) {
            return $app->make(Services\ServiceManager::class)->get('fail2ban');
        });

        // Register interfaces to their default implementations
        $this->app->singleton(ScannerServiceInterface::class, function ($app) {
            return $app->make(ClamAVService::class);
        });

        $this->app->singleton(MonitorServiceInterface::class, function ($app) {
            return $app->make(FalcoService::class);
        });

        $this->app->singleton(VulnerabilityScannerInterface::class, function ($app) {
            return $app->make(TrivyService::class);
        });

        $this->app->singleton(FirewallServiceInterface::class, function ($app) {
            return $app->make(UfwService::class);
        });

        $this->app->singleton(IntrusionPreventionInterface::class, function ($app) {
            return $app->make(Fail2banService::class);
        });

        // AppArmor Manager
        $this->app->singleton(Services\AppArmorManager::class);

        // Reporting Service (not managed by ServiceManager)
        $this->app->singleton(ReportingService::class, function ($app) {
            return new ReportingService(config('perimeter.reporting'));
        });

        // Register the facade
        $this->app->singleton('perimeter', function ($app) {
            // Create a new Perimeter instance with the ServiceManager
            return new Perimeter(
                $app->make(Services\ServiceManager::class),
                $app->make(ReportingService::class)
            );
        });

        // Register reporting service alias for compliance reports
        $this->app->alias(ReportingService::class, 'perimeter.reporting');
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        // Publish configuration and migrations
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/perimeter.php' => config_path('perimeter.php'),
            ], 'perimeter-config');

            // Publish migrations
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'perimeter-migrations');

            // Load migrations automatically
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

            // Register commands
            $this->commands([
                PerimeterAudit::class,
                PerimeterMonitor::class,
                PerimeterTerminate::class,
                PerimeterReport::class,
                PerimeterHealth::class,
                PerimeterInstall::class,
                InstallClamAV::class,
                InstallFalco::class,
                InstallFail2ban::class,
                InstallTrivy::class,
                InstallUfw::class,
                PerimeterPrune::class,
                PerimeterSeedTestData::class,
            ]);
        }

        // Register middleware
        $this->app['router']->aliasMiddleware(
            'perimeter.protect', \Prahsys\Perimeter\Http\Middleware\PerimeterProtection::class
        );

        // Set up automatic pruning of old records if enabled
        if (config('perimeter.storage.auto_prune', true)) {
            $this->setupAutoPruning();
        }
    }

    /**
     * Set up automatic pruning for old security records.
     *
     * @return void
     */
    protected function setupAutoPruning()
    {
        // For Laravel 8.79+ with automatic model pruning, we don't need to do anything.
        // Laravel will automatically handle pruning for models that use the Prunable trait
        // through its own model pruning service.

        // The PerimeterPrune command is still available for manual pruning or
        // for applications using older Laravel versions.
    }
}
