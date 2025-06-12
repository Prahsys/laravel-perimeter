<?php

namespace Prahsys\Perimeter;

use Illuminate\Support\ServiceProvider;
use Prahsys\Perimeter\Commands\PerimeterAudit;
use Prahsys\Perimeter\Commands\PerimeterHealth;
use Prahsys\Perimeter\Commands\PerimeterInstall;
use Prahsys\Perimeter\Commands\PerimeterMonitor;
use Prahsys\Perimeter\Commands\PerimeterReport;
use Prahsys\Perimeter\Services\ClamAVService;
use Prahsys\Perimeter\Services\FalcoService;
use Prahsys\Perimeter\Services\ReportingService;
use Prahsys\Perimeter\Services\TrivyService;

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

        // Register the facade
        $this->app->singleton('perimeter', function ($app) {
            return new Perimeter(
                $app->make(ClamAVService::class),
                $app->make(FalcoService::class),
                $app->make(TrivyService::class),
                $app->make(ReportingService::class)
            );
        });

        // Register services
        $this->app->singleton(ClamAVService::class, function ($app) {
            return new ClamAVService(config('perimeter.clamav'));
        });

        $this->app->singleton(FalcoService::class, function ($app) {
            return new FalcoService(config('perimeter.falco'));
        });

        $this->app->singleton(TrivyService::class, function ($app) {
            return new TrivyService(config('perimeter.trivy'));
        });

        $this->app->singleton(ReportingService::class, function ($app) {
            return new ReportingService(config('perimeter.reporting'));
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
        // Publish configuration
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/perimeter.php' => config_path('perimeter.php'),
            ], 'perimeter-config');

            // Register commands
            $this->commands([
                PerimeterAudit::class,
                PerimeterMonitor::class,
                PerimeterReport::class,
                PerimeterHealth::class,
                PerimeterInstall::class,
            ]);
        }

        // Register middleware
        $this->app['router']->aliasMiddleware(
            'perimeter.protect', \Prahsys\Perimeter\Http\Middleware\PerimeterProtection::class
        );
    }
}