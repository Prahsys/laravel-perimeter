<?php

namespace Prahsys\Perimeter\Tests\Feature;

use Illuminate\Http\UploadedFile;
use Mockery;
use Orchestra\Testbench\TestCase;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\Http\Middleware\PerimeterProtection;
use Prahsys\Perimeter\PerimeterServiceProvider;
use Prahsys\Perimeter\ScanResult;
use Prahsys\Perimeter\Services\ClamAVService;

class MiddlewareTest extends TestCase
{
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

    protected function setUp(): void
    {
        parent::setUp();

        // Mock the ClamAV service
        $this->app->singleton(ClamAVService::class, function () {
            return Mockery::mock(ClamAVService::class, function ($mock) {
                $mock->shouldReceive('isEnabled')->andReturn(true);
                $mock->shouldReceive('scanFile')->andReturn(ScanResult::clean('/path/to/file'));
            });
        });

        // Set up route with middleware
        $this->app['router']->post('/test-upload', function () {
            return response()->json(['success' => true]);
        })->middleware(PerimeterProtection::class);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /** @test */
    public function it_allows_safe_file_uploads()
    {
        $file = UploadedFile::fake()->create('document.pdf', 100);

        $response = $this->postJson('/test-upload', [
            'file' => $file,
        ]);

        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    }

    /** @test */
    public function it_blocks_malicious_file_uploads()
    {
        // Override the mock to return an infected file
        $this->app->singleton(ClamAVService::class, function () {
            return Mockery::mock(ClamAVService::class, function ($mock) {
                $mock->shouldReceive('isEnabled')->andReturn(true);
                $mock->shouldReceive('scanFile')->andReturn(
                    ScanResult::infected('/path/to/file', 'Trojan.PHP.Agent')
                );
            });
        });

        $file = UploadedFile::fake()->create('malicious.php', 100);

        $response = $this->postJson('/test-upload', [
            'file' => $file,
        ]);

        $response->assertStatus(422);
        $response->assertSee('Security threat detected');
    }
}