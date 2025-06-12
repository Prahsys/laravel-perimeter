<?php

namespace Prahsys\Perimeter\Tests;

use Illuminate\Http\UploadedFile;
use Mockery;
use Orchestra\Testbench\TestCase;
use Prahsys\Perimeter\Facades\Perimeter;
use Prahsys\Perimeter\PerimeterServiceProvider;
use Prahsys\Perimeter\ScanResult;
use Prahsys\Perimeter\Services\ClamAVService;

class PerimeterTest extends TestCase
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

    public function setUp(): void
    {
        parent::setUp();
        
        // Mock the ClamAV service to avoid actual system calls
        $this->app->singleton(ClamAVService::class, function () {
            return Mockery::mock(ClamAVService::class, function ($mock) {
                $mock->shouldReceive('isEnabled')->andReturn(true);
                $mock->shouldReceive('scanFile')->andReturn(ScanResult::clean('/path/to/file'));
            });
        });
    }

    public function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /** @test */
    public function it_can_scan_a_file()
    {
        $file = UploadedFile::fake()->create('document.pdf', 100);
        
        $result = Perimeter::scan($file);
        
        $this->assertInstanceOf(ScanResult::class, $result);
        $this->assertFalse($result->hasThreat());
        $this->assertNull($result->getThreat());
    }

    /** @test */
    public function it_can_detect_threats_in_a_file()
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
        
        $file = UploadedFile::fake()->create('document.php', 100);
        
        $result = Perimeter::scan($file);
        
        $this->assertInstanceOf(ScanResult::class, $result);
        $this->assertTrue($result->hasThreat());
        $this->assertEquals('Trojan.PHP.Agent', $result->getThreat());
    }

    /** @test */
    public function it_can_register_and_trigger_threat_callbacks()
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
        
        $callbackCalled = false;
        $detectedThreat = null;
        
        Perimeter::onThreatDetected(function ($result) use (&$callbackCalled, &$detectedThreat) {
            $callbackCalled = true;
            $detectedThreat = $result->getThreat();
        });
        
        $file = UploadedFile::fake()->create('document.php', 100);
        Perimeter::scan($file);
        
        $this->assertTrue($callbackCalled);
        $this->assertEquals('Trojan.PHP.Agent', $detectedThreat);
    }
}