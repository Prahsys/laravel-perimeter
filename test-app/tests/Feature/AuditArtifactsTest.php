<?php

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Artisan;

it('creates artifacts when running perimeter audit command', function () {
    $storage = Storage::disk(config('perimeter.artifacts.disk', 'local'));
    $rootPath = config('perimeter.artifacts.root_path', 'perimeter/audits');
    
    // Clear any existing artifacts
    $storage->deleteDirectory('perimeter');
    
    // Run audit command (using only fail2ban since it's installed in Docker)
    $exitCode = Artisan::call('perimeter:audit', [
        '--services' => 'fail2ban'
    ]);
    
    // Command should succeed
    expect($exitCode)->toBe(0);
    
    // Check that artifacts directory was created
    expect($storage->exists($rootPath))->toBeTrue();
    
    // Find today's audit directory
    $todayDir = $rootPath . '/' . now()->format('Y-m-d');
    expect($storage->exists($todayDir))->toBeTrue("Today's audit directory not found: $todayDir");
    
    // Should have either directories or zip files (artifacts are compressed)
    $auditDirs = $storage->directories($todayDir);
    $zipFiles = collect($storage->files($todayDir))->filter(fn($file) => str_ends_with($file, '.zip'));
    
    // Should have either audit directories or zip files
    $hasContent = !empty($auditDirs) || $zipFiles->isNotEmpty();
    expect($hasContent)->toBeTrue('No audit directories or zip files found');
    
    // If we have zip files, verify structure
    if ($zipFiles->isNotEmpty()) {
        $zipFile = $zipFiles->first();
        $localZipPath = $storage->path($zipFile);
        
        // Verify zip file exists and has content
        expect(file_exists($localZipPath))->toBeTrue()
            ->and(filesize($localZipPath))->toBeGreaterThan(0);
        
        // Extract and check for required files
        $extractDir = sys_get_temp_dir() . '/audit_test_' . uniqid();
        mkdir($extractDir, 0755, true);
        
        $zip = new ZipArchive();
        if ($zip->open($localZipPath) === TRUE) {
            $zip->extractTo($extractDir);
            $zip->close();
            
            // Check for required metadata files
            expect(file_exists($extractDir . '/audit_metadata.json'))->toBeTrue();
            expect(file_exists($extractDir . '/audit_summary.json'))->toBeTrue();
            expect(file_exists($extractDir . '/audit_log.txt'))->toBeTrue();
            
            // Verify metadata structure
            $metadata = json_decode(file_get_contents($extractDir . '/audit_metadata.json'), true);
            expect($metadata)->toBeArray()
                ->and($metadata)->toHaveKey('audit_id')
                ->and($metadata)->toHaveKey('started_at')
                ->and($metadata)->toHaveKey('hostname');
            
            // Verify summary structure
            $summary = json_decode(file_get_contents($extractDir . '/audit_summary.json'), true);
            expect($summary)->toBeArray()
                ->and($summary)->toHaveKey('audit_id')
                ->and($summary)->toHaveKey('completed_at')
                ->and($summary)->toHaveKey('summary');
            
            // Verify audit log has content
            $auditLog = file_get_contents($extractDir . '/audit_log.txt');
            expect($auditLog)->not->toBeEmpty()
                ->and($auditLog)->toContain('Intrusion Prevention');
            
            // Cleanup
            array_map('unlink', glob("$extractDir/*"));
            rmdir($extractDir);
        }
    }
});

it('creates artifacts in correct directory structure', function () {
    $storage = Storage::disk(config('perimeter.artifacts.disk', 'local'));
    
    // Clear existing artifacts
    $storage->deleteDirectory('perimeter');
    
    // Run audit
    Artisan::call('perimeter:audit', ['--services' => 'fail2ban']);
    
    // Check directory structure follows expected pattern
    $rootDir = 'perimeter/audits';
    expect($storage->exists($rootDir))->toBeTrue();
    
    $todayDir = $rootDir . '/' . now()->format('Y-m-d');
    expect($storage->exists($todayDir))->toBeTrue();
    
    // Should have either audit directories or zip files
    $contents = array_merge(
        $storage->directories($todayDir),
        $storage->files($todayDir)
    );
    
    expect($contents)->not->toBeEmpty();
    
    // Verify at least one item follows the audit ID pattern (date_time_uniqid)
    $hasValidAuditId = false;
    foreach ($contents as $item) {
        $basename = basename($item);
        // Remove .zip extension if present
        $basename = str_replace('.zip', '', $basename);
        
        if (preg_match('/^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_[a-f0-9]+$/', $basename)) {
            $hasValidAuditId = true;
            break;
        }
    }
    
    expect($hasValidAuditId)->toBeTrue('No valid audit ID pattern found in artifacts');
});