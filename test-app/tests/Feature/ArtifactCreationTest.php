<?php

use Illuminate\Support\Facades\Storage;
use Prahsys\Perimeter\Services\ArtifactManager;

function getArtifactStorage() {
    return Storage::disk(config('perimeter.artifacts.disk', 'local'));
}

it('creates audit artifacts with metadata when running audit command', function () {
    $storage = getArtifactStorage();
    
    // Clear any existing artifacts
    $storage->deleteDirectory('perimeter');
    
    // Run a limited audit to avoid timeouts - just UFW
    $output = shell_exec('php artisan perimeter:audit --services=ufw 2>&1');
    
    // Verify the command completed successfully
    expect($output)->toContain('completed at:')
        ->and($output)->toContain('Audit artifacts saved to:');
    
    // Check that artifacts directory was created
    expect($storage->exists('perimeter/audits'))->toBeTrue();
    
    // Find today's audit directory
    $todayDir = 'perimeter/audits/' . now()->format('Y-m-d');
    expect($storage->exists($todayDir))->toBeTrue("Today's audit directory not found: $todayDir");
    
    // Should have either directories or zip files (due to immediate compression)
    $auditDirs = $storage->directories($todayDir);
    $zipFiles = collect($storage->files($todayDir))->filter(fn($file) => str_ends_with($file, '.zip'));
    
    expect($auditDirs)->not->toBeEmpty()
        ->or($zipFiles)->not->toBeEmpty();
    
    // If we have zip files, verify one contains the expected metadata
    if ($zipFiles->isNotEmpty()) {
        $zipFile = $zipFiles->first();
        $localZipPath = $storage->path($zipFile);
        
        // Extract to check contents
        $extractDir = sys_get_temp_dir() . '/audit_test_' . uniqid();
        mkdir($extractDir, 0755, true);
        
        $zip = new ZipArchive();
        if ($zip->open($localZipPath) === TRUE) {
            $zip->extractTo($extractDir);
            $zip->close();
            
            // Check for metadata file
            $metadataFile = $extractDir . '/audit_metadata.json';
            expect(file_exists($metadataFile))->toBeTrue();
            
            $metadata = json_decode(file_get_contents($metadataFile), true);
            expect($metadata)->toBeArray()
                ->and($metadata)->toHaveKey('audit_id')
                ->and($metadata)->toHaveKey('started_at')
                ->and($metadata)->toHaveKey('hostname')
                ->and($metadata)->toHaveKey('php_version')
                ->and($metadata['audit_id'])->toMatch('/^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_[a-f0-9]+$/');
            
            // Check for summary file
            $summaryFile = $extractDir . '/audit_summary.json';
            expect(file_exists($summaryFile))->toBeTrue();
            
            $summary = json_decode(file_get_contents($summaryFile), true);
            expect($summary)->toBeArray()
                ->and($summary)->toHaveKey('audit_id')
                ->and($summary)->toHaveKey('completed_at')
                ->and($summary)->toHaveKey('summary')
                ->and($summary['summary'])->toHaveKey('services_audited')
                ->and($summary['summary']['services_audited'])->toContain('ufw');
            
            // Cleanup
            array_map('unlink', glob("$extractDir/*"));
            rmdir($extractDir);
        }
    }
});

it('creates and saves individual artifacts through ArtifactManager', function () {
    $artifactManager = new ArtifactManager();
    
    // Initialize an audit
    $auditId = now()->format('Y-m-d_H-i-s') . '_test_' . uniqid();
    $auditPath = $artifactManager->initializeAudit($auditId);
    
    expect($auditPath)->toBeString()
        ->and(Storage::exists($auditPath))->toBeTrue();
    
    // Save test artifacts
    $testContent = "Test UFW Status Output\n" . 
                   "Status: active\n" .
                   "To                Action      From\n" .
                   "--                ------      ----\n" .
                   "22/tcp            ALLOW IN    Anywhere\n" .
                   "80/tcp            ALLOW IN    Anywhere\n";
    
    $artifactPath = $artifactManager->saveArtifact('ufw', 'status', $testContent, [
        'command' => 'ufw status verbose',
        'timestamp' => now()->toISOString()
    ]);
    
    expect($artifactPath)->not->toBeNull()
        ->and(Storage::exists($artifactPath))->toBeTrue();
    
    // Verify artifact content
    $savedContent = Storage::get($artifactPath);
    expect($savedContent)->toBe($testContent);
    
    // Verify metadata file
    $metadataPath = $artifactPath . '.meta.json';
    expect(Storage::exists($metadataPath))->toBeTrue();
    
    $metadata = json_decode(Storage::get($metadataPath), true);
    expect($metadata)->toBeArray()
        ->and($metadata['service'])->toBe('ufw')
        ->and($metadata['type'])->toBe('status')
        ->and($metadata['audit_id'])->toBe($auditId)
        ->and($metadata['metadata']['command'])->toBe('ufw status verbose');
    
    // Save command output
    $commandPath = $artifactManager->saveCommandOutput('ufw', 'ufw status', $testContent, 0);
    expect($commandPath)->not->toBeNull()
        ->and(Storage::exists($commandPath))->toBeTrue();
    
    // Save JSON artifact
    $jsonData = [
        'scan_results' => [
            'service' => 'ufw',
            'status' => 'active',
            'rules_count' => 3,
            'issues_found' => 0
        ]
    ];
    
    $jsonPath = $artifactManager->saveJsonArtifact('ufw', 'scan_results', $jsonData);
    expect($jsonPath)->not->toBeNull()
        ->and(Storage::exists($jsonPath))->toBeTrue();
    
    $savedJson = json_decode(Storage::get($jsonPath), true);
    expect($savedJson)->toBe($jsonData);
    
    // Get artifacts list
    $artifactsList = $artifactManager->getArtifactsList();
    expect($artifactsList)->toBeArray()
        ->and(count($artifactsList))->toBeGreaterThan(0);
    
    // Finalize audit
    $summary = [
        'services_audited' => ['ufw'],
        'total_artifacts' => count($artifactsList),
        'test_run' => true
    ];
    
    $artifactManager->finalizeAudit($summary);
    
    // Check if compression happened (config dependent)
    $zipFile = $auditPath . '.zip';
    if (config('perimeter.artifacts.compress_old', true)) {
        expect(Storage::exists($zipFile))->toBeTrue()
            ->and(Storage::exists($auditPath))->toBeFalse(); // Original directory should be removed
    }
});

it('includes artifact information in audit output', function () {
    // Clear any existing artifacts
    Storage::deleteDirectory('perimeter');
    
    // Run audit and capture output
    $output = shell_exec('php artisan perimeter:audit --services=ufw 2>&1');
    
    // Verify audit mentions artifacts
    expect($output)->toContain('Audit artifacts will be saved to:')
        ->and($output)->toContain('perimeter/audits/')
        ->and($output)->toContain('Audit artifacts saved to:');
    
    // Verify the path mentioned in output actually exists (as directory or zip)
    preg_match('/Audit artifacts saved to: (.+)$/m', $output, $matches);
    
    if (!empty($matches[1])) {
        $artifactPath = trim($matches[1]);
        $zipPath = $artifactPath . '.zip';
        
        // Should exist as either directory or zip file
        expect(Storage::exists($artifactPath))->toBeTrue()
            ->or(Storage::exists($zipPath))->toBeTrue();
    } else {
        // Just check that today's artifacts directory exists
        $todayDir = 'perimeter/audits/' . now()->format('Y-m-d');
        expect(Storage::exists($todayDir))->toBeTrue();
    }
});

it('compresses artifacts immediately when compression is enabled', function () {
    // Ensure compression is enabled
    config(['perimeter.artifacts.compress_old' => true]);
    
    $artifactManager = new ArtifactManager();
    $auditId = now()->format('Y-m-d_H-i-s') . '_compress_test';
    $auditPath = $artifactManager->initializeAudit($auditId);
    
    // Add some content
    $artifactManager->saveArtifact('test', 'data', 'Test content for compression');
    
    // Finalize (should trigger compression)
    $artifactManager->finalizeAudit(['test' => 'complete']);
    
    // Check that zip file exists and original directory is removed
    $zipFile = $auditPath . '.zip';
    expect(Storage::exists($zipFile))->toBeTrue()
        ->and(Storage::exists($auditPath))->toBeFalse();
    
    // Verify zip has content
    expect(Storage::size($zipFile))->toBeGreaterThan(0);
});