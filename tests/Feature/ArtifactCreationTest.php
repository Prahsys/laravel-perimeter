<?php

use Illuminate\Support\Facades\Storage;
use Prahsys\Perimeter\Services\ArtifactManager;

function getArtifactStorage() {
    return Storage::disk(config('perimeter.artifacts.disk', 'local'));
}

it('creates and saves individual artifacts through ArtifactManager', function () {
    $artifactManager = new ArtifactManager();
    
    // Initialize an audit
    $auditId = now()->format('Y-m-d_H-i-s') . '_test_' . uniqid();
    $auditPath = $artifactManager->initializeAudit($auditId);
    
    expect($auditPath)->toBeString()
        ->and(Storage::exists($auditPath))->toBeTrue();
    
    // Save test artifacts using simplified interface
    $testContent = "Test UFW Status Output\n" . 
                   "Status: active\n" .
                   "To                Action      From\n" .
                   "--                ------      ----\n" .
                   "22/tcp            ALLOW IN    Anywhere\n" .
                   "80/tcp            ALLOW IN    Anywhere\n";
    
    $artifactPath = $artifactManager->saveArtifact('ufw_status.txt', $testContent, [
        'service' => 'ufw',
        'type' => 'status',
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
        ->and($metadata['metadata']['service'])->toBe('ufw')
        ->and($metadata['metadata']['type'])->toBe('status')
        ->and($metadata['audit_id'])->toBe($auditId)
        ->and($metadata['metadata']['command'])->toBe('ufw status verbose');
    
    // Save command output
    $commandPath = $artifactManager->saveCommandOutput('ufw_command_output.txt', 'ufw status', $testContent, 0);
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
    
    $jsonPath = $artifactManager->saveJsonArtifact('ufw_scan_results.json', $jsonData);
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
    
    // Check if compression happened (artifacts are always compressed)
    $zipFile = $auditPath . '.zip';
    expect(Storage::exists($zipFile))->toBeTrue()
        ->and(Storage::exists($auditPath))->toBeFalse(); // Original directory should be removed
});

it('compresses artifacts immediately when finalized', function () {
    // Artifacts are always compressed when finalized
    $artifactManager = new ArtifactManager();
    $auditId = now()->format('Y-m-d_H-i-s') . '_compress_test';
    $auditPath = $artifactManager->initializeAudit($auditId);
    
    // Add some content
    $artifactManager->saveArtifact('test_data.txt', 'Test content for compression', [
        'service' => 'test',
        'type' => 'data'
    ]);
    
    // Finalize (should trigger compression)
    $artifactManager->finalizeAudit(['test' => 'complete']);
    
    // Check that zip file exists and original directory is removed
    $zipFile = $auditPath . '.zip';
    expect(Storage::exists($zipFile))->toBeTrue()
        ->and(Storage::exists($auditPath))->toBeFalse();
    
    // Verify zip has content
    expect(Storage::size($zipFile))->toBeGreaterThan(0);
});

it('uses simplified artifact manager interface correctly', function () {
    $artifactManager = new ArtifactManager();
    $auditId = now()->format('Y-m-d_H-i-s') . '_interface_test';
    $artifactManager->initializeAudit($auditId);
    
    // Test the simplified interface: saveArtifact(relativePath, content, metadata)
    $relativePath = 'service/logs/output.txt';
    $content = 'Test log content';
    $metadata = ['service' => 'test', 'type' => 'log'];
    
    $result = $artifactManager->saveArtifact($relativePath, $content, $metadata);
    
    expect($result)->not->toBeNull()
        ->and(Storage::exists($result))->toBeTrue()
        ->and(Storage::get($result))->toBe($content);
    
    // Test command output method
    $cmdResult = $artifactManager->saveCommandOutput('cmd_output.txt', 'test command', 'command output', 0);
    expect($cmdResult)->not->toBeNull()
        ->and(Storage::exists($cmdResult))->toBeTrue();
    
    $cmdContent = Storage::get($cmdResult);
    expect($cmdContent)->toContain('# Command: test command')
        ->and($cmdContent)->toContain('# Exit Code: 0')
        ->and($cmdContent)->toContain('command output');
    
    // Test JSON artifact method
    $jsonData = ['test' => 'data', 'number' => 123];
    $jsonResult = $artifactManager->saveJsonArtifact('data.json', $jsonData);
    expect($jsonResult)->not->toBeNull()
        ->and(Storage::exists($jsonResult))->toBeTrue();
    
    $savedJson = json_decode(Storage::get($jsonResult), true);
    expect($savedJson)->toBe($jsonData);
});