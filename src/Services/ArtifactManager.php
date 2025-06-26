<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;

class ArtifactManager
{
    protected array $config;
    protected string $auditId;
    protected string $auditPath;
    protected $disk;

    public function __construct(array $config = [])
    {
        $this->config = array_merge(config('perimeter.artifacts', []), $config);
        $this->disk = Storage::disk($this->config['disk'] ?? 'local');
    }

    /**
     * Initialize artifacts for a new audit
     */
    public function initializeAudit(string $auditId): string
    {
        $this->auditId = $auditId;
        $this->auditPath = $this->getAuditPath($auditId);

        $this->ensureDirectoryExists($this->auditPath);
        $this->createAuditMetadata();

        return $this->auditPath;
    }

    /**
     * Save an artifact for the current audit
     */
    public function saveArtifact(string $service, string $type, string $content, array $metadata = []): ?string
    {
        if (!$this->auditPath) {
            return null;
        }

        $filename = $this->generateArtifactFilename($service, $type);
        $filepath = $this->auditPath . '/' . $filename;

        // Save the main content
        $this->disk->put($filepath, $content);

        // Save metadata if provided
        if (!empty($metadata)) {
            $metadataFile = $filepath . '.meta.json';
            $this->disk->put($metadataFile, json_encode([
                'service' => $service,
                'type' => $type,
                'timestamp' => now()->toISOString(),
                'audit_id' => $this->auditId,
                'file_size' => strlen($content),
                'metadata' => $metadata,
            ], JSON_PRETTY_PRINT));
        }

        Log::debug("Artifact saved: {$filename}");

        return $filepath;
    }

    /**
     * Save raw command output as an artifact
     */
    public function saveCommandOutput(string $service, string $command, string $output, int $exitCode = 0): ?string
    {

        $sanitizedCommand = preg_replace('/[^a-zA-Z0-9_-]/', '_', $command);
        $filename = "{$service}_command_{$sanitizedCommand}.txt";
        $filepath = $this->auditPath . '/' . $filename;

        $content = "# Command: {$command}\n";
        $content .= "# Exit Code: {$exitCode}\n";
        $content .= "# Timestamp: " . now()->toISOString() . "\n";
        $content .= "# Audit ID: {$this->auditId}\n";
        $content .= "\n" . $output;

        $this->disk->put($filepath, $content);

        return $filepath;
    }

    /**
     * Save structured data as JSON artifact
     */
    public function saveJsonArtifact(string $service, string $type, array $data): ?string
    {
        $content = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        return $this->saveArtifact($service, $type, $content, [
            'format' => 'json',
            'records_count' => is_array($data) ? count($data) : null,
        ]);
    }

    /**
     * Save audit summary with all artifacts
     */
    public function finalizeAudit(array $summary): void
    {
        if (!$this->auditPath) {
            return;
        }

        $summaryFile = $this->auditPath . '/audit_summary.json';
        $auditSummary = [
            'audit_id' => $this->auditId,
            'completed_at' => now()->toISOString(),
            'summary' => $summary,
            'artifacts' => $this->getArtifactsList(),
        ];

        $this->disk->put($summaryFile, json_encode($auditSummary, JSON_PRETTY_PRINT));

        // Update audit metadata
        $this->updateAuditMetadata(['completed_at' => now()->toISOString()]);

        // Compress upon finalization
        $this->compress();

        Log::info("Audit artifacts finalized: {$this->auditPath}");
    }

    /**
     * Get the path for a specific audit
     */
    public function getAuditPath(string $auditId): string
    {
        $rootPath = $this->config['root_path'] ?? 'perimeter/audits';

        // Extract date from audit ID (format: Y-m-d_H-i-s_uniqid)
        $datePart = substr($auditId, 0, 10); // Get first 10 chars (Y-m-d)
        $date = Carbon::createFromFormat('Y-m-d', $datePart)->format('Y-m-d');

        return "{$rootPath}/{$date}/{$auditId}";
    }

    /**
     * List all artifacts for the current audit
     */
    public function getArtifactsList(): array
    {
        if (!$this->auditPath || !$this->disk->exists($this->auditPath)) {
            return [];
        }

        $artifacts = [];
        $files = $this->disk->files($this->auditPath);

        foreach ($files as $file) {
            $filename = basename($file);

            // Skip metadata files and summary
            if (str_ends_with($filename, '.meta.json') || $filename === 'audit_summary.json' || $filename === 'audit_metadata.json') {
                continue;
            }

            $artifacts[] = [
                'filename' => $filename,
                'size' => $this->disk->size($file),
                'path' => $file,
                'modified' => Carbon::createFromTimestamp($this->disk->lastModified($file))->toISOString(),
            ];
        }

        return $artifacts;
    }

    /**
     * Clean up old artifacts based on retention policy
     */
    public function cleanupOldArtifacts(): int
    {

        $rootPath = $this->config['root_path'] ?? 'perimeter/audits';
        $retentionDays = $this->config['retention_days'] ?? 90;
        $cutoffDate = now()->subDays($retentionDays);

        $deletedCount = 0;

        if (!$this->disk->exists($rootPath)) {
            return 0;
        }

        // Clean up old audit directories
        $dateDirs = $this->disk->directories($rootPath);

        foreach ($dateDirs as $dateDir) {
            $dirname = basename($dateDir);

            try {
                $dirDate = Carbon::createFromFormat('Y-m-d', $dirname);

                if ($dirDate->lt($cutoffDate)) {
                    Log::info("Cleaning up old artifacts: {$dateDir}");
                    $this->disk->deleteDirectory($dateDir);
                    $deletedCount++;
                }
            } catch (\Exception $e) {
                Log::warning("Could not parse date directory: {$dirname}");
            }
        }

        return $deletedCount;
    }

    /**
     * Compress current audit immediately upon finalization
     */
    public function compress(): bool
    {
        if (!$this->auditPath) {
            return false;
        }

        try {
            $zipFile = $this->auditPath . '.zip';

            if (!$this->disk->exists($zipFile)) {
                $this->compressDirectory($this->auditPath, $zipFile);
                $this->disk->deleteDirectory($this->auditPath);

                Log::info("Compressed audit artifacts: {$this->auditId}");
                return true;
            }
        } catch (\Exception $e) {
            Log::warning("Could not compress audit: {$this->auditId} - " . $e->getMessage());
        }

        return false;
    }

    /**
     * Get the full local path for an audit (for external tools that need filesystem paths)
     */
    public function getLocalPath(string $auditId = null): string
    {
        $auditId = $auditId ?: $this->auditId;
        $auditPath = $this->getAuditPath($auditId);

        // For local disk, get the full filesystem path
        if ($this->disk->getAdapter() instanceof \League\Flysystem\Local\LocalFilesystemAdapter) {
            return $this->disk->path($auditPath);
        }

        // For other disks, return the relative path
        return $auditPath;
    }


    /**
     * Ensure directory exists
     */
    protected function ensureDirectoryExists(string $path): void
    {
        if (!$this->disk->exists($path)) {
            $this->disk->makeDirectory($path);
        }
    }

    /**
     * Generate artifact filename
     */
    protected function generateArtifactFilename(string $service, string $type): string
    {
        $timestamp = now()->format('His'); // HHMMSS
        $sanitizedType = preg_replace('/[^a-zA-Z0-9_-]/', '_', $type);

        return "{$service}_{$sanitizedType}_{$timestamp}.txt";
    }

    /**
     * Create audit metadata file
     */
    protected function createAuditMetadata(): void
    {
        $metadataFile = $this->auditPath . '/audit_metadata.json';
        $metadata = [
            'audit_id' => $this->auditId,
            'started_at' => now()->toISOString(),
            'hostname' => gethostname(),
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'perimeter_version' => '1.0.0', // TODO: Get from package version
            'disk' => $this->config['disk'] ?? 'local',
            'root_path' => $this->config['root_path'] ?? 'perimeter/audits',
        ];

        $this->disk->put($metadataFile, json_encode($metadata, JSON_PRETTY_PRINT));
    }

    /**
     * Update audit metadata
     */
    protected function updateAuditMetadata(array $updates): void
    {
        $metadataFile = $this->auditPath . '/audit_metadata.json';

        if ($this->disk->exists($metadataFile)) {
            $metadata = json_decode($this->disk->get($metadataFile), true);
            $metadata = array_merge($metadata, $updates);
            $this->disk->put($metadataFile, json_encode($metadata, JSON_PRETTY_PRINT));
        }
    }

    /**
     * Compress a directory to ZIP (for local disk only)
     */
    protected function compressDirectory(string $sourceDir, string $zipFile): void
    {
        // Only compress if using local disk
        if (!($this->disk->getAdapter() instanceof \League\Flysystem\Local\LocalFilesystemAdapter)) {
            Log::warning("Compression only supported for local disk storage");
            return;
        }

        $localSourceDir = $this->disk->path($sourceDir);
        $localZipFile = $this->disk->path($zipFile);

        $zip = new \ZipArchive();

        if ($zip->open($localZipFile, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== TRUE) {
            throw new \Exception("Could not create zip file: {$localZipFile}");
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($localSourceDir),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($files as $file) {
            if (!$file->isDir()) {
                $filePath = $file->getRealPath();
                $relativePath = substr($filePath, strlen($localSourceDir) + 1);
                $zip->addFile($filePath, $relativePath);
            }
        }

        $zip->close();
    }
}
