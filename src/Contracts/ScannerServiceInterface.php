<?php

namespace Prahsys\Perimeter\Contracts;

use Prahsys\Perimeter\ScanResult;

interface ScannerServiceInterface extends SecurityServiceInterface
{
    /**
     * Scan a single file for threats.
     */
    public function scanFile(string $filePath): ScanResult;

    /**
     * Scan multiple paths for threats.
     */
    public function scanPaths(array $paths, array $excludePatterns = []): array;

    /**
     * Update virus definitions if applicable.
     */
    public function updateDefinitions(): bool;
}
