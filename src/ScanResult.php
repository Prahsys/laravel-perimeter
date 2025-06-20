<?php

namespace Prahsys\Perimeter;

class ScanResult
{
    /**
     * Create a new scan result instance.
     *
     * @return void
     */
    public function __construct(
        protected string $filePath,
        protected bool $hasThreat = false,
        protected ?string $threat = null,
        protected ?string $fileHash = null
    ) {
        //
    }

    /**
     * Determine if the scan found a threat.
     */
    public function hasThreat(): bool
    {
        return $this->hasThreat;
    }

    /**
     * Get the threat description.
     */
    public function getThreat(): ?string
    {
        return $this->threat;
    }

    /**
     * Get the file path that was scanned.
     */
    public function getFilePath(): string
    {
        return $this->filePath;
    }

    /**
     * Get the file hash, if available.
     */
    public function getFileHash(): ?string
    {
        return $this->fileHash;
    }

    /**
     * Create a new scan result for a clean file.
     *
     * @return static
     */
    public static function clean(string $filePath, ?string $fileHash = null): self
    {
        return new static($filePath, false, null, $fileHash);
    }

    /**
     * Create a new scan result for an infected file.
     *
     * @return static
     */
    public static function infected(string $filePath, string $threat, ?string $fileHash = null): self
    {
        return new static($filePath, true, $threat, $fileHash);
    }
}
