<?php

namespace Prahsys\Perimeter;

class ScanResult
{
    /**
     * Create a new scan result instance.
     *
     * @param string $filePath
     * @param bool $hasThreat
     * @param string|null $threat
     * @return void
     */
    public function __construct(
        protected string $filePath,
        protected bool $hasThreat = false,
        protected ?string $threat = null
    ) {
        //
    }

    /**
     * Determine if the scan found a threat.
     *
     * @return bool
     */
    public function hasThreat(): bool
    {
        return $this->hasThreat;
    }

    /**
     * Get the threat description.
     *
     * @return string|null
     */
    public function getThreat(): ?string
    {
        return $this->threat;
    }

    /**
     * Get the file path that was scanned.
     *
     * @return string
     */
    public function getFilePath(): string
    {
        return $this->filePath;
    }

    /**
     * Create a new scan result for a clean file.
     *
     * @param string $filePath
     * @return static
     */
    public static function clean(string $filePath): self
    {
        return new static($filePath, false, null);
    }

    /**
     * Create a new scan result for an infected file.
     *
     * @param string $filePath
     * @param string $threat
     * @return static
     */
    public static function infected(string $filePath, string $threat): self
    {
        return new static($filePath, true, $threat);
    }
}