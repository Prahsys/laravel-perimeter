<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\ScanResult;

class ClamAVService
{
    /**
     * Create a new ClamAV service instance.
     *
     * @param array $config
     * @return void
     */
    public function __construct(protected array $config)
    {
        //
    }

    /**
     * Scan a single file for threats.
     *
     * @param string $filePath
     * @return \Prahsys\Perimeter\ScanResult
     */
    public function scanFile(string $filePath): ScanResult
    {
        if (!$this->isEnabled()) {
            return ScanResult::clean($filePath);
        }

        try {
            // In a real implementation, we would connect to ClamAV socket
            // and perform the actual scan. For demo purposes, we simulate.
            $scanCommand = "clamdscan --fdpass " . escapeshellarg($filePath);
            
            // Simulate scanning (in real implementation, we'd execute the command)
            // $output = shell_exec($scanCommand);
            
            // For demonstration, randomly simulate infected files (1% chance)
            $isInfected = (rand(1, 100) === 1);
            
            if ($isInfected) {
                return ScanResult::infected($filePath, $this->getRandomMalwareName());
            }
            
            return ScanResult::clean($filePath);
        } catch (\Exception $e) {
            Log::error('ClamAV scan failed: ' . $e->getMessage(), [
                'file' => $filePath,
                'exception' => $e,
            ]);
            
            // In case of error, we consider the file clean but log the error
            return ScanResult::clean($filePath);
        }
    }

    /**
     * Scan multiple paths for threats.
     *
     * @param array $paths
     * @param array $excludePatterns
     * @return array
     */
    public function scanPaths(array $paths, array $excludePatterns = []): array
    {
        if (!$this->isEnabled()) {
            return [];
        }

        $results = [];

        foreach ($paths as $path) {
            // In a real implementation, we would recursively scan files
            // For demo purposes, we just simulate a few files
            $sampleFiles = $this->getSampleFilesInPath($path);
            
            foreach ($sampleFiles as $file) {
                // Skip excluded patterns
                $excluded = false;
                foreach ($excludePatterns as $pattern) {
                    if (fnmatch($pattern, $file)) {
                        $excluded = true;
                        break;
                    }
                }
                
                if (!$excluded) {
                    $result = $this->scanFile($file);
                    
                    if ($result->hasThreat()) {
                        $results[] = [
                            'file' => $result->getFilePath(),
                            'threat' => $result->getThreat(),
                            'timestamp' => now()->toIso8601String(),
                        ];
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Check if ClamAV service is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Enable real-time file scanning.
     *
     * @return bool
     */
    public function enableRealtime(): bool
    {
        // In a real implementation, this would enable OnAccess scanning
        // through ClamAV's clamonacc utility
        return true;
    }

    /**
     * Disable real-time file scanning.
     *
     * @return bool
     */
    public function disableRealtime(): bool
    {
        // In a real implementation, this would disable OnAccess scanning
        return true;
    }

    /**
     * Get sample files in a path for simulation purposes.
     *
     * @param string $path
     * @return array
     */
    protected function getSampleFilesInPath(string $path): array
    {
        // For demo purposes, we simulate files in the path
        return [
            $path . '/index.php',
            $path . '/app/Http/Controllers/UserController.php',
            $path . '/storage/app/uploads/document.pdf',
            $path . '/public/js/app.js',
            $path . '/resources/views/welcome.blade.php',
        ];
    }

    /**
     * Get a random malware name for simulation purposes.
     *
     * @return string
     */
    protected function getRandomMalwareName(): string
    {
        $malwareTypes = [
            'Trojan.PHP.Agent',
            'Backdoor.PHP.Shell',
            'Virus.Win32.Sality',
            'Ransomware.Cryptolocker',
            'PUP.JS.Miner',
            'Adware.HTML.Script',
        ];

        return $malwareTypes[array_rand($malwareTypes)];
    }
}