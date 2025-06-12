<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;

class TrivyService
{
    /**
     * Create a new Trivy service instance.
     *
     * @param array $config
     * @return void
     */
    public function __construct(protected array $config)
    {
        //
    }

    /**
     * Scan dependencies for vulnerabilities.
     *
     * @return array
     */
    public function scanDependencies(): array
    {
        if (!$this->isEnabled()) {
            return [];
        }

        try {
            $results = [];
            
            foreach ($this->config['scan_paths'] as $path) {
                // In a real implementation, this would run Trivy against the files
                // For demo purposes, we simulate results based on file type
                
                if (str_ends_with($path, 'composer.lock')) {
                    $results = array_merge($results, $this->scanComposerLock($path));
                } elseif (str_ends_with($path, 'package-lock.json') || str_ends_with($path, 'yarn.lock')) {
                    $results = array_merge($results, $this->scanNpmLock($path));
                }
            }
            
            // Filter results by severity threshold
            return $this->filterBySeverity($results);
        } catch (\Exception $e) {
            Log::error('Trivy scan failed: ' . $e->getMessage(), [
                'exception' => $e,
            ]);
            
            return [];
        }
    }

    /**
     * Scan specific file for vulnerabilities.
     *
     * @param string $filePath
     * @return array
     */
    public function scanFile(string $filePath): array
    {
        if (!$this->isEnabled()) {
            return [];
        }

        try {
            // In a real implementation, this would run Trivy against the file
            // For demo purposes, we simulate results based on file type
            
            if (str_ends_with($filePath, 'composer.lock')) {
                return $this->filterBySeverity($this->scanComposerLock($filePath));
            } elseif (str_ends_with($filePath, 'package-lock.json') || str_ends_with($filePath, 'yarn.lock')) {
                return $this->filterBySeverity($this->scanNpmLock($filePath));
            }
            
            return [];
        } catch (\Exception $e) {
            Log::error('Trivy scan failed: ' . $e->getMessage(), [
                'file' => $filePath,
                'exception' => $e,
            ]);
            
            return [];
        }
    }

    /**
     * Check if Trivy service is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Simulate scanning a composer.lock file.
     *
     * @param string $filePath
     * @return array
     */
    protected function scanComposerLock(string $filePath): array
    {
        // In a real implementation, this would run Trivy against composer.lock
        // For demo purposes, we simulate some PHP vulnerabilities
        
        return [
            [
                'packageName' => 'symfony/http-kernel',
                'version' => '5.4.0',
                'severity' => 'HIGH',
                'title' => 'HTTP Request Smuggling in Symfony HttpFoundation',
                'description' => 'Improper input validation in the HTTP foundation component may lead to HTTP request smuggling.',
                'cve' => 'CVE-2024-1234',
                'fixedVersion' => '5.4.22',
            ],
            [
                'packageName' => 'laravel/framework',
                'version' => '8.40.0',
                'severity' => 'MEDIUM',
                'title' => 'Potential XSS vulnerability in Laravel pagination links',
                'description' => 'The pagination component does not properly escape URLs, which can lead to XSS attacks.',
                'cve' => 'CVE-2023-5678',
                'fixedVersion' => '8.40.2',
            ],
            [
                'packageName' => 'guzzlehttp/guzzle',
                'version' => '7.0.0',
                'severity' => 'CRITICAL',
                'title' => 'Certificate validation bypass in Guzzle',
                'description' => 'A vulnerability in certificate validation can allow MITM attacks.',
                'cve' => 'CVE-2022-9876',
                'fixedVersion' => '7.0.1',
            ],
        ];
    }

    /**
     * Simulate scanning a package-lock.json or yarn.lock file.
     *
     * @param string $filePath
     * @return array
     */
    protected function scanNpmLock(string $filePath): array
    {
        // In a real implementation, this would run Trivy against package-lock.json
        // For demo purposes, we simulate some JavaScript vulnerabilities
        
        return [
            [
                'packageName' => 'axios',
                'version' => '0.21.0',
                'severity' => 'HIGH',
                'title' => 'Server-Side Request Forgery in axios',
                'description' => 'Axios before 0.21.1 allows server-side request forgery (SSRF) attacks.',
                'cve' => 'CVE-2020-28168',
                'fixedVersion' => '0.21.1',
            ],
            [
                'packageName' => 'lodash',
                'version' => '4.17.15',
                'severity' => 'MEDIUM',
                'title' => 'Prototype Pollution in lodash',
                'description' => 'Versions of lodash prior to 4.17.20 are vulnerable to Prototype Pollution.',
                'cve' => 'CVE-2020-8203',
                'fixedVersion' => '4.17.20',
            ],
            [
                'packageName' => 'minimist',
                'version' => '1.2.5',
                'severity' => 'LOW',
                'title' => 'Prototype Pollution in minimist',
                'description' => 'The minimist package before 1.2.6 is vulnerable to Prototype Pollution.',
                'cve' => 'CVE-2021-44906',
                'fixedVersion' => '1.2.6',
            ],
        ];
    }

    /**
     * Filter results by severity threshold.
     *
     * @param array $results
     * @return array
     */
    protected function filterBySeverity(array $results): array
    {
        $threshold = $this->config['severity_threshold'] ?? 'MEDIUM';
        $severityLevels = [
            'CRITICAL' => 4,
            'HIGH' => 3,
            'MEDIUM' => 2,
            'LOW' => 1,
        ];
        
        $thresholdLevel = $severityLevels[$threshold] ?? 2;
        
        return array_filter($results, function ($result) use ($severityLevels, $thresholdLevel) {
            $resultLevel = $severityLevels[$result['severity']] ?? 0;
            return $resultLevel >= $thresholdLevel;
        });
    }
}