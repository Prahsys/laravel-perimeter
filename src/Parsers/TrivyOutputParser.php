<?php

namespace Prahsys\Perimeter\Parsers;

class TrivyOutputParser
{
    /**
     * Parse Trivy JSON output and extract vulnerabilities.
     *
     * @param  string  $jsonData  The JSON output from Trivy
     * @return array Array of vulnerabilities
     */
    public static function parseVulnerabilities(string $jsonData): array
    {
        $data = json_decode($jsonData, true);
        if (! is_array($data) || ! isset($data['Results'])) {
            return [];
        }

        $vulnerabilities = [];

        foreach ($data['Results'] as $result) {
            if (isset($result['Vulnerabilities']) && is_array($result['Vulnerabilities'])) {
                foreach ($result['Vulnerabilities'] as $vuln) {
                    $vulnerabilities[] = [
                        'packageName' => $vuln['PkgName'] ?? 'unknown',
                        'version' => $vuln['InstalledVersion'] ?? 'unknown',
                        'severity' => $vuln['Severity'] ?? 'UNKNOWN',
                        'title' => $vuln['Title'] ?? ($vuln['VulnerabilityID'] ?? 'Unknown vulnerability'),
                        'description' => $vuln['Description'] ?? 'No description available',
                        'cve' => $vuln['VulnerabilityID'] ?? 'Unknown',
                        'fixedVersion' => $vuln['FixedVersion'] ?? 'None',
                        'timestamp' => now(),
                    ];
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Parse Trivy text output and extract vulnerabilities.
     * This is more complex as the text format is not as structured as JSON.
     *
     * @param  string  $textOutput  The text output from Trivy
     * @return array Array of vulnerabilities
     */
    public static function parseTextOutput(string $textOutput): array
    {
        $vulnerabilities = [];
        $lines = explode("\n", $textOutput);

        $currentPackage = null;
        $currentVersion = null;

        foreach ($lines as $i => $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            // Look for package name and version
            if (preg_match('/^(.+) \((.+)\)$/', $line, $matches)) {
                $currentPackage = $matches[1];
                $currentVersion = $matches[2];
            }
            // Look for vulnerability details
            elseif (preg_match('/^\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(.+?)\s+\|/', $line, $matches)) {
                $cve = $matches[1];
                $severity = $matches[2];
                $title = trim($matches[3]);

                // Only process if we have a package context
                if ($currentPackage && $currentVersion) {
                    // Try to find fixed version in the next line if it exists
                    $fixedVersion = 'None';
                    if (isset($lines[$i + 1]) && strpos($lines[$i + 1], 'Fixed version:') !== false) {
                        if (preg_match('/Fixed version:\s+(.+)/', $lines[$i + 1], $fixMatches)) {
                            $fixedVersion = $fixMatches[1];
                        }
                    }

                    $vulnerabilities[] = [
                        'packageName' => $currentPackage,
                        'version' => $currentVersion,
                        'severity' => $severity,
                        'title' => $title,
                        'description' => "Vulnerability in $currentPackage $currentVersion",
                        'cve' => $cve,
                        'fixedVersion' => $fixedVersion,
                        'timestamp' => now(),
                    ];
                }
            }
        }

        return $vulnerabilities;
    }
}
