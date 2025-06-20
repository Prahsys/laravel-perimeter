<?php

namespace Prahsys\Perimeter\Parsers;

class ClamAVOutputParser
{
    /**
     * Parse ClamAV scan output and extract infected files.
     *
     * @param  string  $output  The scan output from ClamAV
     * @return array Array of infection results
     */
    public static function parseInfectedFiles(string $output): array
    {
        $results = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (strpos($line, 'FOUND') !== false) {
                [$filePath, $threatInfo] = explode(': ', $line);
                $threatName = str_replace(' FOUND', '', $threatInfo);

                $results[] = [
                    'file' => $filePath,
                    'threat' => $threatName,
                    'timestamp' => now(),
                ];
            }
        }

        return $results;
    }

    /**
     * Parse the scan summary section to extract statistics.
     *
     * @param  string  $output  The scan output from ClamAV
     * @return array Array of scan statistics
     */
    public static function parseScanSummary(string $output): array
    {
        $summary = [];
        $inSummary = false;
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (strpos($line, 'SCAN SUMMARY') !== false) {
                $inSummary = true;

                continue;
            }

            if ($inSummary && ! empty(trim($line))) {
                if (strpos($line, ':') !== false) {
                    [$key, $value] = explode(':', $line, 2);
                    $key = strtolower(trim($key));
                    $key = str_replace(' ', '_', $key);
                    $summary[$key] = trim($value);
                }
            }
        }

        return $summary;
    }
}
