<?php

namespace Prahsys\Perimeter\Parsers;

use DateTime;
use DateTimeInterface;

class FalcoOutputParser
{
    /**
     * Parse Falco text output and extract security events.
     *
     * @param  string  $output  The text output from Falco
     * @return array Array of security events
     */
    public static function parseTextEvents(string $output): array
    {
        $results = [];
        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }

            // Format is like: 13:35:21.159766067: Critical A shell was spawned in a container (user=root...)
            if (preg_match('/(\d+:\d+:\d+\.\d+): (\w+) (.*) \((.*)\)/', $line, $matches)) {
                $time = $matches[1];
                $priority = $matches[2];
                $description = $matches[3];
                $details = $matches[4];

                // Parse details
                $detailsArray = [];
                $user = null;
                $process = null;

                $detailPairs = explode(' ', $details);
                foreach ($detailPairs as $pair) {
                    if (strpos($pair, '=') !== false) {
                        [$key, $value] = explode('=', $pair, 2);
                        if ($key === 'user') {
                            $user = $value;
                        } elseif ($key === 'command' || $key === 'shell') {
                            $process = $value;
                        }
                        $detailsArray[$key] = $value;
                    }
                }

                $now = new DateTime;
                $timestamp = $now->format('Y-m-d').'T'.substr($time, 0, 8).'Z';

                $results[] = [
                    'timestamp' => $timestamp,
                    'priority' => strtolower($priority),
                    'description' => $description,
                    'process' => $process,
                    'user' => $user,
                    'rule' => $description, // Use description as rule name since it's not provided in text format
                    'details' => $detailsArray,
                ];
            }
        }

        return $results;
    }

    /**
     * Parse Falco JSON output and extract security events.
     *
     * @param  string  $jsonData  The JSON data from Falco
     * @return array Array of security events
     */
    public static function parseJsonEvents(string $jsonData): array
    {
        $data = json_decode($jsonData, true);

        if (! is_array($data) || ! isset($data['events'])) {
            return [];
        }

        return $data['events'];
    }

    /**
     * Format a parsed event for output.
     *
     * @param  array  $event  The parsed event
     * @param  string  $format  The output format (text, json)
     * @return string Formatted event
     */
    public static function formatEvent(array $event, string $format = 'text'): string
    {
        if ($format === 'json') {
            return json_encode($event, JSON_PRETTY_PRINT);
        }

        // Default to text format
        $timestamp = $event['timestamp'];
        if ($timestamp instanceof DateTimeInterface) {
            $timestamp = $timestamp->format(DateTimeInterface::ISO8601);
        }

        $severity = strtoupper($event['priority'] ?? 'unknown');
        $description = $event['description'] ?? 'Unknown event';
        $details = '';

        if (isset($event['details']) && is_array($event['details'])) {
            $detailPairs = [];
            foreach ($event['details'] as $key => $value) {
                $detailPairs[] = $key.'='.$value;
            }
            $details = '('.implode(' ', $detailPairs).')';
        }

        return "$timestamp: $severity $description $details";
    }
}
