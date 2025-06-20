<?php

namespace Prahsys\Perimeter\Parsers;

use DateTime;

class UfwOutputParser
{
    /**
     * Parse UFW log events.
     */
    public static function parseLogEvents(string $logOutput, int $limit = 10): array
    {
        $events = [];
        $lines = explode("\n", $logOutput);

        foreach ($lines as $line) {
            if (empty(trim($line))) {
                continue;
            }

            // UFW log format: timestamp hostname kernel: [timestamp] UFW BLOCK/ALLOW: IN/OUT=... SRC=... DST=... ...
            if (preg_match('/^(.*?)\s+.*?\s+kernel:\s+\[(.*?)\]\s+\[?UFW\s+(\w+)\]?:\s+(.*?)$/', $line, $matches)) {
                $logTime = $matches[1];
                $kernelTime = $matches[2];
                $action = strtolower($matches[3]);
                $details = $matches[4];

                // Parse direction (IN/OUT)
                $direction = '';
                if (preg_match('/(?:^|\s)IN=(\S+)/', $details, $dirMatches)) {
                    $direction = 'incoming';
                    $interface = $dirMatches[1] ?: 'unknown';
                } elseif (preg_match('/(?:^|\s)OUT=(\S+)/', $details, $dirMatches)) {
                    $direction = 'outgoing';
                    $interface = $dirMatches[1] ?: 'unknown';
                }

                // Parse source and destination
                $source = preg_match('/SRC=(\S+)/', $details, $srcMatches) ? $srcMatches[1] : 'unknown';
                $destination = preg_match('/DST=(\S+)/', $details, $dstMatches) ? $dstMatches[1] : 'unknown';

                // Parse protocol
                $protocol = preg_match('/PROTO=(\S+)/', $details, $protoMatches) ? strtolower($protoMatches[1]) : 'unknown';

                // Parse ports
                $srcPort = preg_match('/SPT=(\d+)/', $details, $sptMatches) ? (int) $sptMatches[1] : null;
                $dstPort = preg_match('/DPT=(\d+)/', $details, $dptMatches) ? (int) $dptMatches[1] : null;

                // Format timestamp
                try {
                    $timestamp = new DateTime($logTime);
                } catch (\Exception $e) {
                    $timestamp = new DateTime;
                }

                // Determine severity based on action
                $severity = ($action === 'block') ? 'medium' : 'low';

                // Create event data
                $event = [
                    'timestamp' => $timestamp->format('c'),
                    'type' => 'firewall',
                    'action' => $action,
                    'direction' => $direction,
                    'interface' => $interface,
                    'source' => $source,
                    'source_port' => $srcPort,
                    'destination' => $destination,
                    'destination_port' => $dstPort,
                    'protocol' => $protocol,
                    'severity' => $severity,
                    'description' => self::formatDescription($action, $direction, $source, $destination, $protocol, $dstPort),
                    'raw_log' => $line,
                ];

                $events[] = $event;

                if (count($events) >= $limit) {
                    break;
                }
            }
        }

        return $events;
    }

    /**
     * Parse UFW status output.
     */
    public static function parseStatusOutput(string $statusOutput): array
    {
        $result = [
            'active' => false,
            'rules' => [],
            'default_policy' => [
                'incoming' => 'deny',
                'outgoing' => 'allow',
                'routed' => 'reject',
            ],
        ];

        $lines = explode("\n", $statusOutput);

        // Parse status line
        foreach ($lines as $index => $line) {
            if (strpos($line, 'Status:') === 0) {
                $result['active'] = trim(substr($line, 8)) === 'active';
                break;
            }
        }

        // Parse default policies
        foreach ($lines as $line) {
            if (preg_match('/Default:\s+(\w+)\s+\((\w+)\)/', $line, $matches)) {
                $direction = strtolower($matches[1]);
                $policy = strtolower($matches[2]);

                if (in_array($direction, ['incoming', 'outgoing', 'routed'])) {
                    $result['default_policy'][$direction] = $policy;
                }
            }
        }

        // Parse rules
        $inRuleSection = false;
        foreach ($lines as $line) {
            // Rule section starts after a line with dashes
            if (preg_match('/^-+$/', $line)) {
                $inRuleSection = true;

                continue;
            }

            if ($inRuleSection && ! empty(trim($line))) {
                // Typical format: "[ 1] 22/tcp                   ALLOW IN    Anywhere"
                if (preg_match('/^\[\s*(\d+)\]\s+(\S+)\s+(\w+)\s+(\w+)\s+(.*)$/', $line, $matches)) {
                    $number = (int) $matches[1];
                    $port = $matches[2];
                    $action = strtolower($matches[3]);
                    $direction = strtolower($matches[4]);
                    $source = trim($matches[5]);

                    $rule = [
                        'number' => $number,
                        'port' => $port,
                        'action' => $action,
                        'direction' => $direction,
                        'source' => $source,
                    ];

                    $result['rules'][] = $rule;
                }
            }
        }

        return $result;
    }

    /**
     * Format a human-readable description of the event.
     */
    protected static function formatDescription(
        string $action,
        string $direction,
        string $source,
        string $destination,
        string $protocol,
        ?int $dstPort
    ): string {
        $actionStr = ($action === 'block') ? 'blocked' : 'allowed';
        $directionStr = ($direction === 'incoming') ? 'incoming' : 'outgoing';
        $portStr = $dstPort ? " on port $dstPort" : '';
        $protocolStr = ($protocol !== 'unknown') ? " ($protocol)" : '';

        if ($direction === 'incoming') {
            return "Firewall $actionStr $directionStr connection from $source to $destination$portStr$protocolStr";
        } else {
            return "Firewall $actionStr $directionStr connection to $destination from $source$portStr$protocolStr";
        }
    }
}
