<?php

namespace Prahsys\Perimeter\Parsers;

use Carbon\Carbon;

class Fail2banOutputParser
{
    /**
     * Parse the output of 'fail2ban-client status' command.
     */
    public static function parseStatus(string $output): array
    {
        $result = [
            'version' => null,
            'jails' => [],
            'running' => false,
        ];

        // Check if fail2ban is running
        // The server is running if we get a status output with jail list
        if (strpos($output, 'Server replied:') !== false ||
            strpos($output, 'Jail list:') !== false ||
            strpos($output, 'Number of jail:') !== false) {
            $result['running'] = true;
        }

        // Extract version if present
        if (preg_match('/v([0-9]+\.[0-9]+\.[0-9]+)/', $output, $matches)) {
            $result['version'] = $matches[1];
        }

        // Extract jail names
        if (preg_match('/Jail list:\s+(.+)$/m', $output, $matches)) {
            $jailList = trim($matches[1]);
            if (! empty($jailList)) {
                $result['jails'] = array_map('trim', explode(', ', $jailList));
            }
        }

        return $result;
    }

    /**
     * Parse the output of 'fail2ban-client status' to get a list of jails.
     */
    public static function parseJailList(string $output): array
    {
        $jails = [];

        // Extract jail names
        if (preg_match('/Jail list:\s+(.+)$/m', $output, $matches)) {
            $jailList = trim($matches[1]);
            if (! empty($jailList)) {
                $jails = array_map('trim', explode(', ', $jailList));
            }
        }

        return $jails;
    }

    /**
     * Parse the output of 'fail2ban-client status <jail>' command.
     */
    public static function parseJailStatus(string $output): array
    {
        $result = [
            'jail' => null,
            'currently_failed' => 0,
            'total_failed' => 0,
            'banned_ips' => [],
            'file_list' => [],
            'filter' => null,
            'actions' => [],
        ];

        // Extract jail name
        if (preg_match('/Status for the jail:\s*(.+)$/m', $output, $matches)) {
            $result['jail'] = trim($matches[1]);
        }

        // Extract currently failed
        if (preg_match('/Currently failed:\s+(\d+)/i', $output, $matches)) {
            $result['currently_failed'] = (int) $matches[1];
        }

        // Extract total failed
        if (preg_match('/Total failed:\s+(\d+)/i', $output, $matches)) {
            $result['total_failed'] = (int) $matches[1];
        }

        // Extract banned IPs
        if (preg_match('/Banned IP list:\s+(.+)$/m', $output, $matches)) {
            $ipList = trim($matches[1]);
            if (! empty($ipList) && $ipList !== 'No banned IP list') {
                $result['banned_ips'] = array_map('trim', explode(' ', $ipList));
            }
        }

        // Extract file list
        if (preg_match('/File list:\s+(.+)$/m', $output, $matches)) {
            $fileList = trim($matches[1]);
            if (! empty($fileList)) {
                $result['file_list'] = array_map('trim', explode(', ', $fileList));
            }
        }

        // Extract filter
        if (preg_match('/Filter:\s+(.+)$/m', $output, $matches)) {
            $result['filter'] = trim($matches[1]);
        }

        // Extract actions
        if (preg_match('/Actions:\s+(.+)$/m', $output, $matches)) {
            $actionsList = trim($matches[1]);
            if (! empty($actionsList)) {
                $result['actions'] = array_map('trim', explode(', ', $actionsList));
            }
        }

        return $result;
    }

    /**
     * Parse fail2ban log events.
     */
    public static function parseLogEvents(string $logContent, int $limit = 10): array
    {
        $events = [];
        $lines = explode("\n", $logContent);
        $lines = array_reverse($lines); // Start with most recent events

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            // Match typical fail2ban log entries
            if (preg_match('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) fail2ban\.(\w+)\s+\[(\d+)\]: (INFO|WARNING|ERROR|CRITICAL|DEBUG|NOTICE)\s+(.+)/', $line, $matches)) {
                $timestamp = $matches[1];
                $component = $matches[2];
                $pid = $matches[3];
                $level = strtolower($matches[4]);
                $message = $matches[5];

                // Parse ban/unban actions
                $jail = null;
                $ip = null;
                $action = null;

                if (preg_match('/\[([\w-]+)\] (Ban|Unban) ([\d\.]+)/', $message, $actionMatches)) {
                    $jail = $actionMatches[1];
                    $action = strtolower($actionMatches[2]);
                    $ip = $actionMatches[3];
                }

                try {
                    // Parse the timestamp with milliseconds
                    $timestampObj = null;

                    try {
                        // Try with milliseconds format
                        $timestampObj = Carbon::createFromFormat('Y-m-d H:i:s,v', $timestamp);
                    } catch (\Exception $e) {
                        // Try without milliseconds
                        try {
                            $timestampObj = Carbon::createFromFormat('Y-m-d H:i:s', $timestamp);
                        } catch (\Exception $e2) {
                            // If both formats fail, use current time
                            $timestampObj = Carbon::now();
                        }
                    }

                    $event = [
                        'timestamp' => $timestampObj->toIso8601String(),
                        'component' => $component,
                        'level' => $level,
                        'message' => $message,
                        'jail' => $jail,
                        'action' => $action,
                        'ip' => $ip,
                    ];

                    $events[] = $event;

                    if (count($events) >= $limit) {
                        break;
                    }
                } catch (\Exception $e) {
                    // Skip this event if there's a general error
                    continue;
                }
            }
        }

        return $events;
    }
}
