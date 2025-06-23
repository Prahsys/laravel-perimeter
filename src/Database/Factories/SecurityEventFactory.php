<?php

namespace Prahsys\Perimeter\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Prahsys\Perimeter\Models\SecurityEvent;

class SecurityEventFactory extends Factory
{
    protected $model = SecurityEvent::class;

    public function definition()
    {
        $types = ['malware', 'vulnerability', 'behavioral', 'intrusion', 'firewall'];
        $type = $this->faker->randomElement($types);

        // Different details based on event type
        $details = $this->getDetailsByType($type);

        // Generate a random timestamp with good distribution across recent time
        $timeRanges = [
            '-30 minutes', '-1 hour', '-3 hours', '-6 hours',
            '-12 hours', '-1 day', '-2 days', '-3 days',
            '-1 week', '-2 weeks', '-1 month',
        ];
        $timestamp = $this->faker->dateTimeBetween(
            $this->faker->randomElement($timeRanges),
            'now'
        );

        return [
            // Null scan_id indicates a runtime monitoring event (not part of a scan)
            'scan_id' => null,
            'timestamp' => $timestamp,
            'type' => $type,
            'severity' => $this->faker->randomElement(['critical', 'high', 'medium', 'low']),
            'description' => $details['description'],
            'location' => $details['location'],
            'user' => $this->faker->optional(0.7)->userName,
            'service' => $details['service'],
            'details' => $details['details'],
        ];
    }

    protected function getDetailsByType($type)
    {
        switch ($type) {
            case 'malware':
                $threat = $this->faker->randomElement([
                    'EICAR-Test-Signature', 'Trojan.PHP.Agent', 'PHP.Malware.UploadShell',
                    'Win.Malware.Ramnit', 'Linux.Trojan.Mirai', 'JS.Cryptominer.Generic',
                    'Backdoor.PHP.WebShell', 'Trojan.JS.Obfuscated', 'Malware.Encoded.Base64',
                ]);
                $file = '/var/www/'.$this->faker->randomElement(['html', 'app', 'data', 'public', 'storage', 'uploads']).'/'.$this->faker->word.'/'.$this->faker->word.'.'.$this->faker->randomElement(['php', 'js', 'txt', 'pdf', 'png', 'jpg', 'zip']);

                return [
                    'description' => "Detected {$threat} in file",
                    'location' => $file,
                    'service' => 'clamav',
                    'details' => [
                        'threat' => $threat,
                        'file' => $file,
                        'hash' => $this->faker->sha256,
                        'scan_date' => $this->faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
                    ],
                ];

            case 'vulnerability':
                $package = $this->faker->randomElement([
                    'symfony/http-kernel', 'laravel/framework', 'guzzlehttp/guzzle',
                    'monolog/monolog', 'doctrine/orm', 'aws/aws-sdk-php',
                    'tymon/jwt-auth', 'phpunit/phpunit', 'league/flysystem',
                ]);
                $version = $this->faker->semver;
                $year = $this->faker->numberBetween(2022, 2025);
                $cve = 'CVE-'.$year.'-'.$this->faker->numberBetween(1000, 99999);
                $severity = $this->faker->randomElement(['critical', 'high', 'medium', 'low']);

                return [
                    'description' => "{$severity} severity {$cve} found in {$package}",
                    'location' => "{$package}@{$version}",
                    'service' => 'trivy',
                    'details' => [
                        'package' => $package,
                        'version' => $version,
                        'cve' => $cve,
                        'fix_version' => $this->faker->semver,
                        'cvss_score' => $this->faker->randomFloat(1, 1, 10),
                        'discovery_date' => $this->faker->dateTimeThisYear()->format('Y-m-d'),
                    ],
                ];

            case 'behavioral':
                $rules = [
                    'Terminal shell in container' => 'Container security violation: user spawned a terminal shell',
                    'Unauthorized file access' => 'Process attempted to access sensitive files',
                    'Privilege escalation attempt' => 'Process attempted to gain elevated privileges',
                    'Suspicious network connection' => 'Unexpected outbound connection to suspicious IP',
                    'Unexpected process execution' => 'Unknown process executed in container environment',
                    'Sensitive data access' => 'Process accessed credentials or sensitive configuration',
                    'Unusual file system activity' => 'High volume of file operations detected',
                    'Container escape attempt' => 'Process attempted to escape container namespace',
                ];

                $rule = $this->faker->randomElement(array_keys($rules));
                $description = $rules[$rule];
                $process = $this->faker->randomElement(['bash', 'sh', 'php', 'node', 'python', 'perl', 'ruby', 'curl', 'wget']);
                $pid = $this->faker->numberBetween(1000, 30000);

                return [
                    'description' => $description,
                    'location' => '/proc/'.$pid,
                    'service' => 'falco',
                    'details' => [
                        'rule' => $rule,
                        'process' => $process,
                        'pid' => $pid,
                        'user' => $this->faker->randomElement(['www-data', 'root', 'nobody', 'admin', 'ubuntu', 'app']),
                        'command' => $process.' '.$this->faker->text(30),
                        'priority' => $this->faker->randomElement(['critical', 'warning', 'notice']),
                    ],
                ];

            case 'intrusion':
                $ip = $this->faker->ipv4;
                $action = $this->faker->randomElement(['blocked', 'detected', 'attempted']);
                $jail = $this->faker->randomElement(['sshd', 'apache-auth', 'php-fpm', 'wordpress', 'postfix', 'dovecot', 'proftpd']);
                $attempts = $this->faker->numberBetween(3, 20);
                $component = $this->faker->randomElement(['jail', 'filter', 'action']);
                $level = $this->faker->randomElement(['info', 'warning', 'notice', 'error']);

                // Generate different timestamps within a realistic range
                $timestamp = $this->faker->dateTimeBetween('-3 days', '-10 minutes')->format('Y-m-d H:i:s');

                // Create more varied descriptions based on the jail type
                $descriptions = [
                    "Intrusion attempt {$action} from {$ip}",
                    "Banned IP {$ip} after {$attempts} failed attempts",
                    "Suspicious login activity from {$ip}",
                    "Brute force attack {$action} from {$ip}",
                    "Multiple authentication failures from {$ip}",
                    "Possible credential stuffing from {$ip}",
                    "{$jail}: {$attempts} failed login attempts from {$ip}",
                    "IP {$ip} banned for excessive login failures",
                    "Security violation detected from {$ip}",
                    "Authentication attack detected on {$jail} service",
                ];

                // Create more detailed event information
                $messages = [
                    "Jail '{$jail}' started",
                    "Ban {$ip}",
                    "Found {$ip} - {$attempts} time(s)",
                    "Unban {$ip}",
                    "{$attempts} authentication failures from {$ip}",
                    "Added permanent ban for {$ip}",
                ];

                return [
                    'description' => $this->faker->randomElement($descriptions),
                    'location' => $ip,
                    'service' => 'fail2ban',
                    'details' => [
                        'timestamp' => $timestamp,
                        'component' => $component,
                        'level' => $level,
                        'message' => $this->faker->randomElement($messages),
                        'ip' => $ip,
                        'jail' => $jail,
                        'attempts' => $attempts,
                        'country' => $this->faker->countryCode,
                        'ban_time' => $this->faker->randomElement([3600, 7200, 86400, 604800]),
                        'action' => $action,
                        'service' => 'fail2ban',
                    ],
                ];

            case 'firewall':
                $port = $this->faker->numberBetween(1, 65535);
                $ip = $this->faker->ipv4;
                $protocol = $this->faker->randomElement(['TCP', 'UDP']);
                $service = $this->faker->randomElement(['HTTP', 'SSH', 'FTP', 'SMTP', 'DNS', 'Unknown']);

                $descriptions = [
                    "Blocked connection attempt to port {$port}/{$protocol}",
                    "Denied {$service} access from {$ip}",
                    "Firewall blocked traffic to restricted port {$port}",
                    "Unauthorized connection attempt to {$service} service",
                    "Suspicious traffic blocked from {$ip}",
                ];

                return [
                    'description' => $this->faker->randomElement($descriptions),
                    'location' => $ip,
                    'service' => 'ufw',
                    'details' => [
                        'ip' => $ip,
                        'port' => $port,
                        'protocol' => $protocol,
                        'service_name' => $service,
                        'direction' => $this->faker->randomElement(['inbound', 'outbound']),
                        'packets' => $this->faker->numberBetween(1, 100),
                        'timestamp' => $this->faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
                    ],
                ];

            default:
                return [
                    'description' => 'Unknown security event',
                    'location' => null,
                    'service' => 'unknown',
                    'details' => [],
                ];
        }
    }

    // Malware events only
    public function malware()
    {
        return $this->state(function (array $attributes) {
            $details = $this->getDetailsByType('malware');

            return [
                'type' => 'malware',
                'severity' => $this->faker->randomElement(['critical', 'high']),
                'description' => $details['description'],
                'location' => $details['location'],
                'details' => $details['details'],
            ];
        });
    }

    // Vulnerability events only
    public function vulnerability()
    {
        return $this->state(function (array $attributes) {
            $details = $this->getDetailsByType('vulnerability');

            return [
                'type' => 'vulnerability',
                'severity' => $this->faker->randomElement(['high', 'medium', 'low']),
                'description' => $details['description'],
                'location' => $details['location'],
                'details' => $details['details'],
            ];
        });
    }

    // Behavioral events only
    public function behavioral()
    {
        return $this->state(function (array $attributes) {
            $details = $this->getDetailsByType('behavioral');

            return [
                'type' => 'behavioral',
                'severity' => $this->faker->randomElement(['critical', 'medium']),
                'description' => $details['description'],
                'location' => $details['location'],
                'details' => $details['details'],
            ];
        });
    }
}
