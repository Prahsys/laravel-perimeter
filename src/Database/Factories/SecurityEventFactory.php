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

        return [
            // Null scan_id indicates a runtime monitoring event (not part of a scan)
            'scan_id' => null,
            'timestamp' => $this->faker->dateTimeBetween('-1 week', 'now'),
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
                    'Win.Malware.Ramnit', 'Linux.Trojan.Mirai',
                ]);
                $file = '/var/www/'.$this->faker->randomElement(['html', 'app', 'data']).'/'.$this->faker->word.'.'.$this->faker->randomElement(['php', 'js', 'txt']);

                return [
                    'description' => "Detected {$threat} in file",
                    'location' => $file,
                    'service' => 'clamav',
                    'details' => [
                        'threat' => $threat,
                        'file' => $file,
                        'hash' => $this->faker->sha256,
                    ],
                ];

            case 'vulnerability':
                $package = $this->faker->word.'/'.$this->faker->word;
                $version = $this->faker->semver;
                $cve = 'CVE-'.$this->faker->year.'-'.$this->faker->numberBetween(1000, 99999);

                return [
                    'description' => "Vulnerability {$cve} found in {$package}",
                    'location' => "{$package}@{$version}",
                    'service' => 'trivy',
                    'details' => [
                        'package' => $package,
                        'version' => $version,
                        'cve' => $cve,
                        'fix_version' => $this->faker->semver,
                    ],
                ];

            case 'behavioral':
                $rule = $this->faker->randomElement([
                    'Terminal shell in container',
                    'Unauthorized file access',
                    'Privilege escalation attempt',
                    'Suspicious network connection',
                    'Unexpected process execution',
                ]);
                $process = $this->faker->randomElement(['bash', 'sh', 'php', 'node', 'python']);

                return [
                    'description' => $rule,
                    'location' => null,
                    'service' => 'falco',
                    'details' => [
                        'rule' => $rule,
                        'process' => $process,
                        'command' => $this->faker->text(50),
                    ],
                ];

            case 'intrusion':
                $ip = $this->faker->ipv4;
                $action = $this->faker->randomElement(['blocked', 'detected', 'attempted']);

                return [
                    'description' => "Intrusion attempt {$action} from {$ip}",
                    'location' => $ip,
                    'service' => 'fail2ban',
                    'details' => [
                        'ip' => $ip,
                        'jail' => $this->faker->randomElement(['sshd', 'apache-auth', 'wordpress']),
                        'attempts' => $this->faker->numberBetween(3, 20),
                    ],
                ];

            case 'firewall':
                $port = $this->faker->numberBetween(1, 65535);
                $ip = $this->faker->ipv4;

                return [
                    'description' => "Blocked connection attempt to port {$port}",
                    'location' => $ip,
                    'service' => 'ufw',
                    'details' => [
                        'ip' => $ip,
                        'port' => $port,
                        'protocol' => $this->faker->randomElement(['TCP', 'UDP']),
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
