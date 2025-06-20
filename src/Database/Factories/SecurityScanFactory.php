<?php

namespace Prahsys\Perimeter\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Prahsys\Perimeter\Models\SecurityScan;

class SecurityScanFactory extends Factory
{
    protected $model = SecurityScan::class;

    public function definition()
    {
        return [
            'scan_type' => $this->faker->randomElement(['audit', 'malware', 'vulnerability', 'behavioral']),
            'started_at' => $this->faker->dateTimeBetween('-1 week', 'now'),
            'completed_at' => $this->faker->optional(0.9)->dateTimeBetween('-1 week', 'now'),
            'status' => $this->faker->randomElement(['pending', 'completed', 'failed']),
            'issues_found' => $this->faker->numberBetween(0, 20),
            'scan_details' => [
                'malware_count' => $this->faker->numberBetween(0, 5),
                'vulnerability_count' => $this->faker->numberBetween(0, 10),
                'behavioral_count' => $this->faker->numberBetween(0, 5),
            ],
            'command' => 'perimeter:'.$this->faker->randomElement(['audit', 'scan', 'monitor']),
            'command_options' => null,
        ];
    }
}
