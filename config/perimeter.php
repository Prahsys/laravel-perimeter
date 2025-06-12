<?php

return [
    'enabled' => env('PERIMETER_ENABLED', true),
    
    // Unified logging configuration
    'logging' => [
        'channels' => explode(',', env('PERIMETER_LOG_CHANNELS', 'stack')),
        'levels' => [
            'malware' => [
                'ransomware' => 'emergency',
                'trojan' => 'critical',
                'virus' => 'critical',
                'adware' => 'warning',
                'test' => 'info',
            ],
            'behavioral' => [
                'privilege_escalation' => 'emergency',
                'suspicious_network' => 'critical',
                'abnormal_file_access' => 'error',
                'unusual_process' => 'warning',
            ],
            'vulnerability' => [
                'critical' => 'critical',
                'high' => 'error',
                'medium' => 'warning',
                'low' => 'info',
            ],
        ],
    ],
    
    // ClamAV Configuration
    'clamav' => [
        'enabled' => env('PERIMETER_CLAMAV_ENABLED', true),
        'socket' => env('CLAMAV_SOCKET', '/var/run/clamav/clamd.ctl'),
        'realtime' => env('PERIMETER_REALTIME_SCAN', true),
        'scan_paths' => [
            base_path(),
            storage_path('app/public'),
        ],
        'exclude_patterns' => [
            '*/vendor/*',
            '*/node_modules/*',
            '*/storage/logs/*',
        ],
    ],
    
    // Falco Configuration
    'falco' => [
        'enabled' => env('PERIMETER_FALCO_ENABLED', true),
        'grpc_endpoint' => env('FALCO_GRPC_ENDPOINT', 'localhost:5060'),
        'rules_path' => base_path('perimeter-rules/falco'),
        'custom_rules' => [
            'laravel_suspicious_file_write' => true,
            'laravel_mass_assignment_attempt' => true,
            'laravel_sql_injection_pattern' => true,
            'laravel_command_injection' => true,
        ],
    ],
    
    // Trivy Configuration
    'trivy' => [
        'enabled' => env('PERIMETER_TRIVY_ENABLED', true),
        'scan_paths' => [
            base_path('composer.lock'),
            base_path('package-lock.json'),
            base_path('yarn.lock'),
        ],
        'scan_schedule' => 'daily',
        'severity_threshold' => env('TRIVY_SEVERITY_THRESHOLD', 'MEDIUM'),
    ],
    
    // Reporting Configuration
    'reporting' => [
        'retention_days' => env('PERIMETER_RETENTION_DAYS', 90),
        'formats' => ['json', 'csv'],
    ],
];