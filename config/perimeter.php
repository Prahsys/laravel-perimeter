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

    // Services Configuration
    'services' => [
        // Each key is the fully qualified class name of the service
        // Each service must define an 'installer' key that points to the fully qualified class name
        // of the command class that installs this service (e.g. \Prahsys\Perimeter\Commands\InstallClamAV::class)
        \Prahsys\Perimeter\Services\SystemAuditService::class => [
            'enabled' => env('PERIMETER_SYSTEM_AUDIT_ENABLED', true),
            'installer' => null, // No installer needed for SystemAuditService
        ],

        \Prahsys\Perimeter\Services\ClamAVService::class => [
            'enabled' => env('PERIMETER_CLAMAV_ENABLED', true),
            'installer' => \Prahsys\Perimeter\Commands\InstallClamAV::class,
            'socket' => env('CLAMAV_SOCKET', '/var/run/clamav/clamd.ctl'),
            'realtime' => env('PERIMETER_REALTIME_SCAN', true),
            'scan_paths' => [
                //                base_path(),
                //                storage_path('app/public'),
                '/',
            ],
            'exclude_patterns' => [
                '*/vendor/*',
                '*/node_modules/*',
                '*/storage/logs/*',
            ],
            'scan_timeout' => env('PERIMETER_CLAMAV_SCAN_TIMEOUT', 1800), // 30 minutes for direct scanning
            'health_check_timeout' => env('PERIMETER_CLAMAV_HEALTH_TIMEOUT', 300), // 5 minutes
            'min_memory_for_daemon' => env('PERIMETER_CLAMAV_MIN_MEMORY', 1536), // 1.5GB minimum for daemon mode
            'force_direct_scan' => env('PERIMETER_CLAMAV_FORCE_DIRECT', false), // Force direct scanning
        ],

        \Prahsys\Perimeter\Services\FalcoService::class => [
            'enabled' => env('PERIMETER_FALCO_ENABLED', true),
            'installer' => \Prahsys\Perimeter\Commands\InstallFalco::class,
            'binary_path' => env('FALCO_BINARY_PATH', null), // Custom path to Falco binary if not in PATH
            'grpc_endpoint' => env('FALCO_GRPC_ENDPOINT', 'localhost:5060'),
            'config_file' => env('FALCO_CONFIG_FILE', '/etc/falco/falco.yaml'),
            'rules_path' => env('FALCO_RULES_PATH', base_path('perimeter-rules/falco')),
            'log_path' => env('FALCO_LOG_PATH', '/var/log/falco.log'),
            'json_output' => env('FALCO_JSON_OUTPUT', true),
            'monitoring_mode' => env('FALCO_MONITORING_MODE', 'background'), // background or foreground
            'custom_rules' => [
                'laravel_suspicious_file_write' => true,
                'laravel_mass_assignment_attempt' => true,
                'laravel_sql_injection_pattern' => true,
                'laravel_command_injection' => true,
            ],
            'severity_filter' => env('FALCO_SEVERITY_FILTER', 'warning'), // minimum severity to report: emergency, alert, critical, error, warning, notice, info, debug
        ],

        \Prahsys\Perimeter\Services\TrivyService::class => [
            'enabled' => env('PERIMETER_TRIVY_ENABLED', true),
            'installer' => \Prahsys\Perimeter\Commands\InstallTrivy::class,
            'scan_paths' => [
                //                base_path('composer.lock'),
                //                base_path('package-lock.json'),
                //                base_path('yarn.lock'),
                '/',
            ],
            'severity_threshold' => env('TRIVY_SEVERITY_THRESHOLD', 'MEDIUM'),
            'scan_timeout' => env('PERIMETER_TRIVY_SCAN_TIMEOUT', 1800), // 30 minutes for large codebases
            // Minimal exclude paths for performance (only critical system directories)
            'exclude_paths' => [
                '/proc',
                '/sys', 
                '/dev',
                '/run',
                '/tmp',
            ],
        ],

        \Prahsys\Perimeter\Services\UfwService::class => [
            'enabled' => env('PERIMETER_UFW_ENABLED', true),
            'installer' => \Prahsys\Perimeter\Commands\InstallUfw::class,
            'log_path' => env('UFW_LOG_PATH', '/var/log/ufw.log'),
            // Ports with any type of access rule (open or restricted)
            'expected_ports' => ! empty(env('PERIMETER_EXPECTED_PORTS')) ? explode('|', env('PERIMETER_EXPECTED_PORTS')) : [],
            // Ports that can be completely open to the internet
            'public_ports' => ! empty(env('PERIMETER_PUBLIC_PORTS')) ? explode('|', env('PERIMETER_PUBLIC_PORTS')) : [],
            // Ports that should be restricted to specific IPs or localhost
            'restricted_ports' => ! empty(env('PERIMETER_RESTRICTED_PORTS')) ? explode('|', env('PERIMETER_RESTRICTED_PORTS')) : [],
        ],

        \Prahsys\Perimeter\Services\Fail2banService::class => [
            'enabled' => env('PERIMETER_FAIL2BAN_ENABLED', true),
            'installer' => \Prahsys\Perimeter\Commands\InstallFail2ban::class,
            'log_path' => env('FAIL2BAN_LOG_PATH', '/var/log/fail2ban.log'),
            'jail_config_path' => env('FAIL2BAN_JAIL_CONFIG', '/etc/fail2ban/jail.local'),
            // Default jails to enable
            'enabled_jails' => explode(',', env('FAIL2BAN_ENABLED_JAILS', 'sshd,apache-auth,php-fpm')),
            // Default ban time in seconds
            'ban_time' => env('FAIL2BAN_BAN_TIME', 3600),
            // Number of retries before banning
            'max_retry' => env('FAIL2BAN_MAX_RETRY', 5),
            // Time window for retries in seconds
            'find_time' => env('FAIL2BAN_FIND_TIME', 600),
        ],
    ],

    // Reporting Configuration
    'reporting' => [
        'retention_days' => env('PERIMETER_RETENTION_DAYS', 90),
        'formats' => ['json', 'csv'],
    ],

    // Database Storage Configuration
    'storage' => [
        'connection' => env('PERIMETER_DB_CONNECTION', null), // Uses default connection if null
        'table_prefix' => env('PERIMETER_TABLE_PREFIX', 'perimeter_'),
        'models' => [
            // Model classes can be overridden by application
            'security_event' => env('PERIMETER_MODEL_SECURITY_EVENT', \Prahsys\Perimeter\Models\SecurityEvent::class),
            'security_scan' => env('PERIMETER_MODEL_SECURITY_SCAN', \Prahsys\Perimeter\Models\SecurityScan::class),
        ],
        // How many batch records to keep before pruning
        'max_batch_records' => env('PERIMETER_MAX_BATCH_RECORDS', 100),
        // Auto-prune events older than retention_days
        'auto_prune' => env('PERIMETER_AUTO_PRUNE', true),
    ],
];
