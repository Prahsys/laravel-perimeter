<?php

use Prahsys\Perimeter\Parsers\Fail2banOutputParser;

test('fail2ban parser can parse status output', function () {
    $output = <<<'EOF'
    Status
    |- Number of jail:      3
    `- Jail list:   sshd, apache-auth, php-fpm
    Server replied: v1.0.2
    EOF;

    $result = Fail2banOutputParser::parseStatus($output);

    expect($result['running'])->toBeTrue();
    expect($result['version'])->toBe('1.0.2');
    expect($result['jails'])->toBe(['sshd', 'apache-auth', 'php-fpm']);
});

test('fail2ban parser detects running with different output formats', function () {
    // Test with 'Server replied:' format
    $output1 = 'Server replied: v1.0.2';
    $result1 = Fail2banOutputParser::parseStatus($output1);
    expect($result1['running'])->toBeTrue();

    // Test with 'Jail list:' format
    $output2 = "Status\n`- Jail list:   sshd";
    $result2 = Fail2banOutputParser::parseStatus($output2);
    expect($result2['running'])->toBeTrue();

    // Test with 'Number of jail:' format
    $output3 = "Status\n|- Number of jail:   1";
    $result3 = Fail2banOutputParser::parseStatus($output3);
    expect($result3['running'])->toBeTrue();

    // Test with empty output
    $output4 = '';
    $result4 = Fail2banOutputParser::parseStatus($output4);
    expect($result4['running'])->toBeFalse();
});

test('fail2ban parser can parse jail status', function () {
    $output = <<<'EOF'
    Status for the jail: sshd
    |- Filter
    |  |- Currently failed: 2
    |  |- Total failed:     12
    |  `- File list:        /var/log/auth.log
    `- Actions
       |- Currently banned: 1
       |- Total banned:     1
       `- Banned IP list:   192.168.1.10
    EOF;

    $result = Fail2banOutputParser::parseJailStatus($output);

    expect($result['jail'])->toBe('sshd');
    expect($result['currently_failed'])->toBe(2);
    expect($result['total_failed'])->toBe(12);
    expect($result['banned_ips'])->toBe(['192.168.1.10']);
    expect($result['file_list'])->toBe(['/var/log/auth.log']);
});

test('fail2ban parser can parse log events', function () {
    $logContent = <<<'EOF'
    2025-06-16 12:00:01,123 fail2ban.actions        [123]: INFO    [sshd] Ban 192.168.1.10
    2025-06-16 12:30:01,456 fail2ban.actions        [123]: INFO    [sshd] Unban 192.168.1.10
    2025-06-16 13:00:01,789 fail2ban.actions        [123]: INFO    [apache-auth] Ban 192.168.1.20
    EOF;

    $events = Fail2banOutputParser::parseLogEvents($logContent, 2);

    expect($events)->toHaveCount(2);

    // Check for the correct events in either order
    $foundBan = false;
    $foundUnban = false;

    foreach ($events as $event) {
        if ($event['jail'] === 'sshd' && $event['action'] === 'ban') {
            $foundBan = true;
            expect($event['ip'])->toBe('192.168.1.10');
        }
        if ($event['jail'] === 'sshd' && $event['action'] === 'unban') {
            $foundUnban = true;
            expect($event['ip'])->toBe('192.168.1.10');
        }
        if ($event['jail'] === 'apache-auth' && $event['action'] === 'ban') {
            $foundApacheBan = true;
            expect($event['ip'])->toBe('192.168.1.20');
        }
    }

    // We should have found at least one of the expected events
    expect($foundBan || $foundUnban || $foundApacheBan)->toBeTrue('No expected events found');
});
