<?php

use Illuminate\Support\Facades\File;
use Prahsys\Perimeter\Parsers\FalcoOutputParser;

test('falco parser extracts text events', function () {
    // Load the detected events example
    $eventsOutput = File::get(getExamplesPath().'/falco/detected_events.txt');
    expect($eventsOutput)->not->toBeEmpty();

    // Parse with the parser
    $events = FalcoOutputParser::parseTextEvents($eventsOutput);

    // We should have multiple events
    expect(count($events))->toBeGreaterThan(1);

    // Check the first event - shell spawned
    expect($events[0]['priority'])->toBe('critical');
    expect($events[0]['description'])->toBe('A shell was spawned in a container with an attached terminal');
    expect($events[0]['user'])->toBe('root');
    expect($events[0]['process'])->toBe('bash');
});

test('falco parser extracts json events', function () {
    // Load the JSON events example
    $jsonData = File::get(getExamplesPath().'/falco/monitor_events.json');
    expect($jsonData)->not->toBeEmpty();

    // Parse with the parser
    $events = FalcoOutputParser::parseJsonEvents($jsonData);

    // We should have 3 events
    expect($events)->toHaveCount(3);

    // Check the first event
    expect($events[0]['rule'])->toBe('Terminal shell in container');
    expect($events[0]['priority'])->toBe('CRITICAL');
    expect($events[0]['description'])->toBe('A shell was spawned in a container with an attached terminal');
    expect($events[0]['user'])->toBe('root');

    // Check the second event
    expect($events[1]['rule'])->toBe('Sensitive File Access');
    expect($events[1]['priority'])->toBe('WARNING');
});

test('falco parser formats event', function () {
    $event = [
        'timestamp' => '2025-06-15T13:45:10Z',
        'priority' => 'critical',
        'description' => 'Test event',
        'details' => [
            'key1' => 'value1',
            'key2' => 'value2',
        ],
    ];

    // Format as text
    $textFormat = FalcoOutputParser::formatEvent($event);
    expect($textFormat)->toContain('2025-06-15T13:45:10Z: CRITICAL Test event');
    expect($textFormat)->toContain('key1=value1');

    // Format as JSON
    $jsonFormat = FalcoOutputParser::formatEvent($event, 'json');
    $decodedJson = json_decode($jsonFormat, true);
    expect($decodedJson)->toBeArray();
    expect($decodedJson['description'])->toBe('Test event');
});
