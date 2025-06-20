<?php

use Prahsys\Perimeter\Contracts\IntrusionPreventionInterface;
use Prahsys\Perimeter\Services\Fail2banService;
use Prahsys\Perimeter\Services\ServiceManager;

test('service manager can register and retrieve services', function () {
    $manager = new ServiceManager;

    // Register a service
    $manager->register('fail2ban', Fail2banService::class, ['enabled' => true]);

    // Check if the service exists
    expect($manager->has('fail2ban'))->toBeTrue();

    // Get the service
    $service = $manager->get('fail2ban');
    expect($service)->toBeInstanceOf(Fail2banService::class);
    expect($service)->toBeInstanceOf(IntrusionPreventionInterface::class);
});

test('service manager can filter services by interface', function () {
    $manager = new ServiceManager;

    // Register multiple services
    $manager->register('fail2ban', Fail2banService::class, ['enabled' => true]);

    // Get services by interface
    $services = $manager->getByInterface(IntrusionPreventionInterface::class);

    expect($services)->toHaveCount(1);
    expect($services->first())->toBeInstanceOf(Fail2banService::class);
});

test('service manager throws exception for unknown service', function () {
    $manager = new ServiceManager;

    // Try to get a non-existent service
    expect(fn () => $manager->get('unknown'))->toThrow(\Prahsys\Perimeter\Exceptions\ServiceNotFoundException::class);
});

test('service manager can register classes by full classname', function () {
    $manager = new ServiceManager;

    // Register a class
    $className = Fail2banService::class;
    $config = ['enabled' => true];
    $manager->registerClass($className, $config);

    // Should be registered with both the full class name and the short name
    expect($manager->has($className))->toBeTrue();
    expect($manager->has('fail2ban'))->toBeTrue();

    // Should have the same driver and config in both registrations
    $services = $manager->all();
    expect($services[$className]['driver'])->toBe($className);
    expect($services['fail2ban']['driver'])->toBe($className);
    expect($services[$className]['config'])->toBe($config);
    expect($services['fail2ban']['config'])->toBe($config);
});
