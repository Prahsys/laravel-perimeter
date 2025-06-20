<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Collection;
use Prahsys\Perimeter\Contracts\SecurityServiceInterface;
use Prahsys\Perimeter\Exceptions\ServiceNotFoundException;

class ServiceManager
{
    /**
     * The registered services.
     *
     * @var array
     */
    protected $services = [];

    /**
     * The service instances.
     *
     * @var array
     */
    protected $instances = [];

    /**
     * Register a service driver.
     */
    public function register(string $name, string $driver, array $config = []): void
    {
        // Ensure service name is included in the config
        if (! isset($config['name'])) {
            $config['name'] = $name;
        }

        $this->services[$name] = [
            'driver' => $driver,
            'config' => $config,
        ];
    }

    /**
     * Register service by class name.
     */
    public function registerClass(string $className, array $config = []): void
    {
        // Extract the short name from the class (e.g., ClamAVService -> clamav)
        $shortName = strtolower(preg_replace('/Service$/', '', class_basename($className)));

        // Register with the short name for easier access
        $this->register($shortName, $className, $config);

        // Also register with the full class name for more explicit access
        $this->register($className, $className, $config);
    }

    /**
     * Get a service by name.
     *
     * @throws \Prahsys\Perimeter\Exceptions\ServiceNotFoundException
     */
    public function get(string $name): SecurityServiceInterface
    {
        if (! isset($this->services[$name])) {
            throw new ServiceNotFoundException("Service driver [{$name}] not found.");
        }

        if (! isset($this->instances[$name])) {
            $this->instances[$name] = $this->resolve($name);
        }

        return $this->instances[$name];
    }

    /**
     * Check if a service exists.
     */
    public function has(string $name): bool
    {
        return isset($this->services[$name]);
    }

    /**
     * Get all registered services.
     */
    public function all(): array
    {
        return $this->services;
    }

    /**
     * Get all services by interface type.
     */
    public function getByInterface(string $interface): Collection
    {
        return collect($this->services)
            ->filter(function ($service) use ($interface) {
                $driver = $service['driver'];

                return is_subclass_of($driver, $interface);
            })
            ->map(function ($service, $name) {
                return $this->get($name);
            });
    }

    /**
     * Resolve a service instance.
     */
    protected function resolve(string $name): SecurityServiceInterface
    {
        $service = $this->services[$name];
        $driver = $service['driver'];
        $config = $service['config'];

        return new $driver($config);
    }

    /**
     * Get all scanner services.
     */
    public function getScanners(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\ScannerServiceInterface::class);
    }

    /**
     * Get all monitor services.
     */
    public function getMonitors(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\MonitorServiceInterface::class);
    }

    /**
     * Get all vulnerability scanner services.
     */
    public function getVulnerabilityScanners(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\VulnerabilityScannerInterface::class);
    }

    /**
     * Get all firewall services.
     */
    public function getFirewalls(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\FirewallServiceInterface::class);
    }

    /**
     * Get all intrusion prevention services.
     */
    public function getIntrusionPreventionServices(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\IntrusionPreventionInterface::class);
    }

    /**
     * Get all system audit services.
     */
    public function getSystemAuditServices(): Collection
    {
        return $this->getByInterface(\Prahsys\Perimeter\Contracts\SystemAuditInterface::class);
    }
}
