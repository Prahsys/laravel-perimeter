<?php

namespace Prahsys\Perimeter\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\Process\Process;

class PerimeterTerminate extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'perimeter:terminate {--wait=5 : Wait time in seconds for graceful shutdown}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Terminate the perimeter monitoring daemon';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $waitTime = (int) $this->option('wait');

        $this->info('Terminating perimeter monitoring...');

        // Signal all running monitoring processes to terminate
        $terminated = $this->signalTermination();

        if (! $terminated) {
            $this->warn('No active monitoring processes found.');

            return 0;
        }

        $this->info("Waiting up to {$waitTime} seconds for graceful shutdown...");

        // Wait for processes to terminate gracefully
        $startTime = time();
        while ((time() - $startTime) < $waitTime) {
            if (! $this->hasActiveMonitoring()) {
                $this->info('All monitoring processes terminated gracefully.');

                return 0;
            }
            sleep(1);
        }

        // Force kill if still running
        $this->warn('Graceful shutdown timeout reached. Force terminating...');
        $forceKilled = $this->forceTerminate();

        if ($forceKilled) {
            $this->info('Monitoring processes force terminated.');
        } else {
            $this->error('Failed to terminate some monitoring processes.');

            return 1;
        }

        return 0;
    }

    /**
     * Signal termination to monitoring processes
     */
    protected function signalTermination(): bool
    {
        $terminated = false;

        // Set termination signal in cache (similar to Horizon)
        Cache::forever('perimeter:terminate', time());

        // Find and signal PHP processes running perimeter:monitor
        $processes = $this->findMonitoringProcesses();

        foreach ($processes as $pid) {
            $this->line("Sending SIGTERM to process {$pid}");

            // Send SIGTERM for graceful shutdown
            $process = new Process(['kill', '-TERM', $pid]);
            $process->run();

            if ($process->isSuccessful()) {
                $terminated = true;
            }
        }

        return $terminated;
    }

    /**
     * Force terminate monitoring processes
     */
    protected function forceTerminate(): bool
    {
        $processes = $this->findMonitoringProcesses();
        $allKilled = true;

        foreach ($processes as $pid) {
            $this->line("Force killing process {$pid}");

            // Send SIGKILL
            $process = new Process(['kill', '-KILL', $pid]);
            $process->run();

            if (! $process->isSuccessful()) {
                $allKilled = false;
                $this->error("Failed to kill process {$pid}");
            }
        }

        // Clear the termination signal
        Cache::forget('perimeter:terminate');

        return $allKilled;
    }

    /**
     * Find running monitoring processes
     */
    protected function findMonitoringProcesses(): array
    {
        // Look for PHP processes running perimeter:monitor
        $process = new Process(['pgrep', '-f', 'perimeter:monitor']);
        $process->run();

        if (! $process->isSuccessful()) {
            return [];
        }

        $pids = array_filter(array_map('trim', explode("\n", $process->getOutput())));

        // Filter out the current process
        $currentPid = getmypid();

        return array_filter($pids, function ($pid) use ($currentPid) {
            return $pid != $currentPid && is_numeric($pid);
        });
    }

    /**
     * Check if there are active monitoring processes
     */
    protected function hasActiveMonitoring(): bool
    {
        return ! empty($this->findMonitoringProcesses());
    }
}
