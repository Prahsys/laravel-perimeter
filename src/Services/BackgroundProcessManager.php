<?php

namespace Prahsys\Perimeter\Services;

use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\Process;

class BackgroundProcessManager
{
    /**
     * Callback registry for event handlers
     * 
     * @var array<string, array<callable>>
     */
    protected array $eventHandlers = [];
    
    /**
     * Output pipes for streaming processes
     * 
     * @var array<string, resource>
     */
    protected array $outputPipes = [];
    
    /**
     * Start a process in the background and return its PID.
     *
     * @param string|array $command Command to run (string or array of arguments)
     * @param string|null $name Identifier for the process (used for PID file)
     * @param array $options Additional options
     * @return int|null The process ID or null on failure
     */
    public function start($command, ?string $name = null, array $options = []): ?int
    {
        try {
            $name = $name ?? 'process-' . md5(is_array($command) ? implode(' ', $command) : $command);
            
            // Check if we should enable real-time output streaming
            $enableStreaming = $options['stream_output'] ?? false;
            
            // Prepare the command
            if (is_string($command)) {
                // For string commands, wrap in sh -c
                if ($enableStreaming) {
                    // Don't use nohup or & if we want to stream output
                    $process = new Process(['sh', '-c', $command]);
                } else {
                    $process = new Process(['nohup', 'sh', '-c', $command . ' &']);
                }
            } else {
                if ($enableStreaming) {
                    // Don't use nohup or & if we want to stream output
                    $process = new Process($command);
                } else {
                    // For array commands, append & to run in background
                    $command[] = '&';
                    $process = new Process(array_merge(['nohup'], $command));
                }
            }
            
            // Configure the process
            if (!$enableStreaming) {
                $process->disableOutput();
            }
            
            if (!empty($options['timeout'])) {
                $process->setTimeout($options['timeout']);
            }
            
            // Set environment variables if provided
            if (!empty($options['env'])) {
                $process->setEnv($options['env']);
            }
            
            // Start the process
            if ($enableStreaming) {
                // Enable output streaming
                $process->start(function ($type, $buffer) use ($name) {
                    $this->handleProcessOutput($name, $type, $buffer);
                });
                
                // Store the process object for later interaction
                $this->storeProcess($name, $process);
                
                // If we're streaming, the PID is readily available
                $pid = $process->getPid();
            } else {
                // Start process without output callback
                $process->start();
                
                // Wait briefly to ensure process started
                usleep(100000); // 0.1 seconds
                
                // Get the PID (might require different approaches)
                $pid = $this->findProcessPid($name, $command);
            }
            
            if ($pid) {
                // Store the PID for later reference
                $this->storePid($name, $pid);
                
                Log::info("Started background process: {$name}", [
                    'pid' => $pid,
                    'streaming' => $enableStreaming,
                    'command' => is_array($command) ? implode(' ', $command) : $command
                ]);
                
                return $pid;
            }
            
            Log::warning("Process started but could not determine PID: {$name}");
            return null;
        } catch (\Exception $e) {
            Log::error("Failed to start background process: {$e->getMessage()}", [
                'name' => $name,
                'command' => $command,
                'exception' => $e
            ]);
            
            return null;
        }
    }
    
    /**
     * Store a process object for later interaction.
     * 
     * @param string $name Process name
     * @param Process $process Process object
     */
    protected function storeProcess(string $name, Process $process): void
    {
        // Create a file to store the serialized process info
        $processFile = sys_get_temp_dir() . '/perimeter_' . preg_replace('/[^a-z0-9_-]/i', '_', $name) . '.process';
        
        // We can't serialize the process object, so we'll just store some key info
        $info = [
            'pid' => $process->getPid(),
            'command' => $process->getCommandLine(),
            'created_at' => time(),
        ];
        
        file_put_contents($processFile, json_encode($info));
    }
    
    /**
     * Handle output from a streaming process.
     * 
     * @param string $name Process name
     * @param string $type Output type (out or err)
     * @param string $buffer Output content
     */
    protected function handleProcessOutput(string $name, string $type, string $buffer): void
    {
        // Process the output
        if ($type === Process::OUT) {
            // Standard output
            $this->fireEvent($name, 'output', $buffer);
        } else {
            // Error output
            $this->fireEvent($name, 'error', $buffer);
        }
        
        // Also fire a general data event
        $this->fireEvent($name, 'data', [
            'type' => $type,
            'content' => $buffer
        ]);
    }
    
    /**
     * Stop a background process by name or PID.
     *
     * @param string|int $processId Name or PID of the process
     * @param bool $force Use SIGKILL instead of SIGTERM
     * @return bool Whether the process was successfully stopped
     */
    public function stop($processId, bool $force = false): bool
    {
        try {
            // If process ID is a string, assume it's a name and look up the PID
            if (is_string($processId) && !is_numeric($processId)) {
                $pid = $this->getPid($processId);
                if (!$pid) {
                    Log::warning("No PID found for process: {$processId}");
                    return false;
                }
            } else {
                $pid = (int)$processId;
            }
            
            // Check if process is running
            if (!$this->isRunning($pid)) {
                Log::info("Process {$pid} is not running");
                $this->removePidFile(is_string($processId) ? $processId : null);
                return true; // Consider it a success if it's already not running
            }
            
            // Send signal based on force parameter
            $signal = $force ? 'SIGKILL' : 'SIGTERM';
            $killCommand = $force ? ['kill', '-9', $pid] : ['kill', $pid];
            
            $process = new Process($killCommand);
            $process->run();
            
            // Wait briefly to allow process to terminate
            usleep(500000); // 0.5 seconds
            
            // Check if process is still running
            $isStillRunning = $this->isRunning($pid);
            
            if ($isStillRunning && !$force) {
                // If still running and not using force, try with SIGKILL
                Log::info("Process {$pid} did not terminate with SIGTERM, trying SIGKILL");
                return $this->stop($pid, true);
            }
            
            // Remove PID file if we have a name
            if (is_string($processId)) {
                $this->removePidFile($processId);
            }
            
            Log::info("Stopped background process " . (is_string($processId) ? "{$processId} " : "") . "with PID {$pid}");
            return !$isStillRunning;
        } catch (\Exception $e) {
            Log::error("Failed to stop process: {$e->getMessage()}", [
                'process_id' => $processId,
                'exception' => $e
            ]);
            
            return false;
        }
    }
    
    /**
     * Schedule a process to be terminated after a specified duration.
     *
     * @param string|int $processId Name or PID of the process
     * @param int $duration Duration in seconds before termination
     * @return bool Whether the termination was successfully scheduled
     */
    public function scheduleTermination($processId, int $duration): bool
    {
        try {
            // If process ID is a string, assume it's a name and look up the PID
            if (is_string($processId) && !is_numeric($processId)) {
                $pid = $this->getPid($processId);
                if (!$pid) {
                    Log::warning("No PID found for process: {$processId}");
                    return false;
                }
            } else {
                $pid = (int)$processId;
            }
            
            // Create a detached process that will sleep and then terminate the process
            $killCommand = "sleep {$duration} && kill {$pid} > /dev/null 2>&1";
            $process = new Process(['nohup', 'sh', '-c', $killCommand, '&']);
            $process->disableOutput();
            $process->start();
            
            Log::info("Scheduled termination of process {$pid} in {$duration} seconds");
            return true;
        } catch (\Exception $e) {
            Log::error("Failed to schedule termination: {$e->getMessage()}", [
                'process_id' => $processId,
                'duration' => $duration,
                'exception' => $e
            ]);
            
            return false;
        }
    }
    
    /**
     * Check if a process is running.
     *
     * @param int $pid Process ID
     * @return bool Whether the process is running
     */
    public function isRunning(int $pid): bool
    {
        try {
            $process = new Process(['ps', '-p', (string)$pid]);
            $process->run();
            
            return $process->isSuccessful();
        } catch (\Exception $e) {
            Log::warning("Error checking if process {$pid} is running: {$e->getMessage()}");
            return false;
        }
    }
    
    /**
     * Get the PID for a named process.
     *
     * @param string $name Process name
     * @return int|null The process ID or null if not found
     */
    public function getPid(string $name): ?int
    {
        $pidFile = $this->getPidFilePath($name);
        
        if (file_exists($pidFile)) {
            $pid = (int)file_get_contents($pidFile);
            
            // Verify the PID is valid and the process is running
            if ($pid > 0 && $this->isRunning($pid)) {
                return $pid;
            }
            
            // If process is not running, clean up the PID file
            $this->removePidFile($name);
        }
        
        return null;
    }
    
    /**
     * Store a PID for a named process.
     *
     * @param string $name Process name
     * @param int $pid Process ID
     * @return bool Whether the PID was successfully stored
     */
    protected function storePid(string $name, int $pid): bool
    {
        try {
            $pidFile = $this->getPidFilePath($name);
            file_put_contents($pidFile, $pid);
            
            return true;
        } catch (\Exception $e) {
            Log::warning("Failed to store PID for {$name}: {$e->getMessage()}");
            return false;
        }
    }
    
    /**
     * Remove a PID file.
     *
     * @param string|null $name Process name
     * @return bool Whether the PID file was successfully removed
     */
    protected function removePidFile(?string $name): bool
    {
        if (!$name) {
            return false;
        }
        
        try {
            $pidFile = $this->getPidFilePath($name);
            
            if (file_exists($pidFile)) {
                unlink($pidFile);
                return true;
            }
            
            return false;
        } catch (\Exception $e) {
            Log::warning("Failed to remove PID file for {$name}: {$e->getMessage()}");
            return false;
        }
    }
    
    /**
     * Get the path to a PID file.
     *
     * @param string $name Process name
     * @return string Path to the PID file
     */
    protected function getPidFilePath(string $name): string
    {
        return sys_get_temp_dir() . '/perimeter_' . preg_replace('/[^a-z0-9_-]/i', '_', $name) . '.pid';
    }
    
    /**
     * Register an event handler for a process.
     *
     * @param string $processName Name of the process
     * @param string $event Event name ('output', 'error', 'data', 'start', 'stop')
     * @param callable $callback Function to call when event occurs
     * @return self For method chaining
     */
    public function on(string $processName, string $event, callable $callback): self
    {
        $key = "{$processName}.{$event}";
        
        if (!isset($this->eventHandlers[$key])) {
            $this->eventHandlers[$key] = [];
        }
        
        $this->eventHandlers[$key][] = $callback;
        
        return $this;
    }
    
    /**
     * Remove all event handlers for a process or specific event.
     *
     * @param string $processName Name of the process
     * @param string|null $event Optional event name to clear specific handlers
     * @return self For method chaining
     */
    public function off(string $processName, ?string $event = null): self
    {
        if ($event === null) {
            // Clear all events for this process
            foreach (array_keys($this->eventHandlers) as $key) {
                if (strpos($key, "{$processName}.") === 0) {
                    unset($this->eventHandlers[$key]);
                }
            }
        } else {
            // Clear specific event
            $key = "{$processName}.{$event}";
            unset($this->eventHandlers[$key]);
        }
        
        return $this;
    }
    
    /**
     * Fire an event to all registered handlers.
     *
     * @param string $processName Name of the process
     * @param string $event Event name
     * @param mixed $data Data to pass to handlers
     */
    protected function fireEvent(string $processName, string $event, $data): void
    {
        $key = "{$processName}.{$event}";
        
        if (isset($this->eventHandlers[$key])) {
            foreach ($this->eventHandlers[$key] as $callback) {
                try {
                    call_user_func($callback, $data);
                } catch (\Exception $e) {
                    Log::warning("Error in event handler for {$key}: {$e->getMessage()}");
                }
            }
        }
    }
    
    /**
     * Send data/input to a running process.
     *
     * @param string|int $processId Name or PID of the process
     * @param string $input Data to send to the process
     * @return bool Whether the data was successfully sent
     */
    public function sendInput($processId, string $input): bool
    {
        // This will only work with streaming processes that maintain stdin pipe
        try {
            // Get process info
            $name = is_string($processId) ? $processId : null;
            $processFile = $name ? sys_get_temp_dir() . '/perimeter_' . preg_replace('/[^a-z0-9_-]/i', '_', $name) . '.process' : null;
            
            if ($processFile && file_exists($processFile)) {
                $info = json_decode(file_get_contents($processFile), true);
                $pid = $info['pid'] ?? null;
                
                if ($pid && $this->isRunning($pid)) {
                    // Send input using echo and process substitution
                    $process = new Process(['sh', '-c', "echo " . escapeshellarg($input) . " > /proc/{$pid}/fd/0"]);
                    $process->run();
                    
                    return $process->isSuccessful();
                }
            }
            
            return false;
        } catch (\Exception $e) {
            Log::error("Failed to send input to process: {$e->getMessage()}");
            return false;
        }
    }
    
    /**
     * Find the PID of a process by name or command.
     *
     * @param string $name Process name
     * @param string|array $command Command that was executed
     * @return int|null The process ID or null if not found
     */
    protected function findProcessPid(string $name, $command): ?int
    {
        try {
            // First try to get by name from pidof if it's a simple command
            if (is_array($command) && count($command) > 0) {
                $baseCommand = basename($command[0]);
                $pidofProcess = new Process(['pidof', $baseCommand]);
                $pidofProcess->run();
                
                if ($pidofProcess->isSuccessful()) {
                    $pids = explode(' ', trim($pidofProcess->getOutput()));
                    if (!empty($pids)) {
                        // Return the most recently created PID (usually the last one)
                        return (int)trim($pids[0]);
                    }
                }
            }
            
            // For more complex commands, use pgrep with pattern matching
            $searchPattern = is_array($command) 
                ? escapeshellarg(implode(' ', array_filter($command, function($arg) { return $arg !== '&'; })))
                : escapeshellarg($command);
            
            $pgrepProcess = new Process(['pgrep', '-f', $searchPattern]);
            $pgrepProcess->run();
            
            if ($pgrepProcess->isSuccessful()) {
                $pids = explode("\n", trim($pgrepProcess->getOutput()));
                if (!empty($pids)) {
                    // Return the first PID found
                    return (int)$pids[0];
                }
            }
            
            // As a fallback for recent processes, use ps and grep
            $psCommand = "ps -eo pid,cmd --sort=-start_time | grep " . $searchPattern . " | grep -v grep | head -1 | awk '{print $1}'";
            $psProcess = new Process(['sh', '-c', $psCommand]);
            $psProcess->run();
            
            if ($psProcess->isSuccessful() && !empty(trim($psProcess->getOutput()))) {
                return (int)trim($psProcess->getOutput());
            }
            
            return null;
        } catch (\Exception $e) {
            Log::warning("Error finding PID for {$name}: {$e->getMessage()}");
            return null;
        }
    }
}