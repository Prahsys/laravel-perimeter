<?php

namespace Prahsys\Perimeter\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Prahsys\Perimeter\Exceptions\ThreatDetectedException;
use Prahsys\Perimeter\Facades\Perimeter;

class PerimeterProtection
{
    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (! config('perimeter.enabled', true)) {
            return $next($request);
        }

        try {
            // Check file uploads for malware
            $files = $request->allFiles();

            if (! empty($files)) {
                foreach ($files as $fileKey => $file) {
                    Log::debug('PerimeterProtection: Scanning file', ['key' => $fileKey, 'name' => $file->getClientOriginalName()]);
                    $result = Perimeter::scan($file);

                    if ($result->hasThreat()) {
                        // Log threat detection
                        Log::critical('Malware detected in uploaded file', [
                            'file' => $file->getClientOriginalName(),
                            'threat' => $result->getThreat(),
                            'ip' => $request->ip(),
                            'user_agent' => $request->userAgent(),
                        ]);

                        // Throw a custom exception that can be caught and tested
                        throw new ThreatDetectedException($result);
                    }
                }
            }

            // Check for suspicious input patterns
            $this->detectSuspiciousInput($request);

            // Apply additional security checks as needed

            return $next($request);
        } catch (ThreatDetectedException $e) {
            // Always rethrow ThreatDetectedException
            throw $e;
        } catch (\Exception $e) {
            // Log other exceptions but allow request to proceed
            Log::error('Perimeter middleware error: '.$e->getMessage(), [
                'exception' => $e,
                'request' => $request->path(),
            ]);

            return $next($request);
        }
    }

    /**
     * Detect suspicious input patterns.
     *
     * @return void
     */
    protected function detectSuspiciousInput(Request $request)
    {
        $input = $request->all();

        // Flatten input array for easier checking
        $flatInput = $this->flattenArray($input);

        // Check for SQL injection patterns
        foreach ($flatInput as $value) {
            if (! is_string($value)) {
                continue;
            }

            // Simple SQL injection detection
            $sqlPatterns = [
                '/\bUNION\s+ALL\s+SELECT\b/i',
                '/\bOR\s+1=1\b/i',
                '/\bDROP\s+TABLE\b/i',
                '/\'.*--/i',
                '/;.*--/i',
                '/\bEXEC\s+xp_cmdshell\b/i',
            ];

            foreach ($sqlPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    Log::critical('Potential SQL injection attempt detected', [
                        'pattern' => $pattern,
                        'value' => $value,
                        'ip' => $request->ip(),
                        'path' => $request->path(),
                    ]);

                    // You can choose to abort here or just log
                    // abort(403, 'Suspicious request detected');
                }
            }

            // Simple XSS detection
            $xssPatterns = [
                '/<script\b[^>]*>(.*?)<\/script>/i',
                '/javascript:[^"]*/i',
                '/onclick\s*=/i',
                '/onload\s*=/i',
                '/onerror\s*=/i',
            ];

            foreach ($xssPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    Log::warning('Potential XSS attempt detected', [
                        'pattern' => $pattern,
                        'value' => $value,
                        'ip' => $request->ip(),
                        'path' => $request->path(),
                    ]);

                    // You can choose to abort here or just log
                    // abort(403, 'Suspicious request detected');
                }
            }
        }
    }

    /**
     * Flatten a multi-dimensional array.
     */
    protected function flattenArray(array $array, string $prefix = ''): array
    {
        $result = [];

        foreach ($array as $key => $value) {
            $newKey = $prefix.$key;

            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value, $newKey.'.'));
            } else {
                $result[$newKey] = $value;
            }
        }

        return $result;
    }
}
