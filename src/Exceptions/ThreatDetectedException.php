<?php

namespace Prahsys\Perimeter\Exceptions;

use Exception;
use Prahsys\Perimeter\ScanResult;

class ThreatDetectedException extends Exception
{
    protected $scanResult;

    /**
     * Create a new threat detected exception.
     *
     * @param  string  $message
     * @param  int  $code
     */
    public function __construct(ScanResult $scanResult, $message = '', $code = 422, ?Exception $previous = null)
    {
        $this->scanResult = $scanResult;

        if (empty($message)) {
            $message = 'Security threat detected in uploaded file: '.$scanResult->getThreat();
        }

        parent::__construct($message, $code, $previous);
    }

    /**
     * Get the scan result that triggered this exception.
     *
     * @return ScanResult
     */
    public function getScanResult()
    {
        return $this->scanResult;
    }

    /**
     * Render the exception as an HTTP response.
     *
     * @return \Illuminate\Http\Response
     */
    public function render()
    {
        return response([
            'message' => $this->getMessage(),
            'threat' => $this->scanResult->getThreat(),
        ], 422);
    }
}
