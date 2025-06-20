<?php

namespace Prahsys\Perimeter\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;

class SecurityScan extends Model
{
    use HasFactory, Prunable;

    /**
     * Create a new factory instance for the model.
     *
     * @return \Illuminate\Database\Eloquent\Factories\Factory
     */
    protected static function newFactory()
    {
        return \Prahsys\Perimeter\Database\Factories\SecurityScanFactory::new();
    }

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'perimeter_security_scans';

    /**
     * The connection name for the model.
     *
     * @var string|null
     */
    protected $connection = null;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'scan_type',
        'started_at',
        'completed_at',
        'status',
        'issues_found',
        'scan_details',
        'command',
        'command_options',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
        'scan_details' => 'json',
        'command_options' => 'json',
        'issues_found' => 'integer',
    ];

    /**
     * Bootstrap the model.
     */
    protected static function boot()
    {
        parent::boot();

        // Set the connection from config
        $connection = config('perimeter.storage.connection');
        if ($connection) {
            static::$connection = $connection;
        }

        // Allow overriding the table name with a different prefix if configured
        $prefix = config('perimeter.storage.table_prefix', 'perimeter_');
        if ($prefix !== 'perimeter_') {
            static::$table = $prefix.'security_scans';
        }
    }

    /**
     * Get the security events for this scan.
     */
    public function events()
    {
        return $this->hasMany(config('perimeter.storage.models.security_event', SecurityEvent::class), 'scan_id');
    }

    /**
     * Get the prunable model query.
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function prunable()
    {
        $retentionDays = config('perimeter.reporting.retention_days', 90);

        return static::where('created_at', '<=', now()->subDays($retentionDays));
    }

    /**
     * Perform actions before pruning the model.
     *
     * @return void
     */
    protected function pruning()
    {
        // Prune related events when the scan is pruned
        $this->events()->each(function ($event) {
            $event->delete();
        });
    }

    /**
     * Scope a query to only include scans of a specific type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|array  $type
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeOfType($query, $type)
    {
        if (is_array($type)) {
            return $query->whereIn('scan_type', $type);
        }

        return $query->where('scan_type', $type);
    }

    /**
     * Scope a query to only include scans from a specific time period.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|\Carbon\Carbon  $from
     * @param  string|\Carbon\Carbon  $to
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeInPeriod($query, $from, $to = null)
    {
        $query = $query->where('started_at', '>=', $from);

        if ($to) {
            $query = $query->where('started_at', '<=', $to);
        }

        return $query;
    }

    /**
     * Create a new scan record and mark it as started.
     *
     * @param  string  $scanType
     * @param  string|null  $command
     * @param  array  $options
     * @return static
     */
    public static function start($scanType, $command = null, $options = [])
    {
        return static::create([
            'scan_type' => $scanType,
            'started_at' => now(),
            'status' => 'running',
            'command' => $command,
            'command_options' => $options,
        ]);
    }

    /**
     * Mark the scan as completed.
     *
     * @param  int  $issuesFound
     * @param  array  $details
     * @return $this
     */
    public function complete($issuesFound = 0, $details = [])
    {
        $this->update([
            'completed_at' => now(),
            'status' => 'completed',
            'issues_found' => $issuesFound,
            'scan_details' => $details,
        ]);

        return $this;
    }

    /**
     * Mark the scan as failed.
     *
     * @param  array  $details
     * @return $this
     */
    public function fail($details = [])
    {
        $this->update([
            'completed_at' => now(),
            'status' => 'failed',
            'scan_details' => $details,
        ]);

        return $this;
    }
}
