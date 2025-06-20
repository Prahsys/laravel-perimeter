<?php

namespace Prahsys\Perimeter\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;

class SecurityEvent extends Model
{
    use HasFactory, Prunable;

    /**
     * Create a new factory instance for the model.
     *
     * @return \Illuminate\Database\Eloquent\Factories\Factory
     */
    protected static function newFactory()
    {
        return \Prahsys\Perimeter\Database\Factories\SecurityEventFactory::new();
    }

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'perimeter_security_events';

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
        'scan_id',
        'timestamp',
        'type',
        'severity',
        'description',
        'location',
        'user',
        'service',
        'details',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'timestamp' => 'datetime',
        'details' => 'json',
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
            static::$table = $prefix.'security_events';
        }
    }

    /**
     * Get the security scan that this event belongs to.
     */
    public function scan()
    {
        return $this->belongsTo(config('perimeter.storage.models.security_scan', SecurityScan::class), 'scan_id');
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
     * Scope a query to only include events of a specific type.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|array  $type
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeOfType($query, $type)
    {
        if (is_array($type)) {
            return $query->whereIn('type', $type);
        }

        return $query->where('type', $type);
    }

    /**
     * Scope a query to only include events of specific severity levels.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|array  $severity
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeOfSeverity($query, $severity)
    {
        if (is_array($severity)) {
            return $query->whereIn('severity', $severity);
        }

        return $query->where('severity', $severity);
    }

    /**
     * Scope a query to only include events from a specific time period.
     *
     * @param  \Illuminate\Database\Eloquent\Builder  $query
     * @param  string|\Carbon\Carbon  $from
     * @param  string|\Carbon\Carbon  $to
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeInPeriod($query, $from, $to = null)
    {
        $query = $query->where('timestamp', '>=', $from);

        if ($to) {
            $query = $query->where('timestamp', '<=', $to);
        }

        return $query;
    }

    /**
     * Format the event for a report.
     *
     * @return array
     */
    public function toReportFormat()
    {
        return [
            'id' => $this->id,
            'scan_id' => $this->scan_id,
            'timestamp' => $this->timestamp->toIso8601String(),
            'type' => $this->type,
            'severity' => $this->severity,
            'description' => $this->description,
            'location' => $this->location,
            'user' => $this->user,
            'service' => $this->service,
            'details' => $this->details,
        ];
    }
}
