<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: SecurityEvent model for logging and tracking security-related events such as
 *              login attempts, permission changes, and other security activities.
 * URL: apex/autentica/src/Core/Models/SecurityEvent.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;
use App\Models\User;

class SecurityEvent extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'Au10_security_events';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'user_id',
        'event_type',
        'event_data',
        'ip_address',
        'user_agent',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'user_id' => 'integer',
        'event_data' => 'array',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Security event types constants.
     */
    const TYPE_LOGIN_SUCCESS = 'login_success';
    const TYPE_LOGIN_FAILED = 'login_failed';
    const TYPE_LOGOUT = 'logout';
    const TYPE_PASSWORD_CHANGED = 'password_changed';
    const TYPE_PASSWORD_RESET = 'password_reset_requested';
    const TYPE_PERMISSION_CHANGED = 'permission_changed';
    const TYPE_GROUP_CHANGED = 'group_membership_changed';
    const TYPE_ACCOUNT_LOCKED = 'account_locked';
    const TYPE_ACCOUNT_UNLOCKED = 'account_unlocked';
    const TYPE_TOKEN_CREATED = 'token_created';
    const TYPE_TOKEN_REVOKED = 'token_revoked';
    const TYPE_PERMISSIONS_COPIED = 'permissions_copied';

    /**
     * Get the user that triggered the event.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('SecurityEvent.php - user() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Scope a query to only include events of a specific type.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $type
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeOfType($query, string $type)
    {
        return $query->where('event_type', $type);
    }

    /**
     * Scope a query to only include events from a specific IP.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $ipAddress
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeFromIp($query, string $ipAddress)
    {
        return $query->where('ip_address', $ipAddress);
    }

    /**
     * Scope a query to only include recent events.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $minutes
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRecent($query, int $minutes = 60)
    {
        return $query->where('created_at', '>=', now()->subMinutes($minutes));
    }

    /**
     * Get event data value by key.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function getEventData(string $key, $default = null)
    {
        try {
            return data_get($this->event_data, $key, $default);
        } catch (\Exception $e) {
            Log::error('SecurityEvent.php - getEventData() method error: ' . $e->getMessage());
            return $default;
        }
    }

    /**
     * Check if event is of a specific type.
     *
     * @param string $type
     * @return bool
     */
    public function isType(string $type): bool
    {
        return $this->event_type === $type;
    }

    /**
     * Get human-readable event description.
     *
     * @return string
     */
    public function getDescription(): string
    {
        try {
            $descriptions = [
                self::TYPE_LOGIN_SUCCESS => 'Successful login',
                self::TYPE_LOGIN_FAILED => 'Failed login attempt',
                self::TYPE_LOGOUT => 'User logged out',
                self::TYPE_PASSWORD_CHANGED => 'Password changed',
                self::TYPE_PASSWORD_RESET => 'Password reset requested',
                self::TYPE_PERMISSION_CHANGED => 'Permissions modified',
                self::TYPE_GROUP_CHANGED => 'Group membership changed',
                self::TYPE_ACCOUNT_LOCKED => 'Account locked',
                self::TYPE_ACCOUNT_UNLOCKED => 'Account unlocked',
                self::TYPE_TOKEN_CREATED => 'Authentication token created',
                self::TYPE_TOKEN_REVOKED => 'Authentication token revoked',
                self::TYPE_PERMISSIONS_COPIED => 'Permissions copied from another user',
            ];

            return $descriptions[$this->event_type] ?? $this->event_type;
        } catch (\Exception $e) {
            Log::error('SecurityEvent.php - getDescription() method error: ' . $e->getMessage());
            return $this->event_type;
        }
    }

    /**
     * Clean up old security events.
     *
     * @param int $daysToKeep
     * @return int Number of deleted records
     */
    public static function cleanup(int $daysToKeep = 90): int
    {
        try {
            return static::where('created_at', '<', now()->subDays($daysToKeep))->delete();
        } catch (\Exception $e) {
            Log::error('SecurityEvent.php - cleanup() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get events grouped by type for a user.
     *
     * @param int $userId
     * @param int $days
     * @return \Illuminate\Support\Collection
     */
    public static function getEventSummaryForUser(int $userId, int $days = 30)
    {
        try {
            return static::where('user_id', $userId)
                ->where('created_at', '>=', now()->subDays($days))
                ->groupBy('event_type')
                ->selectRaw('event_type, COUNT(*) as count')
                ->pluck('count', 'event_type');
        } catch (\Exception $e) {
            Log::error('SecurityEvent.php - getEventSummaryForUser() method error: ' . $e->getMessage());
            return collect();
        }
    }
}
