<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: LoginAttempt model for tracking successful and failed login attempts,
 *              used for security monitoring and account lockout functionality.
 * URL: apex/autentica/src/Core/Models/LoginAttempt.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;

class LoginAttempt extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'Au10_login_attempts';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'email',
        'ip_address',
        'user_agent',
        'successful',
        'attempted_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'successful' => 'boolean',
        'attempted_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Scope a query to only include successful attempts.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeSuccessful($query)
    {
        return $query->where('successful', true);
    }

    /**
     * Scope a query to only include failed attempts.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeFailed($query)
    {
        return $query->where('successful', false);
    }

    /**
     * Scope a query to only include recent attempts.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $minutes
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRecent($query, int $minutes = 15)
    {
        return $query->where('attempted_at', '>=', now()->subMinutes($minutes));
    }

    /**
     * Scope a query to attempts from a specific IP.
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
     * Scope a query to attempts for a specific email.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $email
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeForEmail($query, string $email)
    {
        return $query->where('email', $email);
    }

    /**
     * Get failed attempts count for an email within a time period.
     *
     * @param string $email
     * @param int $minutes
     * @return int
     */
    public static function getFailedCount(string $email, int $minutes = 15): int
    {
        try {
            return static::forEmail($email)
                ->failed()
                ->recent($minutes)
                ->count();
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - getFailedCount() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get the last successful attempt for an email.
     *
     * @param string $email
     * @return \Apex\Autentica\Core\Models\LoginAttempt|null
     */
    public static function getLastSuccessful(string $email): ?LoginAttempt
    {
        try {
            return static::forEmail($email)
                ->successful()
                ->orderBy('attempted_at', 'desc')
                ->first();
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - getLastSuccessful() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get the last failed attempt for an email.
     *
     * @param string $email
     * @return \Apex\Autentica\Core\Models\LoginAttempt|null
     */
    public static function getLastFailed(string $email): ?LoginAttempt
    {
        try {
            return static::forEmail($email)
                ->failed()
                ->orderBy('attempted_at', 'desc')
                ->first();
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - getLastFailed() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Check if an email is currently locked out.
     *
     * @param string $email
     * @param int $maxAttempts
     * @param int $lockoutMinutes
     * @return bool
     */
    public static function isLocked(string $email, int $maxAttempts = 5, int $lockoutMinutes = 15): bool
    {
        try {
            $failedCount = static::getFailedCount($email, $lockoutMinutes);

            if ($failedCount >= $maxAttempts) {
                // Check if there's been a successful login since the lockout
                $lastSuccess = static::getLastSuccessful($email);
                $lastFailed = static::getLastFailed($email);

                if (!$lastSuccess || ($lastFailed && $lastFailed->attempted_at->gt($lastSuccess->attempted_at))) {
                    return true;
                }
            }

            return false;
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - isLocked() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get time until unlock in minutes.
     *
     * @param string $email
     * @param int $lockoutMinutes
     * @return int
     */
    public static function getUnlockTime(string $email, int $lockoutMinutes = 15): int
    {
        try {
            $lastFailed = static::getLastFailed($email);

            if (!$lastFailed) {
                return 0;
            }

            $unlockTime = $lastFailed->attempted_at->addMinutes($lockoutMinutes);
            return max(0, now()->diffInMinutes($unlockTime, false));
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - getUnlockTime() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Clean up old login attempts.
     *
     * @param int $daysToKeep
     * @return int Number of deleted records
     */
    public static function cleanup(int $daysToKeep = 30): int
    {
        try {
            return static::where('attempted_at', '<', now()->subDays($daysToKeep))->delete();
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - cleanup() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get suspicious IPs based on failed attempt patterns.
     *
     * @param int $threshold
     * @param int $hours
     * @return \Illuminate\Support\Collection
     */
    public static function getSuspiciousIps(int $threshold = 10, int $hours = 24)
    {
        try {
            return static::failed()
                ->where('attempted_at', '>=', now()->subHours($hours))
                ->groupBy('ip_address')
                ->selectRaw('ip_address, COUNT(*) as attempt_count')
                ->having('attempt_count', '>=', $threshold)
                ->orderBy('attempt_count', 'desc')
                ->pluck('attempt_count', 'ip_address');
        } catch (\Exception $e) {
            Log::error('LoginAttempt.php - getSuspiciousIps() method error: ' . $e->getMessage());
            return collect();
        }
    }
}
