<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for enhanced session management with device tracking, location data, and security monitoring
 * File Location: apex/autentica/src/Pro/Models/Session.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Traits\Signable;

class Session extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_sessions';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'session_id',
        'ip_address',
        'user_agent',
        'device_id',
        'location',
        'last_activity',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'signature',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'location' => 'array',
            'last_activity' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    /**
     * Boot the model and set up event listeners.
     *
     * @return void
     */
    protected static function boot(): void
    {
        try {
            parent::boot();

            // Generate signature before creating
            static::creating(function ($model) {
                $model->generateSignature();
            });

            // Update signature before updating
            static::updating(function ($model) {
                $model->generateSignature();
            });

            Log::info('Session model booted successfully', [
                'file' => 'Session.php',
                'method' => 'boot'
            ]);
        } catch (\Exception $e) {
            Log::error('Session.php - boot() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'boot',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the user that owns the session.
     *
     * @return BelongsTo
     * @throws \Exception
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('Session.php - user() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'user',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include active sessions (recent activity).
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $hours Hours to consider as "active"
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeActive($query, int $hours = 1)
    {
        try {
            return $query->where('last_activity', '>', now()->subHours($hours));
        } catch (\Exception $e) {
            Log::error('Session.php - scopeActive() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'scopeActive',
                'hours' => $hours,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include expired sessions.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $hours Hours of inactivity to consider expired
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeExpired($query, int $hours = 24)
    {
        try {
            return $query->where('last_activity', '<', now()->subHours($hours));
        } catch (\Exception $e) {
            Log::error('Session.php - scopeExpired() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'scopeExpired',
                'hours' => $hours,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to filter by session ID.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $sessionId
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeBySessionId($query, string $sessionId)
    {
        try {
            return $query->where('session_id', $sessionId);
        } catch (\Exception $e) {
            Log::error('Session.php - scopeBySessionId() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'scopeBySessionId',
                'session_id' => $sessionId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to filter by device ID.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $deviceId
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeByDeviceId($query, string $deviceId)
    {
        try {
            return $query->where('device_id', $deviceId);
        } catch (\Exception $e) {
            Log::error('Session.php - scopeByDeviceId() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'scopeByDeviceId',
                'device_id' => $deviceId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to filter by IP address.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $ipAddress
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeByIpAddress($query, string $ipAddress)
    {
        try {
            return $query->where('ip_address', $ipAddress);
        } catch (\Exception $e) {
            Log::error('Session.php - scopeByIpAddress() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'scopeByIpAddress',
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the session is active (recent activity).
     *
     * @param int $hours Hours to consider as "active"
     * @return bool
     * @throws \Exception
     */
    public function isActive(int $hours = 1): bool
    {
        try {
            return $this->last_activity && $this->last_activity->gt(now()->subHours($hours));
        } catch (\Exception $e) {
            Log::error('Session.php - isActive() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'isActive',
                'model_id' => $this->id ?? 'unknown',
                'hours' => $hours,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the session is expired (no recent activity).
     *
     * @param int $hours Hours of inactivity to consider expired
     * @return bool
     * @throws \Exception
     */
    public function isExpired(int $hours = 24): bool
    {
        try {
            return !$this->last_activity || $this->last_activity->lt(now()->subHours($hours));
        } catch (\Exception $e) {
            Log::error('Session.php - isExpired() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'isExpired',
                'model_id' => $this->id ?? 'unknown',
                'hours' => $hours,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update the session's last activity timestamp.
     *
     * @param string|null $ipAddress
     * @return bool
     * @throws \Exception
     */
    public function updateActivity(?string $ipAddress = null): bool
    {
        try {
            $updateData = ['last_activity' => now()];

            if ($ipAddress !== null) {
                $updateData['ip_address'] = $ipAddress;
            }

            $result = $this->update($updateData);

            Log::info('Session activity updated', [
                'file' => 'Session.php',
                'method' => 'updateActivity',
                'model_id' => $this->id,
                'user_id' => $this->user_id,
                'session_id' => $this->session_id,
                'ip_address' => $ipAddress
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('Session.php - updateActivity() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'updateActivity',
                'model_id' => $this->id ?? 'unknown',
                'ip_address' => $ipAddress,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the session activity status display.
     *
     * @return string
     * @throws \Exception
     */
    public function getActivityStatus(): string
    {
        try {
            if ($this->isActive(1)) {
                return 'Active';
            }

            if ($this->isActive(24)) {
                return 'Inactive (last 24h)';
            }

            return 'Expired';
        } catch (\Exception $e) {
            Log::error('Session.php - getActivityStatus() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getActivityStatus',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the last activity display.
     *
     * @return string
     * @throws \Exception
     */
    public function getLastActivityDisplay(): string
    {
        try {
            if (!$this->last_activity) {
                return 'Never';
            }

            return $this->last_activity->diffForHumans();
        } catch (\Exception $e) {
            Log::error('Session.php - getLastActivityDisplay() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getLastActivityDisplay',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the location display string.
     *
     * @return string
     * @throws \Exception
     */
    public function getLocationDisplay(): string
    {
        try {
            if (!$this->location || !is_array($this->location)) {
                return 'Unknown';
            }

            $parts = [];

            if (!empty($this->location['city'])) {
                $parts[] = $this->location['city'];
            }

            if (!empty($this->location['region'])) {
                $parts[] = $this->location['region'];
            }

            if (!empty($this->location['country'])) {
                $parts[] = $this->location['country'];
            }

            return !empty($parts) ? implode(', ', $parts) : 'Unknown';
        } catch (\Exception $e) {
            Log::error('Session.php - getLocationDisplay() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getLocationDisplay',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Parse browser information from user agent.
     *
     * @return string
     * @throws \Exception
     */
    public function getBrowserInfo(): string
    {
        try {
            if (!$this->user_agent) {
                return 'Unknown Browser';
            }

            $userAgent = $this->user_agent;

            if (stripos($userAgent, 'Edg/') !== false) return 'Edge';
            if (stripos($userAgent, 'Chrome') !== false) return 'Chrome';
            if (stripos($userAgent, 'Firefox') !== false) return 'Firefox';
            if (stripos($userAgent, 'Safari') !== false && stripos($userAgent, 'Chrome') === false) return 'Safari';
            if (stripos($userAgent, 'Opera') !== false || stripos($userAgent, 'OPR') !== false) return 'Opera';

            return 'Unknown Browser';
        } catch (\Exception $e) {
            Log::error('Session.php - getBrowserInfo() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getBrowserInfo',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Parse platform information from user agent.
     *
     * @return string
     * @throws \Exception
     */
    public function getPlatformInfo(): string
    {
        try {
            if (!$this->user_agent) {
                return 'Unknown Platform';
            }

            $userAgent = $this->user_agent;

            if (stripos($userAgent, 'Windows NT') !== false) return 'Windows';
            if (stripos($userAgent, 'Macintosh') !== false || stripos($userAgent, 'Mac OS') !== false) return 'macOS';
            if (stripos($userAgent, 'X11') !== false || stripos($userAgent, 'Linux') !== false) return 'Linux';
            if (stripos($userAgent, 'iPhone') !== false) return 'iOS';
            if (stripos($userAgent, 'iPad') !== false) return 'iPadOS';
            if (stripos($userAgent, 'Android') !== false) return 'Android';

            return 'Unknown Platform';
        } catch (\Exception $e) {
            Log::error('Session.php - getPlatformInfo() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getPlatformInfo',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get session duration.
     *
     * @return string
     * @throws \Exception
     */
    public function getDuration(): string
    {
        try {
            if (!$this->last_activity) {
                return '0 minutes';
            }

            return $this->created_at->diffForHumans($this->last_activity, true);
        } catch (\Exception $e) {
            Log::error('Session.php - getDuration() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getDuration',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get session statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public static function getStatsForUser(User $user): array
    {
        try {
            $totalSessions = self::where('user_id', $user->id)->count();
            $activeSessions = self::where('user_id', $user->id)->active(1)->count();
            $uniqueDevices = self::where('user_id', $user->id)
                ->distinct('device_id')
                ->count('device_id');
            $lastActivity = self::where('user_id', $user->id)
                ->orderBy('last_activity', 'desc')
                ->value('last_activity');

            $stats = [
                'total_sessions' => $totalSessions,
                'active_sessions' => $activeSessions,
                'unique_devices' => $uniqueDevices,
                'last_activity' => $lastActivity,
                'has_sessions' => $totalSessions > 0,
            ];

            Log::info('Session statistics retrieved for user', [
                'file' => 'Session.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('Session.php - getStatsForUser() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up expired sessions.
     *
     * @param int $hoursInactive Hours of inactivity before session is considered expired
     * @return int Number of sessions cleaned up
     * @throws \Exception
     */
    public static function cleanupExpired(int $hoursInactive = 24): int
    {
        try {
            $deleted = self::expired($hoursInactive)->delete();

            Log::info('Expired sessions cleaned up', [
                'file' => 'Session.php',
                'method' => 'cleanupExpired',
                'hours_inactive' => $hoursInactive,
                'sessions_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('Session.php - cleanupExpired() method error: ' . $e->getMessage(), [
                'file' => 'Session.php',
                'method' => 'cleanupExpired',
                'hours_inactive' => $hoursInactive,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
