<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for trusted device management with device fingerprinting, activity tracking, and security monitoring
 * File Location: apex/autentica/src/Pro/Models/TrustedDevice.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Traits\Signable;

class TrustedDevice extends Model
{
    use SoftDeletes, Signable;

    protected $table = 'au10_trusted_devices';

    protected $fillable = [
        'user_id',
        'device_id',
        'device_name',
        'browser',
        'platform',
        'ip_address',
        'last_used_at',
    ];

    protected $hidden = ['signature'];

    protected function casts(): array
    {
        return [
            'last_used_at' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    protected static function boot(): void
    {
        try {
            parent::boot();
            static::creating(function ($model) {
                $model->generateSignature();
            });
            static::updating(function ($model) {
                $model->generateSignature();
            });
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - boot() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - user() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeActive($query, int $days = 30)
    {
        try {
            return $query->where('last_used_at', '>', now()->subDays($days));
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - scopeActive() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeInactive($query, int $days = 30)
    {
        try {
            return $query->where('last_used_at', '<=', now()->subDays($days));
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - scopeInactive() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeByDeviceId($query, string $deviceId)
    {
        try {
            return $query->where('device_id', $deviceId);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - scopeByDeviceId() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeByIpAddress($query, string $ipAddress)
    {
        try {
            return $query->where('ip_address', $ipAddress);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - scopeByIpAddress() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function isActive(int $days = 30): bool
    {
        try {
            return $this->last_used_at && $this->last_used_at->gt(now()->subDays($days));
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - isActive() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function isInactive(int $days = 30): bool
    {
        try {
            return !$this->isActive($days);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - isInactive() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function updateLastUsed(?string $ipAddress = null): bool
    {
        try {
            $updateData = ['last_used_at' => now()];
            if ($ipAddress !== null) {
                $updateData['ip_address'] = $ipAddress;
            }
            return $this->update($updateData);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - updateLastUsed() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function getActivityStatus(): string
    {
        try {
            if ($this->isActive(1)) return 'Active (Last 24 hours)';
            if ($this->isActive(7)) return 'Active (Last week)';
            if ($this->isActive(30)) return 'Active (Last month)';
            return 'Inactive';
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getActivityStatus() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function getDisplayName(): string
    {
        try {
            if ($this->device_name) {
                return $this->device_name;
            }
            $browser = $this->browser ?: 'Unknown Browser';
            $platform = $this->platform ?: 'Unknown OS';
            return "{$browser} on {$platform}";
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getDisplayName() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function getLastUsedDisplay(): string
    {
        try {
            return $this->last_used_at ? $this->last_used_at->diffForHumans() : 'Never';
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getLastUsedDisplay() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function updateName(string $newName): bool
    {
        try {
            return $this->update(['device_name' => $newName]);
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - updateName() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public static function getStatsForUser(User $user): array
    {
        try {
            $totalDevices = self::where('user_id', $user->id)->count();
            $activeDevices = self::where('user_id', $user->id)->active(30)->count();
            $inactiveDevices = $totalDevices - $activeDevices;

            $oldestDevice = self::where('user_id', $user->id)
                ->orderBy('created_at', 'asc')
                ->value('created_at');

            $newestDevice = self::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $lastActivity = self::where('user_id', $user->id)
                ->orderBy('last_used_at', 'desc')
                ->value('last_used_at');

            return [
                'total_devices' => $totalDevices,
                'active_devices' => $activeDevices,
                'inactive_devices' => $inactiveDevices,
                'oldest_device' => $oldestDevice,
                'newest_device' => $newestDevice,
                'last_activity' => $lastActivity,
                'has_devices' => $totalDevices > 0,
            ];
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getStatsForUser() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public static function cleanupInactiveDevices(int $daysInactive = 90): int
    {
        try {
            return self::inactive($daysInactive)->delete();
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - cleanupInactiveDevices() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public static function getBrowsersForUser(User $user): array
    {
        try {
            return self::where('user_id', $user->id)
                ->distinct()
                ->pluck('browser')
                ->filter()
                ->toArray();
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getBrowsersForUser() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public static function getPlatformsForUser(User $user): array
    {
        try {
            return self::where('user_id', $user->id)
                ->distinct()
                ->pluck('platform')
                ->filter()
                ->toArray();
        } catch (\Exception $e) {
            Log::error('TrustedDevice.php - getPlatformsForUser() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}
