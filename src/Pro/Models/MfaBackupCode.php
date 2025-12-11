<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for MFA backup recovery codes with usage tracking and secure hash storage
 * File Location: apex/autentica/src/Pro/Models/MfaBackupCode.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Traits\Signable;

class MfaBackupCode extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_mfa_backup_codes';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'code',
        'used_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'code',
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
            'used_at' => 'datetime',
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

            Log::info('MfaBackupCode model booted successfully', [
                'file' => 'MfaBackupCode.php',
                'method' => 'boot'
            ]);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - boot() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'boot',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the user that owns the backup code.
     *
     * @return BelongsTo
     * @throws \Exception
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - user() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'user',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include unused backup codes.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeUnused($query)
    {
        try {
            return $query->whereNull('used_at');
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - scopeUnused() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'scopeUnused',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include used backup codes.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeUsed($query)
    {
        try {
            return $query->whereNotNull('used_at');
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - scopeUsed() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'scopeUsed',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include codes used within a specific timeframe.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param \Carbon\Carbon $since
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeUsedSince($query, \Carbon\Carbon $since)
    {
        try {
            return $query->whereNotNull('used_at')
                ->where('used_at', '>=', $since);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - scopeUsedSince() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'scopeUsedSince',
                'since' => $since->toDateTimeString(),
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include old used codes for cleanup.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $daysOld
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeOldUsedCodes($query, int $daysOld = 90)
    {
        try {
            $cutoffDate = now()->subDays($daysOld);

            return $query->whereNotNull('used_at')
                ->where('used_at', '<', $cutoffDate);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - scopeOldUsedCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'scopeOldUsedCodes',
                'days_old' => $daysOld,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the backup code has been used.
     *
     * @return bool
     * @throws \Exception
     */
    public function isUsed(): bool
    {
        try {
            return !is_null($this->used_at);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - isUsed() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'isUsed',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the backup code is unused.
     *
     * @return bool
     * @throws \Exception
     */
    public function isUnused(): bool
    {
        try {
            return is_null($this->used_at);
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - isUnused() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'isUnused',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Mark the backup code as used.
     *
     * @return bool
     * @throws \Exception
     */
    public function markAsUsed(): bool
    {
        try {
            if ($this->isUsed()) {
                Log::warning('Attempting to mark already used backup code', [
                    'file' => 'MfaBackupCode.php',
                    'method' => 'markAsUsed',
                    'model_id' => $this->id,
                    'user_id' => $this->user_id,
                    'used_at' => $this->used_at
                ]);
                return false;
            }

            $result = $this->update(['used_at' => now()]);

            Log::info('Backup code marked as used', [
                'file' => 'MfaBackupCode.php',
                'method' => 'markAsUsed',
                'model_id' => $this->id,
                'user_id' => $this->user_id
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - markAsUsed() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'markAsUsed',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the usage status display.
     *
     * @return string
     * @throws \Exception
     */
    public function getUsageStatus(): string
    {
        try {
            if ($this->isUsed()) {
                return 'Used on ' . $this->used_at->format('M j, Y \a\t g:i A');
            }

            return 'Available';
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - getUsageStatus() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'getUsageStatus',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the time since the code was used.
     *
     * @return string|null
     * @throws \Exception
     */
    public function getTimeSinceUsed(): ?string
    {
        try {
            if (!$this->isUsed()) {
                return null;
            }

            return $this->used_at->diffForHumans();
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - getTimeSinceUsed() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'getTimeSinceUsed',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get a masked version of the code for display purposes.
     *
     * @return string
     * @throws \Exception
     */
    public function getMaskedCode(): string
    {
        try {
            // This should only be used for display purposes
            // The actual code is stored as a hash and cannot be retrieved
            return '****-****';
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - getMaskedCode() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'getMaskedCode',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get backup code statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public static function getStatsForUser(User $user): array
    {
        try {
            $totalCodes = self::where('user_id', $user->id)->count();
            $usedCodes = self::where('user_id', $user->id)->used()->count();
            $unusedCodes = $totalCodes - $usedCodes;

            $lastGenerated = self::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $stats = [
                'total_codes' => $totalCodes,
                'used_codes' => $usedCodes,
                'unused_codes' => $unusedCodes,
                'last_generated' => $lastGenerated,
                'has_codes' => $totalCodes > 0,
                'needs_regeneration' => $unusedCodes <= 2,
            ];

            Log::info('Backup code statistics retrieved for user', [
                'file' => 'MfaBackupCode.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - getStatsForUser() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up old used backup codes.
     *
     * @param int $daysOld
     * @return int Number of codes cleaned up
     * @throws \Exception
     */
    public static function cleanupOldUsedCodes(int $daysOld = 90): int
    {
        try {
            $deleted = self::oldUsedCodes($daysOld)->delete();

            Log::info('Old used backup codes cleaned up', [
                'file' => 'MfaBackupCode.php',
                'method' => 'cleanupOldUsedCodes',
                'days_old' => $daysOld,
                'codes_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('MfaBackupCode.php - cleanupOldUsedCodes() method error: ' . $e->getMessage(), [
                'file' => 'MfaBackupCode.php',
                'method' => 'cleanupOldUsedCodes',
                'days_old' => $daysOld,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
