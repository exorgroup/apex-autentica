<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: PasswordHistory model for tracking password changes and preventing password reuse.
 * URL: exorgroup/apex-autentica/src/Core/Models/PasswordHistory.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Support\Autentica;

class PasswordHistory extends Model
{
    use Signable;

    /**
     * Password history is deliberately NOT soft-deleted. Pruned entries hold old password
     * hashes; retaining them forever is a liability, and the cleanup routines below expect
     * rows to actually disappear. The table carries no deleted_at column.
     */

    /**
     * This table records created_at only — there is nothing to update.
     */
    public const UPDATED_AT = null;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_password_histories';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'user_id',
        'password',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'user_id' => 'integer',
        'created_at' => 'datetime',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<string>
     */
    protected $hidden = [
        'password',
        'signature',
    ];

    /**
     * Get the user that owns the password history.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(Autentica::userModel());
        } catch (\Exception $e) {
            Log::error('PasswordHistory.php - user() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Clean up old password history entries for a user.
     *
     * @param int $userId
     * @param int $keepCount Number of entries to keep
     * @return int Number of entries deleted
     */
    public static function cleanupForUser(int $userId, int $keepCount): int
    {
        try {
            if ($keepCount <= 0) {
                return 0;
            }

            // Get IDs of entries to keep
            $idsToKeep = static::where('user_id', $userId)
                ->orderBy('created_at', 'desc')
                ->limit($keepCount)
                ->pluck('id');

            // Delete older entries
            return static::where('user_id', $userId)
                ->whereNotIn('id', $idsToKeep)
                ->delete();
        } catch (\Exception $e) {
            Log::error('PasswordHistory.php - cleanupForUser() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get the age of the password in days.
     *
     * @return int
     */
    public function getAgeInDays(): int
    {
        try {
            return $this->created_at->diffInDays(now());
        } catch (\Exception $e) {
            Log::error('PasswordHistory.php - getAgeInDays() method error: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Check if password is older than specified days.
     *
     * @param int $days
     * @return bool
     */
    public function isOlderThan(int $days): bool
    {
        try {
            return $this->getAgeInDays() > $days;
        } catch (\Exception $e) {
            Log::error('PasswordHistory.php - isOlderThan() method error: ' . $e->getMessage());
            return false;
        }
    }
}
