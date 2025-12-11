<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: AuthToken model for managing authentication tokens including remember tokens,
 *              API tokens, and session tokens.
 * URL: apex/autentica/src/Core/Models/AuthToken.php
 */

namespace Apex\Autentica\Core\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Apex\Autentica\Core\Traits\Signable;
use Illuminate\Support\Facades\Log;
use App\Models\User;

class AuthToken extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'Au10_auth_tokens';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'user_id',
        'token',
        'type',
        'expires_at',
        'last_used_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'user_id' => 'integer',
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime',
    ];

    /**
     * Get the user that owns the token.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('AuthToken.php - user() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Check if the token is valid.
     *
     * @return bool
     */
    public function isValid(): bool
    {
        try {
            // Check if token has expired
            if ($this->expires_at && $this->expires_at->isPast()) {
                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - isValid() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if the token is expired.
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        try {
            return $this->expires_at && $this->expires_at->isPast();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - isExpired() method error: ' . $e->getMessage());
            return true;
        }
    }

    /**
     * Update the last used timestamp.
     *
     * @return bool
     */
    public function touchLastUsed(): bool
    {
        try {
            $this->last_used_at = now();
            return $this->save();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - touchLastUsed() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Find a valid token by its value.
     *
     * @param string $token
     * @param string $type
     * @return \Apex\Autentica\Core\Models\AuthToken|null
     */
    public static function findValidToken(string $token, string $type): ?AuthToken
    {
        try {
            $hashedToken = hash('sha256', $token);

            $authToken = static::where('token', $hashedToken)
                ->where('type', $type)
                ->where(function ($query) {
                    $query->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                })
                ->first();

            return $authToken;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - findValidToken() method error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Revoke the token.
     *
     * @return bool
     */
    public function revoke(): bool
    {
        try {
            return $this->delete();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - revoke() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Clean up expired tokens.
     *
     * @return int Number of tokens deleted
     */
    public static function cleanupExpired(): int
    {
        try {
            return static::where('expires_at', '<', now())->delete();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - cleanupExpired() method error: ' . $e->getMessage());
            return 0;
        }
    }
}
