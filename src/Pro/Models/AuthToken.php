<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Pro extensions to the Core AuthToken model — query scopes, statistics and
 *              display helpers for remember, API and session tokens.
 * File Location: exorgroup/apex-autentica/src/Pro/Models/AuthToken.php
 */

namespace Apex\Autentica\Pro\Models;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Models\AuthToken as CoreAuthToken;

/**
 * Both Core and Pro previously declared their own AuthToken model against the same
 * au10_auth_tokens table, each with its own fillable, casts and relations that could drift
 * apart. Pro now extends Core: the table, fillable, casts, signing and the user relation are
 * defined once in Core, and Pro adds only what Pro needs.
 *
 * Extending Core (rather than Core referencing Pro) keeps the dependency pointing the right
 * way, so src/Pro can be lifted into its own package without touching Core.
 */
class AuthToken extends CoreAuthToken
{
    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'token',
        'signature',
    ];

    /**
     * Valid token types
     */
    const VALID_TYPES = ['remember', 'api', 'session'];

    /**
     * Scope query to filter by token type.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $type
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeByType($query, string $type)
    {
        try {
            return $query->where('type', $type);
        } catch (\Exception $e) {
            Log::error('AuthToken.php - scopeByType() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'scopeByType',
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include valid (non-expired) tokens.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeValid($query)
    {
        try {
            return $query->where(function ($q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
        } catch (\Exception $e) {
            Log::error('AuthToken.php - scopeValid() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'scopeValid',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include expired tokens.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeExpired($query)
    {
        try {
            return $query->whereNotNull('expires_at')
                ->where('expires_at', '<=', now());
        } catch (\Exception $e) {
            Log::error('AuthToken.php - scopeExpired() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'scopeExpired',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include tokens expiring soon.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param int $minutes Minutes before expiration
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeExpiringSoon($query, int $minutes = 60)
    {
        try {
            $threshold = now()->addMinutes($minutes);

            return $query->whereNotNull('expires_at')
                ->where('expires_at', '>', now())
                ->where('expires_at', '<=', $threshold);
        } catch (\Exception $e) {
            Log::error('AuthToken.php - scopeExpiringSoon() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'scopeExpiringSoon',
                'minutes' => $minutes,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the token is expired.
     *
     * @return bool
     * @throws \Exception
     */
    public function isExpired(): bool
    {
        try {
            if (!$this->expires_at) {
                return false; // No expiration set, consider it valid
            }

            return $this->expires_at->isPast();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - isExpired() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'isExpired',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the token is valid (not expired).
     *
     * @return bool
     * @throws \Exception
     */
    public function isValid(): bool
    {
        try {
            return !$this->isExpired();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - isValid() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'isValid',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the token will expire soon.
     *
     * @param int $minutes Minutes before expiration to consider "soon"
     * @return bool
     * @throws \Exception
     */
    public function isExpiringSoon(int $minutes = 60): bool
    {
        try {
            if (!$this->expires_at) {
                return false; // No expiration set
            }

            if ($this->isExpired()) {
                return false; // Already expired
            }

            return $this->expires_at->subMinutes($minutes)->isPast();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - isExpiringSoon() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'isExpiringSoon',
                'model_id' => $this->id ?? 'unknown',
                'minutes' => $minutes,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update the token's last used timestamp.
     *
     * @return bool
     * @throws \Exception
     */
    public function updateLastUsed(): bool
    {
        try {
            $result = $this->update(['last_used_at' => now()]);

            Log::info('Auth token last used timestamp updated', [
                'file' => 'AuthToken.php',
                'method' => 'updateLastUsed',
                'model_id' => $this->id,
                'user_id' => $this->user_id,
                'type' => $this->type
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - updateLastUsed() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'updateLastUsed',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Extend the token's expiration time.
     *
     * @param int $additionalHours Hours to add to expiration
     * @return bool
     * @throws \Exception
     */
    public function extendExpiration(int $additionalHours): bool
    {
        try {
            $newExpiration = ($this->expires_at ?? now())->addHours($additionalHours);

            $result = $this->update(['expires_at' => $newExpiration]);

            Log::info('Auth token expiration extended', [
                'file' => 'AuthToken.php',
                'method' => 'extendExpiration',
                'model_id' => $this->id,
                'user_id' => $this->user_id,
                'type' => $this->type,
                'additional_hours' => $additionalHours,
                'new_expiration' => $newExpiration
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - extendExpiration() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'extendExpiration',
                'model_id' => $this->id ?? 'unknown',
                'additional_hours' => $additionalHours,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the token status display.
     *
     * @return string
     * @throws \Exception
     */
    public function getStatus(): string
    {
        try {
            if ($this->isExpired()) {
                return 'Expired';
            }

            if ($this->isExpiringSoon(60)) {
                return 'Expiring Soon';
            }

            return 'Valid';
        } catch (\Exception $e) {
            Log::error('AuthToken.php - getStatus() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'getStatus',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the token type display name.
     *
     * @return string
     * @throws \Exception
     */
    public function getTypeDisplayName(): string
    {
        try {
            $displayNames = [
                'remember' => 'Remember Me',
                'api' => 'API Token',
                'session' => 'Session Token',
            ];

            return $displayNames[$this->type] ?? ucfirst($this->type);
        } catch (\Exception $e) {
            Log::error('AuthToken.php - getTypeDisplayName() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'getTypeDisplayName',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the expiration display.
     *
     * @return string
     * @throws \Exception
     */
    public function getExpirationDisplay(): string
    {
        try {
            if (!$this->expires_at) {
                return 'Never';
            }

            if ($this->isExpired()) {
                return 'Expired ' . $this->expires_at->diffForHumans();
            }

            return 'Expires ' . $this->expires_at->diffForHumans();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - getExpirationDisplay() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'getExpirationDisplay',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the last used display.
     *
     * @return string
     * @throws \Exception
     */
    public function getLastUsedDisplay(): string
    {
        try {
            if (!$this->last_used_at) {
                return 'Never';
            }

            return $this->last_used_at->diffForHumans();
        } catch (\Exception $e) {
            Log::error('AuthToken.php - getLastUsedDisplay() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'getLastUsedDisplay',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the token type is valid.
     *
     * @param string $type
     * @return bool
     */
    public static function isValidType(string $type): bool
    {
        return in_array($type, self::VALID_TYPES);
    }

    /**
     * Get all valid token types.
     *
     * @return array
     */
    public static function getValidTypes(): array
    {
        return self::VALID_TYPES;
    }

    /**
     * Validate the type attribute.
     *
     * @param string $value
     * @return void
     * @throws \Exception
     */
    public function setTypeAttribute(string $value): void
    {
        try {
            if (!self::isValidType($value)) {
                throw new \InvalidArgumentException("Invalid token type: {$value}");
            }

            $this->attributes['type'] = $value;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - setTypeAttribute() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'setTypeAttribute',
                'type' => $value,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get token statistics for a user.
     *
     * @param User $user
     * @return array
     * @throws \Exception
     */
    public static function getStatsForUser(User $user): array
    {
        try {
            $totalTokens = self::where('user_id', $user->id)->count();
            $validTokens = self::where('user_id', $user->id)->valid()->count();
            $expiredTokens = $totalTokens - $validTokens;

            $tokensByType = self::where('user_id', $user->id)
                ->selectRaw('type, count(*) as count')
                ->groupBy('type')
                ->pluck('count', 'type')
                ->toArray();

            $lastTokenCreated = self::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $stats = [
                'total_tokens' => $totalTokens,
                'valid_tokens' => $validTokens,
                'expired_tokens' => $expiredTokens,
                'by_type' => $tokensByType,
                'last_token_created' => $lastTokenCreated,
                'has_tokens' => $totalTokens > 0,
            ];

            Log::info('Auth token statistics retrieved for user', [
                'file' => 'AuthToken.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - getStatsForUser() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'getStatsForUser',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Clean up expired tokens.
     *
     * @return int Number of tokens cleaned up
     * @throws \Exception
     */
    public static function cleanupExpired(): int
    {
        try {
            $deleted = self::expired()->delete();

            Log::info('Expired auth tokens cleaned up', [
                'file' => 'AuthToken.php',
                'method' => 'cleanupExpired',
                'tokens_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('AuthToken.php - cleanupExpired() method error: ' . $e->getMessage(), [
                'file' => 'AuthToken.php',
                'method' => 'cleanupExpired',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
