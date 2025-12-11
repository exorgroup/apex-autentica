<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for social authentication accounts (Google, Microsoft, etc.) with encrypted token storage and provider management
 * File Location: apex/autentica/src/Pro/Models/SocialAccount.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Crypt;
use Apex\Autentica\Core\Traits\Signable;

class SocialAccount extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_social_accounts';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'provider',
        'provider_user_id',
        'access_token',
        'refresh_token',
        'expires_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'access_token',
        'refresh_token',
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
            'expires_at' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    /**
     * Supported OAuth2 providers
     */
    const SUPPORTED_PROVIDERS = ['google', 'microsoft', 'github', 'facebook', 'twitter'];

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

            Log::info('SocialAccount model booted successfully', [
                'file' => 'SocialAccount.php',
                'method' => 'boot'
            ]);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - boot() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'boot',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the user that owns the social account.
     *
     * @return BelongsTo
     * @throws \Exception
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - user() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'user',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to filter by provider.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $provider
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeByProvider($query, string $provider)
    {
        try {
            return $query->where('provider', $provider);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - scopeByProvider() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'scopeByProvider',
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include accounts with valid (non-expired) tokens.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeWithValidTokens($query)
    {
        try {
            return $query->where(function ($q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - scopeWithValidTokens() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'scopeWithValidTokens',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include accounts with expired tokens.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeWithExpiredTokens($query)
    {
        try {
            return $query->whereNotNull('expires_at')
                ->where('expires_at', '<=', now());
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - scopeWithExpiredTokens() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'scopeWithExpiredTokens',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the decrypted access token.
     *
     * @return string|null
     * @throws \Exception
     */
    public function getDecryptedAccessToken(): ?string
    {
        try {
            if (!$this->access_token) {
                return null;
            }

            return Crypt::decryptString($this->access_token);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - getDecryptedAccessToken() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'getDecryptedAccessToken',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the decrypted refresh token.
     *
     * @return string|null
     * @throws \Exception
     */
    public function getDecryptedRefreshToken(): ?string
    {
        try {
            if (!$this->refresh_token) {
                return null;
            }

            return Crypt::decryptString($this->refresh_token);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - getDecryptedRefreshToken() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'getDecryptedRefreshToken',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the access token is expired.
     *
     * @return bool
     * @throws \Exception
     */
    public function isTokenExpired(): bool
    {
        try {
            if (!$this->expires_at) {
                return false; // No expiration set, consider it valid
            }

            return $this->expires_at->isPast();
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - isTokenExpired() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'isTokenExpired',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the access token will expire soon.
     *
     * @param int $minutes Minutes before expiration to consider "soon"
     * @return bool
     * @throws \Exception
     */
    public function isTokenExpiringSoon(int $minutes = 30): bool
    {
        try {
            if (!$this->expires_at) {
                return false; // No expiration set
            }

            return $this->expires_at->subMinutes($minutes)->isPast();
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - isTokenExpiringSoon() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'isTokenExpiringSoon',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'minutes' => $minutes,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the provider is supported.
     *
     * @param string $provider
     * @return bool
     */
    public static function isProviderSupported(string $provider): bool
    {
        return in_array($provider, self::SUPPORTED_PROVIDERS);
    }

    /**
     * Get all supported providers.
     *
     * @return array
     */
    public static function getSupportedProviders(): array
    {
        return self::SUPPORTED_PROVIDERS;
    }

    /**
     * Validate the provider attribute.
     *
     * @param string $value
     * @return void
     * @throws \Exception
     */
    public function setProviderAttribute(string $value): void
    {
        try {
            if (!self::isProviderSupported($value)) {
                throw new \InvalidArgumentException("Unsupported OAuth2 provider: {$value}");
            }

            $this->attributes['provider'] = $value;
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - setProviderAttribute() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'setProviderAttribute',
                'provider' => $value,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the provider display name.
     *
     * @return string
     * @throws \Exception
     */
    public function getProviderDisplayName(): string
    {
        try {
            $displayNames = [
                'google' => 'Google',
                'microsoft' => 'Microsoft',
                'github' => 'GitHub',
                'facebook' => 'Facebook',
                'twitter' => 'Twitter',
            ];

            return $displayNames[$this->provider] ?? ucfirst($this->provider);
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - getProviderDisplayName() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'getProviderDisplayName',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
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
    public function getTokenStatus(): string
    {
        try {
            if (!$this->access_token) {
                return 'No Token';
            }

            if ($this->isTokenExpired()) {
                return 'Expired';
            }

            if ($this->isTokenExpiringSoon()) {
                return 'Expiring Soon';
            }

            return 'Valid';
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - getTokenStatus() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'getTokenStatus',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Update token information.
     *
     * @param string $accessToken
     * @param string|null $refreshToken
     * @param \DateTime|null $expiresAt
     * @return bool
     * @throws \Exception
     */
    public function updateTokens(string $accessToken, ?string $refreshToken = null, ?\DateTime $expiresAt = null): bool
    {
        try {
            $updateData = [
                'access_token' => Crypt::encryptString($accessToken),
                'expires_at' => $expiresAt,
            ];

            if ($refreshToken !== null) {
                $updateData['refresh_token'] = Crypt::encryptString($refreshToken);
            }

            $result = $this->update($updateData);

            Log::info('Social account tokens updated', [
                'file' => 'SocialAccount.php',
                'method' => 'updateTokens',
                'model_id' => $this->id,
                'user_id' => $this->user_id,
                'provider' => $this->provider,
                'expires_at' => $expiresAt?->format('Y-m-d H:i:s')
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('SocialAccount.php - updateTokens() method error: ' . $e->getMessage(), [
                'file' => 'SocialAccount.php',
                'method' => 'updateTokens',
                'model_id' => $this->id ?? 'unknown',
                'provider' => $this->provider ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
