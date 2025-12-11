<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for MFA configurations including TOTP, SMS, and email authentication methods with encrypted secret storage
 * File Location: apex/autentica/src/Pro/Models/MfaConfig.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Traits\Signable;

class MfaConfig extends Model
{
    use SoftDeletes, Signable;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'au10_mfa_configs';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id',
        'method',
        'secret',
        'phone',
        'verified_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'secret',
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
            'verified_at' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    /**
     * Valid MFA methods
     */
    const VALID_METHODS = ['totp', 'sms', 'email'];

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

            Log::info('MfaConfig model booted successfully', [
                'file' => 'MfaConfig.php',
                'method' => 'boot'
            ]);
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - boot() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'boot',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the user that owns the MFA configuration.
     *
     * @return BelongsTo
     * @throws \Exception
     */
    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - user() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'user',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include verified MFA configurations.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeVerified($query)
    {
        try {
            return $query->whereNotNull('verified_at');
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - scopeVerified() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'scopeVerified',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to only include unverified MFA configurations.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeUnverified($query)
    {
        try {
            return $query->whereNull('verified_at');
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - scopeUnverified() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'scopeUnverified',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Scope query to filter by MFA method.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string $method
     * @return \Illuminate\Database\Eloquent\Builder
     * @throws \Exception
     */
    public function scopeByMethod($query, string $method)
    {
        try {
            return $query->where('method', $method);
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - scopeByMethod() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'scopeByMethod',
                'mfa_method' => $method,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the MFA configuration is verified.
     *
     * @return bool
     * @throws \Exception
     */
    public function isVerified(): bool
    {
        try {
            return !is_null($this->verified_at);
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - isVerified() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'isVerified',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Mark the MFA configuration as verified.
     *
     * @return bool
     * @throws \Exception
     */
    public function markAsVerified(): bool
    {
        try {
            $result = $this->update(['verified_at' => now()]);

            Log::info('MFA configuration marked as verified', [
                'file' => 'MfaConfig.php',
                'method' => 'markAsVerified',
                'model_id' => $this->id,
                'user_id' => $this->user_id,
                'mfa_method' => $this->method
            ]);

            return $result;
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - markAsVerified() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'markAsVerified',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if the MFA method is valid.
     *
     * @param string $method
     * @return bool
     */
    public static function isValidMethod(string $method): bool
    {
        return in_array($method, self::VALID_METHODS);
    }

    /**
     * Get all valid MFA methods.
     *
     * @return array
     */
    public static function getValidMethods(): array
    {
        return self::VALID_METHODS;
    }

    /**
     * Validate the method attribute.
     *
     * @param string $value
     * @return void
     * @throws \Exception
     */
    public function setMethodAttribute(string $value): void
    {
        try {
            if (!self::isValidMethod($value)) {
                throw new \InvalidArgumentException("Invalid MFA method: {$value}");
            }

            $this->attributes['method'] = $value;
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - setMethodAttribute() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'setMethodAttribute',
                'mfa_method' => $value,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the method display name.
     *
     * @return string
     * @throws \Exception
     */
    public function getMethodDisplayName(): string
    {
        try {
            $displayNames = [
                'totp' => 'Authenticator App',
                'sms' => 'SMS Text Message',
                'email' => 'Email Verification',
            ];

            return $displayNames[$this->method] ?? ucfirst($this->method);
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - getMethodDisplayName() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'getMethodDisplayName',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get the verification status display.
     *
     * @return string
     * @throws \Exception
     */
    public function getVerificationStatus(): string
    {
        try {
            return $this->isVerified() ? 'Verified' : 'Pending Verification';
        } catch (\Exception $e) {
            Log::error('MfaConfig.php - getVerificationStatus() method error: ' . $e->getMessage(), [
                'file' => 'MfaConfig.php',
                'method' => 'getVerificationStatus',
                'model_id' => $this->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
