<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Model for authentication method configurations with flexible JSON config storage
 * File Location: apex/autentica/src/Pro/Models/AuthMethod.php
 */

namespace Apex\Autentica\Pro\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;
use Apex\Autentica\Core\Traits\Signable;

class AuthMethod extends Model
{
    use SoftDeletes, Signable;

    protected $table = 'au10_auth_methods';

    protected $fillable = [
        'user_id',
        'method',
        'enabled',
        'config',
        'last_used_at',
    ];

    protected $hidden = ['signature'];

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'config' => 'array',
            'last_used_at' => 'datetime',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }

    const VALID_METHODS = ['password', 'totp', 'sms', 'email', 'social'];

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
            Log::error('AuthMethod.php - boot() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function user(): BelongsTo
    {
        try {
            return $this->belongsTo(User::class);
        } catch (\Exception $e) {
            Log::error('AuthMethod.php - user() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeEnabled($query)
    {
        try {
            return $query->where('enabled', true);
        } catch (\Exception $e) {
            Log::error('AuthMethod.php - scopeEnabled() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function scopeByMethod($query, string $method)
    {
        try {
            return $query->where('method', $method);
        } catch (\Exception $e) {
            Log::error('AuthMethod.php - scopeByMethod() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    public static function isValidMethod(string $method): bool
    {
        return in_array($method, self::VALID_METHODS);
    }

    public function setMethodAttribute(string $value): void
    {
        try {
            if (!self::isValidMethod($value)) {
                throw new \InvalidArgumentException("Invalid auth method: {$value}");
            }
            $this->attributes['method'] = $value;
        } catch (\Exception $e) {
            Log::error('AuthMethod.php - setMethodAttribute() method error: ' . $e->getMessage());
            throw $e;
        }
    }
}
