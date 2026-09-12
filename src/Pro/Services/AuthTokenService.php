<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Licence: Commercial — Autentica Pro. NOT MIT. See LICENSE-PRO in the package root.
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for authentication token management including remember tokens, API tokens, and session tokens with security monitoring
 * File Location: exorgroup/apex-autentica/src/Pro/Services/AuthTokenService.php
 */

namespace Apex\Autentica\Pro\Services;

use Illuminate\Foundation\Auth\User;
use Apex\Autentica\Pro\Models\AuthToken;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthTokenService
{
    /**
     * Token types
     */
    private const TOKEN_TYPES = ['remember', 'api', 'session'];

    /**
     * Separates the row id from the secret in an issued token.
     */
    private const TOKEN_SEPARATOR = '|';

    /**
     * A real bcrypt hash of a fixed string, used only to spend the same time on a failed
     * lookup as on a successful one. Never matches a token: the value it hashes is not a
     * token, and tokens are 64 random characters.
     */
    private const TIMING_EQUALISER = '$2y$12$VE.GemA56Osg1U.ljvfJsuxzYBD6mhGz9VkOPsNdlTLk.kJMTT5B6';

    /**
     * Split an issued token into its row id and secret.
     *
     * Returns [null, null] for anything malformed, so a junk token costs no database query.
     *
     * @param string $plainToken
     * @return array{0: int|null, 1: string|null}
     */
    protected function splitToken(string $plainToken): array
    {
        $parts = explode(self::TOKEN_SEPARATOR, $plainToken, 2);

        if (count($parts) !== 2) {
            return [null, null];
        }

        [$id, $secret] = $parts;

        // ctype_digit rejects negatives, decimals, whitespace and the empty string.
        if (! ctype_digit($id) || $secret === '') {
            return [null, null];
        }

        return [(int) $id, $secret];
    }

    /**
     * Get token configuration values
     *
     * @return array
     */
    private function getTokenConfig(): array
    {
        return [
            'remember_expires_hours' => config('autentica_pro.tokens.remember_expires_hours', 8760), // 1 year
            'api_expires_hours' => config('autentica_pro.tokens.api_expires_hours', 8760), // 1 year
            'session_expires_hours' => config('autentica_pro.tokens.session_expires_hours', 24), // 1 day
        ];
    }

    /**
     * Create a new authentication token.
     *
     * @param User $user
     * @param string $type
     * @param int|null $expiresInHours
     * @param array $metadata
     * @return array
     * @throws \Exception
     */
    public function createToken(User $user, string $type, ?int $expiresInHours = null, array $metadata = []): array
    {
        try {
            if (!in_array($type, self::TOKEN_TYPES)) {
                throw new \InvalidArgumentException("Invalid token type: {$type}");
            }

            // Only the secret half is hashed. The row id travels in the token so verification
            // is a single indexed lookup instead of a scan - see verifyToken().
            $secret = Str::random(64);
            $hashedToken = Hash::make($secret);

            // Calculate expiration
            $config = $this->getTokenConfig();
            $defaultExpiration = $config["{$type}_expires_hours"] ?? 24;
            $expiresInHours = $expiresInHours ?? $defaultExpiration;
            $expiresAt = $expiresInHours ? now()->addHours($expiresInHours) : null;

            // Create token record
            $authToken = AuthToken::create([
                'user_id' => $user->id,
                'token' => $hashedToken,
                'type' => $type,
                'expires_at' => $expiresAt,
                'last_used_at' => now(),
            ]);

            Log::info('Authentication token created', [
                'file' => 'AuthTokenService.php',
                'method' => 'createToken',
                'user_id' => $user->id,
                'token_id' => $authToken->id,
                'type' => $type,
                'expires_at' => $expiresAt
            ]);

            return [
                // Format: "{id}|{secret}". The id is not secret - it is a lookup key.
                'token' => $authToken->id . self::TOKEN_SEPARATOR . $secret,
                'token_id' => $authToken->id,
                'expires_at' => $expiresAt,
            ];
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - createToken() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'createToken',
                'user_id' => $user->id,
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Verify and retrieve user by token.
     *
     * @param string $plainToken
     * @param string $type
     * @param bool $updateLastUsed
     * @return User|null
     * @throws \Exception
     */
    public function verifyToken(string $plainToken, string $type, bool $updateLastUsed = true): ?User
    {
        try {
            // The token carries its own row id, so this is one indexed lookup and exactly one
            // hash comparison - never a scan over every live token.
            [$id, $secret] = $this->splitToken($plainToken);

            $token = $id === null ? null : AuthToken::find($id);

            // Wrong id, missing row, or wrong type: burn an equivalent hash comparison before
            // answering, so response time cannot be used to enumerate valid token ids.
            if (! $token || $token->type !== $type) {
                Hash::check($secret ?? '', self::TIMING_EQUALISER);

                Log::warning('Token verification failed', [
                    'file' => 'AuthTokenService.php',
                    'method' => 'verifyToken',
                    'type' => $type
                ]);

                return null;
            }

            if (Hash::check($secret, $token->token) && ! $token->isExpired()) {
                if ($updateLastUsed) {
                    $token->update(['last_used_at' => now()]);
                }

                Log::info('Token verified successfully', [
                    'file' => 'AuthTokenService.php',
                    'method' => 'verifyToken',
                    'user_id' => $token->user_id,
                    'token_id' => $token->id,
                    'type' => $type
                ]);

                return $token->user;
            }

            Log::warning('Token verification failed', [
                'file' => 'AuthTokenService.php',
                'method' => 'verifyToken',
                'type' => $type
            ]);

            return null;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - verifyToken() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'verifyToken',
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Revoke a specific token.
     *
     * @param User $user
     * @param int $tokenId
     * @return bool
     * @throws \Exception
     */
    public function revokeToken(User $user, int $tokenId): bool
    {
        try {
            $deleted = AuthToken::where('id', $tokenId)
                ->where('user_id', $user->id)
                ->delete();

            Log::info('Token revoked', [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeToken',
                'user_id' => $user->id,
                'token_id' => $tokenId,
                'deleted' => $deleted > 0
            ]);

            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - revokeToken() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeToken',
                'user_id' => $user->id,
                'token_id' => $tokenId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Revoke tokens by plain token value.
     *
     * @param string $plainToken
     * @param string|null $type
     * @return bool
     * @throws \Exception
     */
    public function revokeTokenByValue(string $plainToken, ?string $type = null): bool
    {
        try {
            $query = AuthToken::query();

            if ($type) {
                $query->where('type', $type);
            }

            $tokens = $query->get();
            $revoked = false;

            foreach ($tokens as $token) {
                if (Hash::check($plainToken, $token->token)) {
                    $token->delete();
                    $revoked = true;

                    Log::info('Token revoked by value', [
                        'file' => 'AuthTokenService.php',
                        'method' => 'revokeTokenByValue',
                        'token_id' => $token->id,
                        'type' => $token->type,
                        'user_id' => $token->user_id
                    ]);
                    break;
                }
            }

            return $revoked;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - revokeTokenByValue() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeTokenByValue',
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Revoke all tokens of a specific type for a user.
     *
     * @param User $user
     * @param string $type
     * @return int Number of tokens revoked
     * @throws \Exception
     */
    public function revokeTokensByType(User $user, string $type): int
    {
        try {
            if (!in_array($type, self::TOKEN_TYPES)) {
                throw new \InvalidArgumentException("Invalid token type: {$type}");
            }

            $deleted = AuthToken::where('user_id', $user->id)
                ->where('type', $type)
                ->delete();

            Log::info('Tokens revoked by type', [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeTokensByType',
                'user_id' => $user->id,
                'type' => $type,
                'tokens_revoked' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - revokeTokensByType() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeTokensByType',
                'user_id' => $user->id,
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Revoke all tokens for a user.
     *
     * @param User $user
     * @return int Number of tokens revoked
     * @throws \Exception
     */
    public function revokeAllTokens(User $user): int
    {
        try {
            $deleted = AuthToken::where('user_id', $user->id)->delete();

            Log::info('All tokens revoked for user', [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeAllTokens',
                'user_id' => $user->id,
                'tokens_revoked' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - revokeAllTokens() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'revokeAllTokens',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get active tokens for a user.
     *
     * @param User $user
     * @param string|null $type
     * @return \Illuminate\Database\Eloquent\Collection
     * @throws \Exception
     */
    public function getActiveTokens(User $user, ?string $type = null): \Illuminate\Database\Eloquent\Collection
    {
        try {
            $query = AuthToken::where('user_id', $user->id)
                ->where(function ($q) {
                    $q->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                });

            if ($type) {
                $query->where('type', $type);
            }

            $tokens = $query->orderBy('last_used_at', 'desc')->get();

            Log::info('Active tokens retrieved', [
                'file' => 'AuthTokenService.php',
                'method' => 'getActiveTokens',
                'user_id' => $user->id,
                'type' => $type,
                'token_count' => $tokens->count()
            ]);

            return $tokens;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - getActiveTokens() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'getActiveTokens',
                'user_id' => $user->id,
                'type' => $type,
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
    public function cleanupExpiredTokens(): int
    {
        try {
            $deleted = AuthToken::where('expires_at', '<', now())->delete();

            Log::info('Expired tokens cleaned up', [
                'file' => 'AuthTokenService.php',
                'method' => 'cleanupExpiredTokens',
                'tokens_deleted' => $deleted
            ]);

            return $deleted;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - cleanupExpiredTokens() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'cleanupExpiredTokens',
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
    public function getTokenStats(User $user): array
    {
        try {
            $totalTokens = AuthToken::where('user_id', $user->id)->count();
            $activeTokens = AuthToken::where('user_id', $user->id)
                ->where(function ($q) {
                    $q->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                })
                ->count();

            $tokensByType = AuthToken::where('user_id', $user->id)
                ->selectRaw('type, count(*) as count')
                ->groupBy('type')
                ->pluck('count', 'type')
                ->toArray();

            $lastTokenCreated = AuthToken::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->value('created_at');

            $stats = [
                'total_tokens' => $totalTokens,
                'active_tokens' => $activeTokens,
                'expired_tokens' => $totalTokens - $activeTokens,
                'by_type' => $tokensByType,
                'last_token_created' => $lastTokenCreated,
            ];

            Log::info('Token statistics retrieved', [
                'file' => 'AuthTokenService.php',
                'method' => 'getTokenStats',
                'user_id' => $user->id,
                'stats' => $stats
            ]);

            return $stats;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - getTokenStats() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'getTokenStats',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Extend token expiration.
     *
     * @param User $user
     * @param int $tokenId
     * @param int $additionalHours
     * @return bool
     * @throws \Exception
     */
    public function extendTokenExpiration(User $user, int $tokenId, int $additionalHours): bool
    {
        try {
            $token = AuthToken::where('id', $tokenId)
                ->where('user_id', $user->id)
                ->first();

            if (!$token) {
                return false;
            }

            $newExpiration = ($token->expires_at ?? now())->addHours($additionalHours);

            $updated = $token->update(['expires_at' => $newExpiration]);

            Log::info('Token expiration extended', [
                'file' => 'AuthTokenService.php',
                'method' => 'extendTokenExpiration',
                'user_id' => $user->id,
                'token_id' => $tokenId,
                'additional_hours' => $additionalHours,
                'new_expiration' => $newExpiration
            ]);

            return $updated;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - extendTokenExpiration() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'extendTokenExpiration',
                'user_id' => $user->id,
                'token_id' => $tokenId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if token is expired.
     *
     * @param AuthToken $token
     * @return bool
     * @throws \Exception
     */
    public function isTokenExpired(AuthToken $token): bool
    {
        try {
            if (!$token->expires_at) {
                return false; // No expiration set
            }

            return $token->expires_at->isPast();
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - isTokenExpired() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'isTokenExpired',
                'token_id' => $token->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get supported token types.
     *
     * @return array
     */
    public function getSupportedTypes(): array
    {
        return self::TOKEN_TYPES;
    }

    /**
     * Get default expiration for token type.
     *
     * @param string $type
     * @return int|null Hours until expiration
     * @throws \Exception
     */
    public function getDefaultExpiration(string $type): ?int
    {
        try {
            if (!in_array($type, self::TOKEN_TYPES)) {
                throw new \InvalidArgumentException("Invalid token type: {$type}");
            }

            $config = $this->getTokenConfig();
            return $config["{$type}_expires_hours"] ?? null;
        } catch (\Exception $e) {
            Log::error('AuthTokenService.php - getDefaultExpiration() method error: ' . $e->getMessage(), [
                'file' => 'AuthTokenService.php',
                'method' => 'getDefaultExpiration',
                'type' => $type,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
