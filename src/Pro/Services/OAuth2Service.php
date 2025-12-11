<?php

/**
 * Copyright EXOR Group Ltd 2025
 * Version 1.0.0.0
 * APEX Pro Laravel Autentica Authentication System
 * Description: Service class for OAuth2 social authentication management supporting Google, Microsoft, and other providers with token management
 * File Location: apex/autentica/src/Pro/Services/OAuth2Service.php
 */

namespace Apex\Autentica\Pro\Services;

use App\Models\User;
use Apex\Autentica\Pro\Models\SocialAccount;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class OAuth2Service
{
    /**
     * Supported OAuth2 providers configuration
     */
    private const PROVIDERS = [
        'google' => [
            'auth_url' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url' => 'https://oauth2.googleapis.com/token',
            'user_url' => 'https://www.googleapis.com/oauth2/v2/userinfo',
            'scopes' => ['email', 'profile'],
        ],
        'microsoft' => [
            'auth_url' => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token_url' => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'user_url' => 'https://graph.microsoft.com/v1.0/me',
            'scopes' => ['User.Read'],
        ],
    ];

    /**
     * Generate OAuth2 authorization URL for a provider.
     *
     * @param string $provider
     * @param string $redirectUri
     * @param array $additionalScopes
     * @return array
     * @throws \Exception
     */
    public function generateAuthUrl(string $provider, string $redirectUri, array $additionalScopes = []): array
    {
        try {
            if (!isset(self::PROVIDERS[$provider])) {
                throw new \InvalidArgumentException("Unsupported OAuth2 provider: {$provider}");
            }

            $config = self::PROVIDERS[$provider];
            $clientId = config("services.{$provider}.client_id");

            if (!$clientId) {
                throw new \RuntimeException("OAuth2 client ID not configured for provider: {$provider}");
            }

            $state = Str::random(40);
            $scopes = array_merge($config['scopes'], $additionalScopes);

            $params = [
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'scope' => implode(' ', $scopes),
                'response_type' => 'code',
                'state' => $state,
            ];

            // Provider-specific parameters
            if ($provider === 'microsoft') {
                $params['response_mode'] = 'query';
            }

            $authUrl = $config['auth_url'] . '?' . http_build_query($params);

            Log::info('OAuth2 authorization URL generated', [
                'file' => 'OAuth2Service.php',
                'method' => 'generateAuthUrl',
                'provider' => $provider,
                'state' => $state
            ]);

            return [
                'auth_url' => $authUrl,
                'state' => $state
            ];
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - generateAuthUrl() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'generateAuthUrl',
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Exchange authorization code for access token.
     *
     * @param string $provider
     * @param string $code
     * @param string $redirectUri
     * @return array
     * @throws \Exception
     */
    public function exchangeCodeForToken(string $provider, string $code, string $redirectUri): array
    {
        try {
            if (!isset(self::PROVIDERS[$provider])) {
                throw new \InvalidArgumentException("Unsupported OAuth2 provider: {$provider}");
            }

            $config = self::PROVIDERS[$provider];
            $clientId = config("services.{$provider}.client_id");
            $clientSecret = config("services.{$provider}.client_secret");

            if (!$clientId || !$clientSecret) {
                throw new \RuntimeException("OAuth2 credentials not configured for provider: {$provider}");
            }

            $response = Http::asForm()->post($config['token_url'], [
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $redirectUri,
            ]);

            if (!$response->successful()) {
                throw new \RuntimeException("Failed to exchange code for token: " . $response->body());
            }

            $tokenData = $response->json();

            Log::info('OAuth2 code exchanged for token', [
                'file' => 'OAuth2Service.php',
                'method' => 'exchangeCodeForToken',
                'provider' => $provider,
                'expires_in' => $tokenData['expires_in'] ?? 'unknown'
            ]);

            return $tokenData;
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - exchangeCodeForToken() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'exchangeCodeForToken',
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get user information from OAuth2 provider.
     *
     * @param string $provider
     * @param string $accessToken
     * @return array
     * @throws \Exception
     */
    public function getUserInfo(string $provider, string $accessToken): array
    {
        try {
            if (!isset(self::PROVIDERS[$provider])) {
                throw new \InvalidArgumentException("Unsupported OAuth2 provider: {$provider}");
            }

            $config = self::PROVIDERS[$provider];

            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $accessToken,
                'Accept' => 'application/json',
            ])->get($config['user_url']);

            if (!$response->successful()) {
                throw new \RuntimeException("Failed to get user info: " . $response->body());
            }

            $userData = $response->json();

            // Normalize user data across providers
            $normalizedData = $this->normalizeUserData($provider, $userData);

            Log::info('OAuth2 user info retrieved', [
                'file' => 'OAuth2Service.php',
                'method' => 'getUserInfo',
                'provider' => $provider,
                'user_id' => $normalizedData['id']
            ]);

            return $normalizedData;
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - getUserInfo() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'getUserInfo',
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Link social account to user.
     *
     * @param User $user
     * @param string $provider
     * @param array $tokenData
     * @param array $userData
     * @return SocialAccount
     * @throws \Exception
     */
    public function linkSocialAccount(User $user, string $provider, array $tokenData, array $userData): SocialAccount
    {
        try {
            $expiresAt = null;
            if (isset($tokenData['expires_in'])) {
                $expiresAt = now()->addSeconds((int)$tokenData['expires_in']);
            }

            $socialAccount = SocialAccount::updateOrCreate(
                [
                    'user_id' => $user->id,
                    'provider' => $provider,
                ],
                [
                    'provider_user_id' => $userData['id'],
                    'access_token' => isset($tokenData['access_token']) ? Crypt::encryptString($tokenData['access_token']) : null,
                    'refresh_token' => isset($tokenData['refresh_token']) ? Crypt::encryptString($tokenData['refresh_token']) : null,
                    'expires_at' => $expiresAt,
                ]
            );

            Log::info('Social account linked to user', [
                'file' => 'OAuth2Service.php',
                'method' => 'linkSocialAccount',
                'user_id' => $user->id,
                'provider' => $provider,
                'social_account_id' => $socialAccount->id
            ]);

            return $socialAccount;
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - linkSocialAccount() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'linkSocialAccount',
                'user_id' => $user->id,
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Unlink social account from user.
     *
     * @param User $user
     * @param string $provider
     * @return bool
     * @throws \Exception
     */
    public function unlinkSocialAccount(User $user, string $provider): bool
    {
        try {
            $deleted = SocialAccount::where('user_id', $user->id)
                ->where('provider', $provider)
                ->delete();

            Log::info('Social account unlinked from user', [
                'file' => 'OAuth2Service.php',
                'method' => 'unlinkSocialAccount',
                'user_id' => $user->id,
                'provider' => $provider,
                'records_deleted' => $deleted
            ]);

            return $deleted > 0;
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - unlinkSocialAccount() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'unlinkSocialAccount',
                'user_id' => $user->id,
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Refresh access token using refresh token.
     *
     * @param SocialAccount $socialAccount
     * @return bool
     * @throws \Exception
     */
    public function refreshAccessToken(SocialAccount $socialAccount): bool
    {
        try {
            if (!$socialAccount->refresh_token) {
                Log::warning('No refresh token available for social account', [
                    'file' => 'OAuth2Service.php',
                    'method' => 'refreshAccessToken',
                    'social_account_id' => $socialAccount->id
                ]);
                return false;
            }

            $provider = $socialAccount->provider;
            if (!isset(self::PROVIDERS[$provider])) {
                throw new \InvalidArgumentException("Unsupported OAuth2 provider: {$provider}");
            }

            $config = self::PROVIDERS[$provider];
            $clientId = config("services.{$provider}.client_id");
            $clientSecret = config("services.{$provider}.client_secret");

            $refreshToken = Crypt::decryptString($socialAccount->refresh_token);

            $response = Http::asForm()->post($config['token_url'], [
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token',
            ]);

            if (!$response->successful()) {
                throw new \RuntimeException("Failed to refresh access token: " . $response->body());
            }

            $tokenData = $response->json();

            $expiresAt = null;
            if (isset($tokenData['expires_in'])) {
                $expiresAt = now()->addSeconds((int)$tokenData['expires_in']);
            }

            $socialAccount->update([
                'access_token' => Crypt::encryptString($tokenData['access_token']),
                'expires_at' => $expiresAt,
            ]);

            Log::info('Access token refreshed successfully', [
                'file' => 'OAuth2Service.php',
                'method' => 'refreshAccessToken',
                'social_account_id' => $socialAccount->id
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - refreshAccessToken() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'refreshAccessToken',
                'social_account_id' => $socialAccount->id ?? 'unknown',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Get linked social accounts for a user.
     *
     * @param User $user
     * @return \Illuminate\Database\Eloquent\Collection
     * @throws \Exception
     */
    public function getLinkedAccounts(User $user): \Illuminate\Database\Eloquent\Collection
    {
        try {
            return SocialAccount::where('user_id', $user->id)->get();
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - getLinkedAccounts() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'getLinkedAccounts',
                'user_id' => $user->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    /**
     * Check if a provider is supported.
     *
     * @param string $provider
     * @return bool
     */
    public function isProviderSupported(string $provider): bool
    {
        return isset(self::PROVIDERS[$provider]);
    }

    /**
     * Normalize user data from different providers.
     *
     * @param string $provider
     * @param array $userData
     * @return array
     * @throws \Exception
     */
    private function normalizeUserData(string $provider, array $userData): array
    {
        try {
            switch ($provider) {
                case 'google':
                    return [
                        'id' => $userData['id'],
                        'email' => $userData['email'] ?? null,
                        'name' => $userData['name'] ?? null,
                        'first_name' => $userData['given_name'] ?? null,
                        'last_name' => $userData['family_name'] ?? null,
                        'avatar' => $userData['picture'] ?? null,
                    ];

                case 'microsoft':
                    return [
                        'id' => $userData['id'],
                        'email' => $userData['mail'] ?? $userData['userPrincipalName'] ?? null,
                        'name' => $userData['displayName'] ?? null,
                        'first_name' => $userData['givenName'] ?? null,
                        'last_name' => $userData['surname'] ?? null,
                        'avatar' => null, // Microsoft Graph doesn't provide avatar URL directly
                    ];

                default:
                    return $userData;
            }
        } catch (\Exception $e) {
            Log::error('OAuth2Service.php - normalizeUserData() method error: ' . $e->getMessage(), [
                'file' => 'OAuth2Service.php',
                'method' => 'normalizeUserData',
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }
}
