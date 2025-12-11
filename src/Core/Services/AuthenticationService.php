<?php

/**
 * Copyright EXOR Group ltd 2025
 * Version 1.0.0.0
 * APEX Laravel Autentica Authentication System
 * Description: Core authentication service handling login, logout, password management,
 *              session management, and account security features.
 * URL: apex/autentica/src/Core/Services/AuthenticationService.php
 */

namespace Apex\Autentica\Core\Services;

use App\Models\User;
use Apex\Autentica\Core\Models\AuthToken;
use Apex\Autentica\Core\Models\PasswordHistory;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthenticationService
{
    /**
     * Attempt to authenticate a user.
     *
     * @param array $credentials
     * @param bool $remember
     * @return array
     */
    public function attempt(array $credentials, bool $remember = false): array
    {
        try {
            $email = $credentials['email'] ?? '';
            $password = $credentials['password'] ?? '';

            // Check if account exists
            $user = User::where('email', $email)->first();

            if (!$user) {
                User::logFailedLogin($email, ['reason' => 'user_not_found']);
                return [
                    'success' => false,
                    'message' => __('autentica::auth.failed'),
                ];
            }

            // Check if account is locked
            if ($user->isAccountLocked()) {
                $unlockTime = $user->getUnlockTime();
                User::logFailedLogin($email, ['reason' => 'account_locked']);

                return [
                    'success' => false,
                    'message' => __('autentica::auth.locked', ['minutes' => $unlockTime]),
                    'locked_until' => $unlockTime,
                ];
            }

            // Attempt authentication
            if (!Auth::attempt(['email' => $email, 'password' => $password], $remember)) {
                User::logFailedLogin($email, ['reason' => 'invalid_password']);

                // Check if account is now locked
                if ($user->isAccountLocked()) {
                    $unlockTime = $user->getUnlockTime();
                    return [
                        'success' => false,
                        'message' => __('autentica::auth.locked', ['minutes' => $unlockTime]),
                        'locked_until' => $unlockTime,
                    ];
                }

                $remainingAttempts = config('auth.security.max_login_attempts', 5) - $user->getFailedLoginCount();

                return [
                    'success' => false,
                    'message' => __('autentica::auth.failed'),
                    'remaining_attempts' => max(0, $remainingAttempts),
                ];
            }

            // Successful login
            $user->logSuccessfulLogin(['remember' => $remember]);

            // Create remember token if requested
            if ($remember) {
                $this->createRememberToken($user);
            }

            // Check if password needs to be changed
            $passwordExpired = $this->isPasswordExpired($user);

            return [
                'success' => true,
                'user' => $user,
                'password_expired' => $passwordExpired,
                'message' => __('autentica::auth.login_success'),
            ];
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - attempt() method error: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => __('autentica::auth.error'),
            ];
        }
    }

    /**
     * Log out the authenticated user.
     *
     * @return bool
     */
    public function logout(): bool
    {
        try {
            $user = Auth::user();

            if ($user) {
                $user->logLogout();

                // Invalidate remember tokens
                AuthToken::where('user_id', $user->id)
                    ->where('type', 'remember')
                    ->delete();
            }

            Auth::logout();

            // Invalidate session
            request()->session()->invalidate();
            request()->session()->regenerateToken();

            return true;
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - logout() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Change user password.
     *
     * @param User $user
     * @param string $currentPassword
     * @param string $newPassword
     * @return array
     */
    public function changePassword(User $user, string $currentPassword, string $newPassword): array
    {
        try {
            // Verify current password
            if (!Hash::check($currentPassword, $user->password)) {
                return [
                    'success' => false,
                    'message' => __('auth.current_password_incorrect'),
                ];
            }

            // Validate new password
            $validation = $this->validatePassword($newPassword, $user);
            if (!$validation['valid']) {
                return [
                    'success' => false,
                    'message' => $validation['message'],
                    'errors' => $validation['errors'] ?? [],
                ];
            }

            // Check password history
            if (!$this->checkPasswordHistory($user, $newPassword)) {
                return [
                    'success' => false,
                    'message' => __('auth.password_used_recently'),
                ];
            }

            // Update password
            DB::transaction(function () use ($user, $newPassword) {
                // Save to history
                $this->addPasswordToHistory($user);

                // Update password
                $user->password = Hash::make($newPassword);
                $user->save();

                // Log event
                $user->logPasswordChange();
            });

            return [
                'success' => true,
                'message' => __('auth.password_changed'),
            ];
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - changePassword() method error: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => __('auth.error'),
            ];
        }
    }

    /**
     * Reset user password.
     *
     * @param User $user
     * @param string $newPassword
     * @return array
     */
    public function resetPassword(User $user, string $newPassword): array
    {
        try {
            // Validate new password
            $validation = $this->validatePassword($newPassword, $user);
            if (!$validation['valid']) {
                return [
                    'success' => false,
                    'message' => $validation['message'],
                    'errors' => $validation['errors'] ?? [],
                ];
            }

            // Check password history
            if (!$this->checkPasswordHistory($user, $newPassword)) {
                return [
                    'success' => false,
                    'message' => __('auth.password_used_recently'),
                ];
            }

            // Update password
            DB::transaction(function () use ($user, $newPassword) {
                // Save to history
                $this->addPasswordToHistory($user);

                // Update password
                $user->password = Hash::make($newPassword);
                $user->save();

                // Log event
                $user->logPasswordChange(['method' => 'reset']);
            });

            return [
                'success' => true,
                'message' => __('auth.password_reset_success'),
            ];
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - resetPassword() method error: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => __('auth.error'),
            ];
        }
    }

    /**
     * Validate password against configured policies.
     *
     * @param string $password
     * @param User|null $user
     * @return array
     */
    public function validatePassword(string $password, ?User $user = null): array
    {
        try {
            $errors = [];
            $policies = config('autentica.auth.password_policies', [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_special_chars' => false,
                'password_history_count' => 5,
                'password_expiry_days' => 0,
            ]);

            // Check minimum length
            if (strlen($password) < $policies['min_length']) {
                $errors[] = __('autentica::auth.password_min_length', ['length' => $policies['min_length']]);
            }

            // Check uppercase requirement
            if ($policies['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
                $errors[] = __('autentica::auth.password_require_uppercase');
            }

            // Check lowercase requirement
            if ($policies['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
                $errors[] = __('autentica::auth.password_require_lowercase');
            }

            // Check numbers requirement
            if ($policies['require_numbers'] && !preg_match('/[0-9]/', $password)) {
                $errors[] = __('autentica::auth.password_require_numbers');
            }

            // Check special characters requirement
            if ($policies['require_special_chars'] && !preg_match('/[^a-zA-Z0-9]/', $password)) {
                $errors[] = __('autentica::auth.password_require_special');
            }

            // Check if password contains user info
            if ($user) {
                $userInfo = [
                    strtolower($user->name),
                    strtolower($user->email),
                    explode('@', $user->email)[0],
                ];

                foreach ($userInfo as $info) {
                    if (stripos($password, $info) !== false) {
                        $errors[] = __('autentica::auth.password_contains_user_info');
                        break;
                    }
                }
            }

            return [
                'valid' => empty($errors),
                'errors' => $errors,
                'message' => empty($errors) ? __('autentica::auth.password_valid') : implode(' ', $errors),
            ];
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - validatePassword() method error: ' . $e->getMessage());
            return [
                'valid' => false,
                'errors' => [__('autentica::auth.error')],
                'message' => __('autentica::auth.error'),
            ];
        }
    }

    /**
     * Check if password has been used recently.
     *
     * @param User $user
     * @param string $password
     * @return bool
     */
    protected function checkPasswordHistory(User $user, string $password): bool
    {
        try {
            $historyCount = config('auth.password_policies.password_history_count', 5);

            if ($historyCount <= 0) {
                return true;
            }

            $recentPasswords = PasswordHistory::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->limit($historyCount)
                ->pluck('password');

            foreach ($recentPasswords as $oldPassword) {
                if (Hash::check($password, $oldPassword)) {
                    return false;
                }
            }

            // Also check current password
            if (Hash::check($password, $user->password)) {
                return false;
            }

            return true;
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - checkPasswordHistory() method error: ' . $e->getMessage());
            return true; // Allow password change on error
        }
    }

    /**
     * Add current password to history.
     *
     * @param User $user
     * @return void
     */
    protected function addPasswordToHistory(User $user): void
    {
        try {
            PasswordHistory::create([
                'user_id' => $user->id,
                'password' => $user->password,
            ]);

            // Clean up old password history
            $historyCount = config('auth.password_policies.password_history_count', 5);
            if ($historyCount > 0) {
                $idsToKeep = PasswordHistory::where('user_id', $user->id)
                    ->orderBy('created_at', 'desc')
                    ->limit($historyCount)
                    ->pluck('id');

                PasswordHistory::where('user_id', $user->id)
                    ->whereNotIn('id', $idsToKeep)
                    ->delete();
            }
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - addPasswordToHistory() method error: ' . $e->getMessage());
        }
    }

    /**
     * Check if user's password has expired.
     *
     * @param User $user
     * @return bool
     */
    public function isPasswordExpired(User $user): bool
    {
        try {
            $expiryDays = config('auth.password_policies.password_expiry_days', 0);

            if ($expiryDays <= 0) {
                return false;
            }

            $lastChange = PasswordHistory::where('user_id', $user->id)
                ->orderBy('created_at', 'desc')
                ->first();

            if (!$lastChange) {
                // If no history, check user creation date
                return $user->created_at->addDays($expiryDays)->isPast();
            }

            return $lastChange->created_at->addDays($expiryDays)->isPast();
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - isPasswordExpired() method error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a remember token for the user.
     *
     * @param User $user
     * @return AuthToken
     */
    protected function createRememberToken(User $user): AuthToken
    {
        try {
            // Delete existing remember tokens
            AuthToken::where('user_id', $user->id)
                ->where('type', 'remember')
                ->delete();

            $token = Str::random(60);
            $duration = config('auth.security.remember_me_duration', 30);

            return AuthToken::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $token),
                'type' => 'remember',
                'expires_at' => now()->addDays($duration),
            ]);
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - createRememberToken() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Create an API token for the user.
     *
     * @param User $user
     * @param string|null $name
     * @return array
     */
    public function createApiToken(User $user, ?string $name = null): array
    {
        try {
            $token = Str::random(60);
            $expiryDays = config('auth.api_tokens.expiry_days', 365);

            $authToken = AuthToken::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $token),
                'type' => 'api',
                'expires_at' => $expiryDays > 0 ? now()->addDays($expiryDays) : null,
            ]);

            return [
                'token' => $token,
                'expires_at' => $authToken->expires_at,
                'id' => $authToken->id,
            ];
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - createApiToken() method error: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Revoke an API token.
     *
     * @param string $token
     * @return bool
     */
    public function revokeApiToken(string $token): bool
    {
        try {
            return AuthToken::where('token', hash('sha256', $token))
                ->where('type', 'api')
                ->delete() > 0;
        } catch (\Exception $e) {
            Log::error('AuthenticationService.php - revokeApiToken() method error: ' . $e->getMessage());
            return false;
        }
    }
}
